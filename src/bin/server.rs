use std::{
    convert::Infallible,
    io::{Error as IoError, ErrorKind},
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{self, Poll},
    time::Duration,
};

use clap::Parser;
use futures_util::{stream::FuturesUnordered, StreamExt};
use hyper::{
    client::HttpConnector,
    server::{accept::Accept, conn::AddrStream},
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Client, Method, Request, Response, Server, StatusCode,
};
use rustls::{Certificate, PrivateKey, ServerConfig};
use tokio::{
    net::{TcpListener, TcpStream},
    time::Timeout,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

#[derive(Parser)]
/// Runs an HTTP(S) proxy
struct Opts {
    #[clap(short, long, default_value = "127.0.0.1:8100")]
    /// Listen address
    listen: String,

    #[clap(long, requires = "key-file", requires = "cert-file")]
    /// Use TLS
    tls: bool,

    #[clap(long, parse(from_os_str))]
    /// Key file
    key_file: Option<PathBuf>,
    #[clap(long, parse(from_os_str))]
    /// Certificate file
    cert_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let opts = Opts::parse();

    if opts.tls {
        serve_tls(&opts).await?;
    } else {
        serve_plain(&opts).await?;
    }

    Ok(())
}

async fn serve_tls(opts: &Opts) -> anyhow::Result<()> {
    let incoming = Acceptor::from_opts(opts).await?;

    let client = Client::builder()
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .build_http();

    let make_service = make_service_fn(|_| {
        let client = client.clone();
        async move { Ok::<_, Infallible>(service_fn(move |req| tunnel(req, client.clone()))) }
    });

    let server = Server::builder(incoming)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service);

    Ok(server.await?)
}

async fn serve_plain(opts: &Opts) -> anyhow::Result<()> {
    let addr = SocketAddr::from_str(&opts.listen)?;

    let client = Client::builder()
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .build_http();

    let make_service = make_service_fn(|socket: &AddrStream| {
        log::info!("Received connection from {}", socket.remote_addr());
        let client = client.clone();
        async move { Ok::<_, Infallible>(service_fn(move |req| tunnel(req, client.clone()))) }
    });

    let server = Server::bind(&addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service);

    Ok(server.await?)
}

const TLS_TIMEOUT: Duration = Duration::from_secs(5);

struct Acceptor {
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    currently_accepting: FuturesUnordered<Timeout<tokio_rustls::Accept<TcpStream>>>,
}

impl Acceptor {
    async fn from_opts(opts: &Opts) -> anyhow::Result<Self> {
        let addr = SocketAddr::from_str(&opts.listen)?;

        let server_config = {
            let certs = read_certs(opts.cert_file.as_ref().unwrap())?;
            let key = read_key(opts.key_file.as_ref().unwrap())?;

            let mut cfg = ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(certs, key)?;
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

            Arc::new(cfg)
        };

        Ok(Self {
            listener: TcpListener::bind(&addr).await?,
            tls_acceptor: TlsAcceptor::from(server_config),
            currently_accepting: FuturesUnordered::new(),
        })
    }
}

impl Accept for Acceptor {
    type Conn = TlsStream<TcpStream>;
    type Error = IoError;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let this = self.get_mut();

        while let Poll::Ready(res) = this.listener.poll_accept(cx) {
            let (stream, peer) = res?;
            log::info!("Received connection from {peer}");

            this.currently_accepting.push(tokio::time::timeout(
                TLS_TIMEOUT,
                this.tls_acceptor.accept(stream),
            ));
        }

        while let Poll::Ready(Some(tls_stream)) = this.currently_accepting.poll_next_unpin(cx) {
            match tls_stream {
                Ok(Ok(stream)) => return Poll::Ready(Some(Ok(stream))),
                Ok(Err(err)) => log::error!("TLS handshake failed: {err:?}"),
                Err(_elapsed) => log::error!("TLS handshake timeout"),
            }
        }

        Poll::Pending
    }
}

fn read_certs(file: &Path) -> std::io::Result<Vec<Certificate>> {
    let mut file_reader = std::io::BufReader::new(std::fs::File::open(file)?);

    let certs = rustls_pemfile::certs(&mut file_reader)?;

    Ok(certs.into_iter().map(Certificate).collect())
}

fn read_key(file: &Path) -> std::io::Result<PrivateKey> {
    let mut file_reader = std::io::BufReader::new(std::fs::File::open(file)?);

    let keys = rustls_pemfile::pkcs8_private_keys(&mut file_reader)?;

    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| IoError::new(ErrorKind::Other, "no keys"))?;
    Ok(PrivateKey(key))
}

async fn tunnel(
    req: Request<Body>,
    client: Client<HttpConnector>,
) -> Result<Response<Body>, hyper::Error> {
    if let Some(authority) = req.uri().authority() {
        if authority.host() != "domain-name.xyz" {
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body("Only connections to domain-name.xyz are allowed".into())
                .unwrap());
        }
        let authority = authority.to_string();

        if req.method() == Method::CONNECT {
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(err) = tunnel_proxy(upgraded, authority).await {
                            log::error!("Error in tunnel_proxy: {err:?}");
                        }
                    }
                    Err(err) => log::error!("Error: {err:?}"),
                }
            });
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap())
        } else {
            client.request(req).await
        }
    } else {
        Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::empty())
            .unwrap())
    }
}

async fn tunnel_proxy(mut upgraded: Upgraded, remote: String) -> Result<(), IoError> {
    let mut remote = TcpStream::connect(remote).await?;

    let stats = tokio::io::copy_bidirectional(&mut upgraded, &mut remote).await?;
    log::info!("Stats: {stats:?}");

    Ok(())
}
