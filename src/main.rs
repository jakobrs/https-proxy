use std::{
    convert::Infallible,
    io::{Error as IoError, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{self, Poll},
};

use clap::Parser;
use futures_util::{ready, FutureExt};
use hyper::{
    server::accept::Accept,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Method, Request, Response, Server, StatusCode,
};
use rustls::{Certificate, PrivateKey, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
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

    #[clap(long)]
    /// Key file
    key_file: Option<String>,
    #[clap(long)]
    /// Certificate file
    cert_file: Option<String>,
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
    let tls_acceptor = TlsAcceptor::from(server_config);

    let tcp_listener = TcpListener::bind(&addr).await?;
    let incoming = Acceptor {
        listener: tcp_listener,
        tls_acceptor,
        currently_accepting: None,
    };

    let make_service = make_service_fn(|_| async { Ok::<_, Infallible>(service_fn(tunnel)) });

    let server = Server::builder(incoming)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service);

    Ok(server.await?)
}

async fn serve_plain(opts: &Opts) -> anyhow::Result<()> {
    let addr = SocketAddr::from_str(&opts.listen)?;

    let make_service = make_service_fn(|_| async { Ok::<_, Infallible>(service_fn(tunnel)) });

    let server = Server::bind(&addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service);

    Ok(server.await?)
}

struct Acceptor {
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    currently_accepting: Option<tokio_rustls::Accept<TcpStream>>,
}

impl Accept for Acceptor {
    type Conn = TlsStream<TcpStream>;
    type Error = IoError;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let this = self.get_mut();

        loop {
            match this.currently_accepting {
                Some(ref mut accept) => {
                    let tls_stream = ready!(accept.poll_unpin(cx));

                    this.currently_accepting = None;
                    match tls_stream {
                        Ok(stream) => return Poll::Ready(Some(Ok(stream))),
                        Err(err) => {
                            log::error!("TLS handshake failed: {err:?}");
                        }
                    }
                }
                None => {
                    let (stream, _peer) = ready!(this.listener.poll_accept(cx))?;
                    this.currently_accepting = Some(this.tls_acceptor.accept(stream));
                }
            }
        }
    }
}

fn read_certs(file: &str) -> std::io::Result<Vec<Certificate>> {
    let mut file_reader = std::io::BufReader::new(std::fs::File::open(file)?);

    let certs = rustls_pemfile::certs(&mut file_reader)?;

    Ok(certs.into_iter().map(Certificate).collect())
}

fn read_key(file: &str) -> std::io::Result<PrivateKey> {
    let mut file_reader = std::io::BufReader::new(std::fs::File::open(file)?);

    let keys = rustls_pemfile::pkcs8_private_keys(&mut file_reader)?;

    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| IoError::new(ErrorKind::Other, "no keys"))?;
    Ok(PrivateKey(key))
}

async fn tunnel(req: Request<Body>) -> Result<Response<Body>, Infallible> {
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
            Ok(Response::builder()
                .status(StatusCode::NOT_IMPLEMENTED)
                .body(Body::empty())
                .unwrap())
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
