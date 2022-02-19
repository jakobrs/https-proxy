use std::{
    convert::Infallible,
    io::Error as IoError,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{self, Poll},
    time::Duration,
};

use crate::utils;

use anyhow::Context;
use clap::Args;
use futures_util::{stream::FuturesUnordered, StreamExt};
use hyper::{
    client::HttpConnector,
    server::{accept::Accept, conn::AddrStream},
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Client, Method, Request, Response, Server, StatusCode,
};
use rustls::{server::AllowAnyAuthenticatedClient, RootCertStore, ServerConfig};
use tokio::{
    net::{TcpListener, TcpStream},
    time::Timeout,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

#[derive(Args)]
/// Runs an HTTP(S) proxy
pub(crate) struct Opts {
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

    #[clap(long, requires = "client-cert-file", requires = "tls")]
    /// Require clients to be authenticated
    auth: bool,

    #[clap(long, parse(from_os_str))]
    /// Certificate used for client authentication
    client_cert_file: Option<PathBuf>,

    #[clap(long)]
    /// Allow connecting to any domain
    unrestricted: bool,
}

pub(crate) async fn server_main(opts: Opts) -> anyhow::Result<()> {
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

    let unrestricted = opts.unrestricted;
    let make_service = make_service_fn(|_| {
        let client = client.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                tunnel(req, client.clone(), unrestricted)
            }))
        }
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

    let unrestricted = opts.unrestricted;
    let make_service = make_service_fn(|socket: &AddrStream| {
        log::info!("Received connection from {}", socket.remote_addr());
        let client = client.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                tunnel(req, client.clone(), unrestricted)
            }))
        }
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
            let certs = utils::read_certs(opts.cert_file.as_ref().unwrap())?;
            let key = utils::read_key(opts.key_file.as_ref().unwrap())?.context("no key")?;

            let config_builder = ServerConfig::builder().with_safe_defaults();
            let config_builder = if opts.auth {
                let mut roots = RootCertStore::empty();

                for cert in utils::read_certs(opts.client_cert_file.as_deref().unwrap())? {
                    roots.add(&cert)?;
                }

                config_builder.with_client_cert_verifier(AllowAnyAuthenticatedClient::new(roots))
            } else {
                config_builder.with_no_client_auth()
            };
            let mut cfg = config_builder.with_single_cert(certs, key)?;
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

async fn tunnel(
    req: Request<Body>,
    client: Client<HttpConnector>,
    unrestricted: bool,
) -> Result<Response<Body>, hyper::Error> {
    if let Some(authority) = req.uri().authority() {
        if authority.host() != "domain-name.xyz" && !unrestricted {
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
