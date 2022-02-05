use std::convert::Infallible;
use std::io::{Cursor, Error as IoError, ErrorKind};
use std::pin::Pin;
use std::task::{self, Poll};
use std::{net::SocketAddr, str::FromStr, sync::Arc};

use clap::Parser;
use futures::{ready, FutureExt};
use hyper::server::accept::{self, Accept};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Response, Server};
use rustls::{Certificate, PrivateKey, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

#[derive(Parser)]
struct Opts {
    #[clap(short, long, default_value = "127.0.0.1:8100")]
    /// Listen address
    listen: String,

    #[clap(long)]
    /// Key file
    key_file: String,
    #[clap(long)]
    /// Certificate file
    cert_file: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let opts = Opts::parse();
    let addr = SocketAddr::from_str(&opts.listen)?;

    let server_config = {
        let certs = read_certs(&opts.cert_file)?;
        let key = read_key(&opts.key_file)?;

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

    let make_service = make_service_fn(|socket: &_| {
        eprintln!("{socket:?}");

        async {
            Ok::<_, Infallible>(service_fn(|req| async {
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }))
        }
    });

    let server = Server::builder(incoming)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service);

    if let Err(err) = server.await {
        eprintln!("{err:?}");
    }

    Ok(())
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
        .ok_or(IoError::new(ErrorKind::Other, "no keys"))?;
    Ok(PrivateKey(key))
}
