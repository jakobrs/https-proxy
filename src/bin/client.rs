use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use rustls::{ClientConfig, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

#[derive(Parser)]
/// https-proxy client
struct Opts {
    #[clap(short, long, default_value = "127.0.0.1:8080")]
    listen: String,

    #[clap(short, long)]
    remote: String,
    #[clap(short, long, parse(try_from_str = core::convert::TryFrom::try_from))]
    domain: ServerName,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let opts = Arc::new(Opts::parse());

    let tls_connector = get_tls_connector();
    let tcp_listener = TcpListener::bind(&opts.listen).await?;

    loop {
        let (stream, _peer) = tcp_listener.accept().await?;

        let opts = opts.clone();
        let tls_connector = tls_connector.clone();
        tokio::spawn(async move {
            if let Err(err) = tunnel(stream, &opts, tls_connector).await {
                log::error!("Error in client task: {err:?}");
            }
        });
    }
}

fn get_tls_connector() -> TlsConnector {
    // this is basically stolen from the rustls docs

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    ))
}

async fn tunnel(
    mut stream: TcpStream,
    opts: &Opts,
    tls_connector: TlsConnector,
) -> anyhow::Result<()> {
    let remote = TcpStream::connect(&opts.remote).await?;
    let mut remote_tls = tls_connector.connect(opts.domain.clone(), remote).await?;

    let stats = tokio::io::copy_bidirectional(&mut stream, &mut remote_tls).await?;

    log::info!("Stats: {stats:?}");

    Ok(())
}