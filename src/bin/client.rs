use std::{
    io::Cursor,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use clap::{ArgEnum, Parser};
use rustls::{Certificate, ClientConfig, PrivateKey, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

#[derive(Parser)]
/// https-proxy client
struct Opts {
    #[clap(short, long, default_value = "127.0.0.1:8080")]
    /// Listen address
    listen: String,

    #[clap(short, long)]
    /// Remote address
    remote: String,
    #[clap(short, long, parse(try_from_str = core::convert::TryFrom::try_from))]
    /// Remote server name (for SNI and verification)
    domain: ServerName,

    #[clap(long, arg_enum, default_value_t = Runtime::CurrentThread)]
    /// Tokio runtime
    runtime: Runtime,

    #[clap(long, requires = "key-file", requires = "cert-file")]
    /// Enable client authentication
    auth: bool,

    #[clap(long, parse(from_os_str))]
    /// Certificate used for client authentication
    cert_file: Option<PathBuf>,
    #[clap(long, parse(from_os_str))]
    /// Key used for client authentication
    key_file: Option<PathBuf>,
}

#[derive(ArgEnum, Clone, Copy)]
enum Runtime {
    CurrentThread,
    MultiThreaded,
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    let mut runtime_builder = match opts.runtime {
        Runtime::CurrentThread => tokio::runtime::Builder::new_current_thread(),
        Runtime::MultiThreaded => tokio::runtime::Builder::new_multi_thread(),
    };

    let runtime = runtime_builder.enable_all().build()?;

    runtime.block_on(main_inner(opts))
}

async fn main_inner(opts: Opts) -> Result<()> {
    env_logger::init();

    let opts = Arc::new(opts);

    let tls_connector = {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let config_builder = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store);

        let config = if opts.auth {
            let certs = read_certs(opts.cert_file.as_ref().unwrap())?;
            let key = read_key(opts.key_file.as_ref().unwrap())?.context("no key")?;

            config_builder.with_single_cert(certs, key)?
        } else {
            config_builder.with_no_client_auth()
        };

        TlsConnector::from(Arc::new(config))
    };
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

async fn tunnel(mut stream: TcpStream, opts: &Opts, tls_connector: TlsConnector) -> Result<()> {
    let remote = TcpStream::connect(&opts.remote).await?;
    let mut remote_tls = tls_connector.connect(opts.domain.clone(), remote).await?;

    let stats = tokio::io::copy_bidirectional(&mut stream, &mut remote_tls).await?;

    log::info!("Stats: {stats:?}");

    Ok(())
}

fn read_certs(file: &Path) -> std::io::Result<Vec<Certificate>> {
    let mut file_reader = std::io::BufReader::new(std::fs::File::open(file)?);

    let certs = rustls_pemfile::certs(&mut file_reader)?;

    Ok(certs.into_iter().map(Certificate).collect())
}

fn read_key(file: &Path) -> std::io::Result<Option<PrivateKey>> {
    let file_contents = std::fs::read(file)?;

    let keys = rustls_pemfile::pkcs8_private_keys(&mut Cursor::new(&file_contents))?;
    if let Some(key) = keys.into_iter().next() {
        return Ok(Some(PrivateKey(key)));
    }

    let keys = rustls_pemfile::rsa_private_keys(&mut Cursor::new(&file_contents))?;
    if let Some(key) = keys.into_iter().next() {
        return Ok(Some(PrivateKey(key)));
    }

    Ok(None)
}
