use std::{convert::Infallible, io::Error as IoError, net::SocketAddr, str::FromStr};

use clap::Args;
use hyper::{
    client::HttpConnector,
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Client, Method, Request, Response, Server, StatusCode,
};
use tokio::net::TcpStream;

#[derive(Args)]
/// Runs an HTTP(S) proxy
pub(crate) struct Opts {
    #[clap(short, long, default_value = "127.0.0.1:8100")]
    /// Listen address
    listen: String,

    #[clap(long)]
    /// Allow connecting to any domain
    unrestricted: bool,
}

pub(crate) async fn server_main(opts: Opts) -> anyhow::Result<()> {
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
