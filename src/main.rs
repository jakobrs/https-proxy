use clap::{Parser, Subcommand};

mod client;
mod server;
pub(crate) mod utils;

#[derive(Parser)]
struct Opts {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Client(client::Opts),
    Server(server::Opts),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let opts = Opts::parse();

    match opts.command {
        Command::Client(opts) => client::client_main(opts).await,
        Command::Server(opts) => server::server_main(opts).await,
    }
}
