use clap::Parser;
use log::warn;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use args::Commands;
use bpflet_api::constants::directories::RTPATH_BPFLET_SOCKET;

mod args;
mod get;
mod helper;
mod image;
mod list;
mod load;
mod table;
mod unload;

impl Commands {
    pub(crate) async fn execute(&self) -> Result<(), anyhow::Error> {
        match self {
            Commands::Load(l) => l.execute().await,
            Commands::Unload(args) => unload::execute_unload(args).await,
            Commands::Get(args) => get::execute_get(args).await,
            Commands::List(args) => list::execute_list(args).await,
            Commands::Image(i) => i.execute().await,
        }
    }
}

fn select_channel() -> Option<Channel> {
    let path = RTPATH_BPFLET_SOCKET.to_string();

    let address = Endpoint::try_from(format!("unix:/{path}"));
    if let Err(e) = address {
        warn!("Failed to parse unix endpoint: {e:?}");
        return None;
    };
    let address = address.unwrap();
    let channel = address
        .connect_with_connector_lazy(service_fn(move |_: Uri| UnixStream::connect(path.clone())));
    Some(channel)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = args::Cli::parse();
    cli.command.execute().await
}
