pub(crate) mod args;
mod load;
mod image;
mod system;
mod table;
mod unload;

use args::Commands;
use bpflet_api::{
    config::Config,
    util::directories::{CFGPATH_BPFLET_CONFIG, RTPATH_BPFLET_SOCKET},
};
use log::warn;
use std::fs;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

impl Commands {
    pub(crate) fn execute(&self) -> Result<(), anyhow::Error> {
        let config = if let Ok(c) = fs::read_to_string(CFGPATH_BPFLET_CONFIG) {
            c.parse().unwrap_or_else(|_| {
                warn!("Unable to parse config file, using defaults");
                Config::default()
            })
        } else {
            warn!("Unable to read config file, using defaults");
            Config::default()
        };

        match self {
            Commands::Load(l) => l.execute(),
            Commands::Unload(args) => unload::execute_unload(args),
            Commands::System(s) => s.execute(&config),
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
