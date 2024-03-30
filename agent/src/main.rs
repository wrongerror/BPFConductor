use bpfman_api::v1::bpfman_client::BpfmanClient;
use bpfman_lib::directories::RTPATH_BPFMAN_SOCKET;
use lazy_static::lazy_static;
use log::warn;
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

mod cache;
mod common;
mod managers;
mod progs;
mod registry;
mod server;

fn select_channel() -> Option<Channel> {
    let path = RTPATH_BPFMAN_SOCKET.to_string();

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

lazy_static! {
    static ref BPF_CLIENT: Mutex<BpfmanClient<Channel>> = {
        let channel = select_channel().unwrap();
        Mutex::new(BpfmanClient::new(channel))
    };
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let channel = select_channel().unwrap();
    let mut bpf_client = BPF_CLIENT.lock().await;
    let reg = registry::Registry::new();
    registry::register_programs(reg).await;
    println!("Hello, world!");
    Ok(())
}
