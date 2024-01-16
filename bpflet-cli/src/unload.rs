use bpflet_api::v1::{bpflet_client::BpfletClient, UnloadRequest};

use crate::{args::UnloadArgs, select_channel};

pub(crate) async fn execute_unload(args: &UnloadArgs) -> Result<(), anyhow::Error> {
    let channel = select_channel().expect("failed to select channel");
    let mut client = BpfletClient::new(channel);
    let request = tonic::Request::new(UnloadRequest { id: args.id });
    let _response = client.unload(request).await?.into_inner();
    Ok(())
}
