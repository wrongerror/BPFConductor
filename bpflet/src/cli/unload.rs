use bpflet_api::v1::{bpflet_client::BpfletClient, UnloadRequest};
use crate::cli::{args::UnloadArgs, select_channel};

pub(crate) fn execute_unload(args: &UnloadArgs) -> Result<(), anyhow::Error> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let channel = select_channel().expect("failed to select channel");
            let mut client = BpfletClient::new(channel);
            let request = tonic::Request::new(UnloadRequest { id: args.id });
            let _response = client.unload(request).await?.into_inner();
            Ok::<(), anyhow::Error>(())
        })
}