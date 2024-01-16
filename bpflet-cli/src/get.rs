use bpflet_api::v1::{bpflet_client::BpfletClient, GetRequest};

use crate::{args::GetArgs, select_channel, table::ProgTable};

pub(crate) async fn execute_get(args: &GetArgs) -> Result<(), anyhow::Error> {
    let channel = select_channel().expect("failed to select channel");
    let mut client = BpfletClient::new(channel);
    let request = tonic::Request::new(GetRequest { id: args.id });
    let response = client.get(request).await?.into_inner();

    ProgTable::new_get_bpflet(&response.info)?.print();
    ProgTable::new_get_unsupported(&response.kernel_info)?.print();
    Ok(())
}
