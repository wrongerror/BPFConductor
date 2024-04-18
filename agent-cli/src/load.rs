use crate::table::ProgTable;
use agent_api::v1::agent_client::AgentClient;
use agent_api::v1::LoadRequest;
use clap::{Args, Parser};
use tonic::transport::Channel;

#[derive(Parser, Debug)]
pub(crate) enum LoadCommand {
    /// Load a builtin program .
    Builtin(LoadBuiltinArgs),
    /// Load a wasm program packaged in a OCI container image from a given registry.
    Wasm(LoadWasmArgs),
}

impl LoadCommand {
    pub(crate) async fn execute(&self, agent_client: AgentClient<Channel>) -> anyhow::Result<()> {
        match self {
            LoadCommand::Builtin(l) => execute_load_builtin(agent_client, l).await,
            LoadCommand::Wasm(l) => execute_load_wasm(agent_client, l).await,
        }
    }
}

#[derive(Args, Debug)]
pub(crate) struct LoadBuiltinArgs {
    /// Required: The name of the builtin program to load.
    #[clap(short, long)]
    pub(crate) name: String,

    /// Optional: Specify Key/Value metadata to be attached to a program when it
    /// is loaded by agent.
    /// Format: <KEY>=<VALUE>
    ///
    /// This can later be used to `list` a certain subset of programs which contain
    /// the specified metadata.
    /// Example: --metadata owner=acme
    #[clap(short, long, verbatim_doc_comment, value_parser=parse_key_val, value_delimiter = ',')]
    pub(crate) metadata: Option<Vec<(String, String)>>,

    /// Optional: eBPF maps that the program will use.
    /// Format: <MAP_NAME>=<PROG_NAME>
    /// Example: --ebpf-maps my_map=my_prog
    #[clap(short, long, verbatim_doc_comment, value_parser=parse_key_val, value_delimiter = ',')]
    pub(crate) ebpf_maps: Option<Vec<(String, String)>>,
}

#[derive(Args, Debug)]
pub(crate) struct LoadWasmArgs {
    /// Specify how the bytecode image should be pulled.
    #[command(flatten)]
    pub(crate) pull_args: PullBytecodeArgs,

    /// Required: The name of the wasm program to load.
    #[clap(short, long, verbatim_doc_comment, default_value = "")]
    pub(crate) name: String,

    /// Optional: Specify Key/Value metadata to be attached to a program when it
    /// is loaded by bpfman.
    /// Format: <KEY>=<VALUE>
    ///
    /// This can later be used to list a certain subset of programs which contain
    /// the specified metadata.
    /// Example: --metadata owner=acme
    #[clap(short, long, verbatim_doc_comment, value_parser=parse_key_val, value_delimiter = ',')]
    pub(crate) metadata: Option<Vec<(String, String)>>,

    /// Optional: eBPF maps that the program will use.
    /// Format: <MAP_NAME>=<PROG_NAME>
    /// Example: --ebpf-maps my_map=my_prog
    #[clap(short, long, verbatim_doc_comment, value_parser=parse_key_val, value_delimiter = ',')]
    pub(crate) ebpf_maps: Option<Vec<(String, String)>>,
}

#[derive(Args, Debug)]
#[command(disable_version_flag = true)]
pub(crate) struct PullBytecodeArgs {
    /// Required: Container Image URL.
    #[clap(short, long, verbatim_doc_comment)]
    pub(crate) image_url: String,

    /// Optional: Registry auth for authenticating with the specified image registry.
    /// This should be base64 encoded from the '<username>:<password>' string just like
    /// it's stored in the docker/podman host config.
    /// Example: --registry_auth "YnjrcKw63PhDcQodiU9hYxQ2"
    #[clap(short, long, verbatim_doc_comment)]
    pub(crate) registry_auth: Option<String>,

    /// Optional: Pull policy for remote images.
    ///
    /// [possible values: Always, IfNotPresent, Never]
    #[clap(short, long, verbatim_doc_comment, default_value = "IfNotPresent")]
    pub(crate) pull_policy: String,
}

pub(crate) async fn execute_load_builtin(
    mut client: AgentClient<Channel>,
    args: &LoadBuiltinArgs,
) -> anyhow::Result<()> {
    let request = tonic::Request::new(LoadRequest {
        bytecode: None,
        name: args.name.clone(),
        program_type: 0,
        metadata: args
            .metadata
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
        ebpf_maps: args
            .ebpf_maps
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
    });

    let response = client.load(request).await?.into_inner();
    ProgTable::new_program(&response.info)?.print();

    Ok(())
}

async fn execute_load_wasm(
    client: AgentClient<Channel>,
    args: &LoadWasmArgs,
) -> anyhow::Result<()> {
    todo!()
}

/// Parse a single key-value pair
pub(crate) fn parse_key_val(s: &str) -> Result<(String, String), std::io::Error> {
    let pos = s.find('=').ok_or(std::io::ErrorKind::InvalidInput)?;
    Ok((s[..pos].to_string(), s[pos + 1..].to_string()))
}
