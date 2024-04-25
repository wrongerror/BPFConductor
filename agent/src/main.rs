use std::path::PathBuf;

use clap::Parser;

use crate::server::serve;
use crate::utils::init_env;

mod collector;
mod common;
mod managers;
mod progs;
mod server;
mod utils;

#[derive(Parser, Debug)]
#[command(
    long_about = "An agent managing user space programs, including eBPF and non-eBPF, with a metrics server."
)]
#[command(name = "agent")]
pub(crate) struct Args {
    /// Optional: socket address to listen on for the metrics server.
    #[clap(long, verbatim_doc_comment, default_value = "0.0.0.0:8080")]
    pub(crate) metrics_addr: String,
    /// Optional: Path under which to expose metrics.
    #[clap(long, verbatim_doc_comment, default_value = "/metrics")]
    pub(crate) metrics_path: String,
    /// Optional: Location of the agent unix socket.
    #[clap(long, verbatim_doc_comment, default_value = "/run/eva/agent.sock")]
    pub(crate) agent_socket_path: PathBuf,
    /// Optional: Location of the bpfman unix socket.
    #[clap(
        long,
        verbatim_doc_comment,
        default_value = "/run/bpfman-sock/bpfman.sock"
    )]
    pub(crate) bpfman_socket_path: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_env()?;
    serve(args).await?;
    Ok(())
}
