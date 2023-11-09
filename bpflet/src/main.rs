use clap::Parser;

mod cli;
mod command;
mod errors;
mod handler;
mod manager;
mod oci;
mod serve;
mod utils;

const BPFLET_ENV_LOG_LEVEL: &str = "RUST_LOG";

fn main() -> anyhow::Result<()> {
    let cli = cli::args::Cli::parse();
    cli.command.execute()
}