use clap::Parser;
use lazy_static::lazy_static;
use sled::{Config, Db};
use bpflet_api::constants::directories::STDIR_DB;

mod cli;
mod command;
mod errors;
mod handler;
mod manager;
mod oci;
mod serve;
mod helper;
mod dispatcher;

const BPFLET_ENV_LOG_LEVEL: &str = "RUST_LOG";

lazy_static! {
    pub static ref BPFLET_DB: Db = Config::default()
        .path(STDIR_DB)
        .open()
        .expect("Unable to open bpflet database");
}

fn main() -> anyhow::Result<()> {
    let cli = cli::args::Cli::parse();
    cli.command.execute()
}