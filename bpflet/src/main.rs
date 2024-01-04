use clap::Parser;
use lazy_static::lazy_static;
use sled::{Config, Db};

mod cli;
mod command;
mod errors;
mod handler;
mod manager;
mod oci;
mod serve;
mod utils;

const BPFLET_ENV_LOG_LEVEL: &str = "RUST_LOG";

lazy_static! {
    pub static ref BPFLET_DB: Db = Config::default()
        .temporary(true)
        .open()
        .expect("Unable to open temporary root database");
}

fn main() -> anyhow::Result<()> {
    let cli = cli::args::Cli::parse();
    cli.command.execute()
}