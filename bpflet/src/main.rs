use std::fs;

use lazy_static::lazy_static;
use log::warn;
use sled::{Config as DbConfig, Db};

use bpflet_api::config::Config;
use bpflet_api::constants::directories::{CFGPATH_BPFLET_CONFIG, STDIR_DB};

use crate::service::execute_service;

mod command;
mod dispatcher;
mod errors;
mod handler;
mod helper;
mod manager;
mod map;
mod oci;
mod program;
mod serve;
mod service;

const BPFLET_ENV_LOG_LEVEL: &str = "RUST_LOG";

lazy_static! {
    pub static ref BPFLET_DB: Db = DbConfig::default()
        .path(STDIR_DB)
        .open()
        .expect("Unable to open bpflet database");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = if let Ok(c) = fs::read_to_string(CFGPATH_BPFLET_CONFIG) {
        c.parse().unwrap_or_else(|_| {
            warn!("Unable to parse config file, using defaults");
            Config::default()
        })
    } else {
        warn!("Unable to read config file, using defaults");
        Config::default()
    };
    execute_service(&config).await
}
