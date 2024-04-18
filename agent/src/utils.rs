use std::fs::create_dir_all;

use anyhow::Context;
use bpfman_lib::utils::set_file_permissions;
use log::warn;
use nix::{
    libc::RLIM_INFINITY,
    sys::resource::{setrlimit, Resource},
};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use crate::common::constants::directories::{RTDIR, RTDIR_MODE};

pub fn init_env() -> anyhow::Result<()> {
    env_logger::init();
    log::info!("Logger initialized with env_logger");

    setrlimit(Resource::RLIMIT_MEMLOCK, RLIM_INFINITY, RLIM_INFINITY).unwrap();

    create_dir_all(RTDIR).context("unable to create runtime directory")?;

    set_dir_permissions(RTDIR, RTDIR_MODE);

    Ok(())
}

pub(crate) fn set_dir_permissions(directory: &str, mode: u32) {
    // Iterate through the files in the provided directory
    let entries = std::fs::read_dir(directory).unwrap();
    for file in entries.flatten() {
        // Set the permissions on the file based on input
        set_file_permissions(&file.path(), mode);
    }
}
