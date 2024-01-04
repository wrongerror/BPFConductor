use std::{fs::remove_file, path::Path};
use log::{debug, info};
use sled::Config as DbConfig;
use tokio::{
    join,
    net::UnixListener,
    select,
    signal::unix::{signal, SignalKind},
    sync::mpsc,
    task::JoinHandle,
};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

use bpflet_api::{
    config::Config,
    util::directories::{RTPATH_BPFLET_SOCKET, STDIR_DB},
    v1::{
        bpflet_server::BpfletServer
    }
};

use crate::{handler::ProgHandler, manager};
use crate::oci::image_manager::ImageManager;
use crate::utils::{set_file_permissions, SOCK_MODE};


pub async fn serve(
    config: &Config,
) -> anyhow::Result<()> {
    let (tx, rx) = mpsc::channel(32);
    let handler = ProgHandler::new(tx);
    let service = BpfletServer::new(handler);

    let mut listeners: Vec<_> = Vec::new();
    let handle = serve_unix(RTPATH_BPFLET_SOCKET.to_string(), service.clone()).await?;
    listeners.push(handle);

    let allow_unsigned = config.signing.as_ref().map_or(true, |s| s.allow_unsigned);
    let (itx, irx) = mpsc::channel(32);
    let database = DbConfig::default()
        .path(STDIR_DB)
        .open()
        .expect("Unable to open database");
    let mut image_manager = ImageManager::new(database.clone(), allow_unsigned, irx).await?;
    let image_manager_handle = tokio::spawn(async move {
        image_manager.run().await;
    });

    let mut bpf_manager = manager::BpfManager::new(config.clone(), rx, itx, database);
    bpf_manager.rebuild_state().await?;

    join!(
        join_listeners(listeners),
        image_manager_handle,
        bpf_manager.run()
    );

    Ok(())
}

pub(crate) async fn shutdown_handler() {
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    select! {
        _ = sigint.recv() => {debug!("Received SIGINT")},
        _ = sigterm.recv() => {debug!("Received SIGTERM")},
    }
}

async fn join_listeners(listeners: Vec<JoinHandle<()>>) {
    for listener in listeners {
        match listener.await {
            Ok(()) => {}
            Err(e) => eprintln!("Error = {e:?}"),
        }
    }
}

async fn serve_unix(
    path: String,
    service: BpfletServer<ProgHandler>,
) -> anyhow::Result<JoinHandle<()>> {
    if Path::new(&path).exists() {
        remove_file(&path)?;
    }

    let uds = UnixListener::bind(&path)?;
    let uds_stream = UnixListenerStream::new(uds);
    set_file_permissions(&path.clone(), SOCK_MODE).await;

    let serve = Server::builder()
        .add_service(service)
        .serve_with_incoming(uds_stream);

    Ok(tokio::spawn(async move {
        info!("Listening on {}", path);
        if let Err(e) = serve.await {
            eprintln!("Error = {e:?}");
        }
        info!("Shutting down Unix listener {}", path)
    }))
}