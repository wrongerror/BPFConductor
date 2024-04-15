use std::collections::HashMap;
use std::sync::Arc;

use log::{error, info};
use parking_lot::Mutex;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::managers::cache::CacheManager;
use crate::managers::image::ImageManager;
use crate::managers::registry::RegistryManager;
use crate::progs::types::{Program, ShutdownSignal};

#[derive(Debug, Clone)]
pub(crate) struct ProgManager {
    pub cache_manager: CacheManager,
    pub image_manager: ImageManager,
    pub registry_manager: RegistryManager,
    pub program_handlers: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
    pub shutdown_tx: broadcast::Sender<ShutdownSignal>,
}

impl ProgManager {
    pub(crate) async fn new() -> anyhow::Result<ProgManager> {
        let cache_manager = CacheManager::new().await?;
        cache_manager.wait_for_cache_sync().await?;
        let (shutdown_tx, _) = broadcast::channel(100);
        Ok(Self {
            cache_manager,
            image_manager: ImageManager::new(),
            registry_manager: RegistryManager::new(),
            program_handlers: Arc::new(Mutex::new(HashMap::new())),
            shutdown_tx,
        })
    }

    pub(crate) async fn load(&self, prog: Arc<dyn Program>) -> Result<(), anyhow::Error> {
        let shutdown_rx = self.shutdown_tx.subscribe();
        let p = prog.clone();
        let handler = tokio::spawn(async move {
            match p.start(shutdown_rx).await {
                Ok(_) => info!("Program {} started successfully.", p.get_name()),
                Err(e) => error!("Failed to start program {}: {:?}", p.get_name(), e),
            }
        });

        let mut handlers = self.program_handlers.lock();
        handlers.insert(prog.get_name(), handler);

        Ok(())
    }

    pub(crate) async fn unload(&self, program_name: &str) -> Result<(), anyhow::Error> {
        let mut handlers = self.program_handlers.lock();
        if let Some(handler) = handlers.remove(program_name) {
            self.shutdown_tx
                .send(ShutdownSignal::ProgramName(program_name.to_string()))
                .map_err(|e| {
                    error!(
                        "Failed to send shutdown signal for program {}: {:?}",
                        program_name, e
                    );
                    e
                })?;

            match handler.await {
                Ok(_) => {
                    info!("Program {} stopped successfully.", program_name);
                }
                Err(e) => {
                    error!("Failed to stop program {}: {:?}", program_name, e);
                    return Err(anyhow::Error::new(e));
                }
            }
        }
        Ok(())
    }
}
