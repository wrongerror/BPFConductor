use std::collections::HashMap;
use std::sync::Arc;

use log::{debug, error, info};
use parking_lot::Mutex;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::common::types::{
    ListFilter,
    ProgramState::{Failed, Initialized, Running, Stopped, Uninitialized},
    ProgramType,
};
use crate::managers::cache::CacheManager;
use crate::managers::image::ImageManager;
use crate::managers::registry::RegistryManager;
use crate::progs::types::{Program, ShutdownSignal};

#[derive(Debug, Clone)]
pub(crate) struct ProgManager {
    pub cache_manager: CacheManager,
    pub image_manager: ImageManager,
    pub registry_manager: RegistryManager,
    pub program_handles: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
    pub shutdown_tx: broadcast::Sender<ShutdownSignal>,
}

impl ProgManager {
    pub(crate) async fn new(
        shutdown_tx: broadcast::Sender<ShutdownSignal>,
    ) -> anyhow::Result<ProgManager> {
        let cache_manager = CacheManager::new().await?;
        cache_manager.wait_for_cache_sync().await?;
        Ok(Self {
            cache_manager,
            image_manager: ImageManager::new(),
            registry_manager: RegistryManager::new(),
            program_handles: Arc::new(Mutex::new(HashMap::new())),
            shutdown_tx,
        })
    }

    pub(crate) async fn pre_load(
        &self,
        program_name: String,
        program_type: ProgramType,
        metadata: HashMap<String, String>,
        cache_manager: CacheManager,
        map_to_prog_id: HashMap<String, u32>,
    ) -> Result<Arc<dyn Program>, anyhow::Error> {
        let prog = match self.get(program_name.clone(), Some(program_type)).await {
            Some(p) => p,
            None => {
                let err_msg = format!("Program {} not found.", program_name);
                error!("{}", &err_msg);
                return Err(anyhow::Error::msg(err_msg));
            }
        };
        match prog.get_state() {
            Uninitialized => match prog.init(metadata, cache_manager, map_to_prog_id) {
                Ok(()) => {
                    info!("Program {} initialized successfully.", prog.get_name());
                }
                Err(e) => {
                    error!("Failed to initialize program {}: {:?}", prog.get_name(), e)
                }
            },
            _ => {
                debug!("Program {} is already initialized.", prog.get_name());
            }
        }

        Ok(prog)
    }

    pub(crate) async fn get(
        &self,
        program_name: String,
        program_type: Option<ProgramType>,
    ) -> Option<Arc<dyn Program>> {
        self.registry_manager
            .get_program(program_name.as_str(), program_type)
    }

    pub(crate) async fn list(&self, list_filter: ListFilter) -> Vec<Arc<dyn Program>> {
        self.registry_manager.list_programs(list_filter)
    }

    pub(crate) async fn load(&self, prog: Arc<dyn Program>) -> Result<(), anyhow::Error> {
        match prog.get_state() {
            Initialized | Stopped => {
                let shutdown_rx = self.shutdown_tx.subscribe();
                let p = prog.clone();
                let handle = tokio::spawn(async move {
                    match p.start(shutdown_rx).await {
                        Ok(_) => info!("Program {} started successfully.", p.get_name()),
                        Err(e) => error!("Failed to start program {}: {:?}", p.get_name(), e),
                    }
                });

                let mut handlers = self.program_handles.lock();
                handlers.insert(prog.get_name(), handle);
            }
            Uninitialized | Running | Failed => {
                let err_msg = format!(
                    "Program {} is in an invalid state to be loaded: {:?}",
                    prog.get_name(),
                    prog.get_state()
                );
                debug!("{}", &err_msg);
                return Err(anyhow::Error::msg(err_msg));
            }
        }

        Ok(())
    }

    pub(crate) async fn unload(&self, program_name: String) -> Result<(), anyhow::Error> {
        let program = self
            .registry_manager
            .get_program(program_name.as_str(), None)
            .ok_or(anyhow::Error::msg(format!(
                "Failed to get program {} for unloading.",
                program_name
            )))?;

        program.stop().await?;

        self.shutdown_tx
            .send(ShutdownSignal::ProgramName(program_name.clone()))
            .map_err(|e| {
                error!(
                    "Failed to send shutdown signal for program {}: {:?}",
                    program_name, e
                );
                anyhow::Error::new(e)
            })?;

        let handle = {
            let mut handles = self.program_handles.lock();
            handles
                .remove(&program_name)
                .ok_or(anyhow::Error::msg(format!(
                    "Failed to get handle for program {} for unloading.",
                    program_name
                )))?
        };

        match handle.await {
            Ok(_) => {
                info!("Program {} stopped successfully.", program_name);
            }
            Err(e) => {
                error!("Failed during program operation {}: {:?}", program_name, e);
                return Err(anyhow::Error::new(e));
            }
        }

        Ok(())
    }
}
