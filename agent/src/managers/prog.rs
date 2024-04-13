use crate::managers::cache::CacheManager;
use crate::managers::image::ImageManager;
use crate::managers::registry::RegistryManager;
use crate::progs::types::Program;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) struct ProgManager {
    pub cache_manager: CacheManager,
    pub image_manager: ImageManager,
    pub registry_manager: RegistryManager,
}

impl ProgManager {
    pub(crate) async fn new() -> anyhow::Result<ProgManager> {
        let cache_manager = CacheManager::new().await?;
        cache_manager.wait_for_cache_sync().await?;
        Ok(Self {
            cache_manager,
            image_manager: ImageManager::new(),
            registry_manager: RegistryManager::new(),
        })
    }

    pub(crate) async fn load(&self, prog: Arc<dyn Program>) -> Result<(), anyhow::Error> {
        Ok(())
    }
}
