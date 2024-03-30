use ahash::AHashMap;
use std::sync::{Arc, RwLock};

use crate::progs::types::Program;

#[derive(Debug, Clone)]
pub(crate) struct Registry {
    inner: Arc<RwLock<AHashMap<String, Arc<dyn Program>>>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(AHashMap::new())),
        }
    }

    pub(crate) async fn insert(&self, name: String, prog: Arc<dyn Program>) {
        self.inner.write().unwrap().insert(name, prog);
    }

    pub(crate) async fn remove(&self, name: String) {
        self.inner.write().unwrap().remove(&name);
    }

    pub(crate) async fn get(&self, name: String) -> Option<Arc<dyn Program>> {
        self.inner.read().unwrap().get(&name).cloned()
    }

    pub(crate) async fn list(&self) -> Vec<Arc<dyn Program>> {
        self.inner.read().unwrap().values().cloned().collect()
    }

    pub(crate) async fn clear(&self) {
        self.inner.write().unwrap().clear();
    }
}
