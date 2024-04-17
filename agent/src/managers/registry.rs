use std::sync::Arc;

use crate::common::types::{ListFilter, ProgramType};
use ahash::AHashMap;
use parking_lot::RwLock;

use crate::progs::service_map::program::ServiceMap;
use crate::progs::types::Program;

#[derive(Debug, Clone)]
pub struct BuiltinRegistry {
    inner: Arc<RwLock<AHashMap<String, Arc<dyn Program>>>>,
}

impl BuiltinRegistry {
    pub fn new() -> Self {
        let registry = Self {
            inner: Arc::new(RwLock::new(AHashMap::new())),
        };
        registry
    }

    pub fn register_builtin_progs(&self) {
        let mut inner = self.inner.write();
        inner.insert("service_map".to_string(), Arc::new(ServiceMap::new()));
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Program>> {
        let inner = self.inner.read();
        inner.get(name).cloned()
    }

    pub fn insert(&self, name: &str, program: Arc<dyn Program>) -> Option<Arc<dyn Program>> {
        let mut inner = self.inner.write();
        inner.insert(name.parse().unwrap(), program)
    }

    pub fn remove(&self, name: &str) -> Option<Arc<dyn Program>> {
        let mut inner = self.inner.write();
        inner.remove(name)
    }

    pub fn list(&self) -> Vec<Arc<dyn Program>> {
        let inner = self.inner.read();
        inner.values().cloned().collect()
    }
}

#[derive(Debug, Clone)]
pub struct WasmRegistry {
    inner: Arc<RwLock<AHashMap<String, Arc<dyn Program>>>>,
}

impl WasmRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(AHashMap::new())),
        }
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Program>> {
        let inner = self.inner.read();
        inner.get(name).cloned()
    }

    pub fn insert(&self, name: &str, program: Arc<dyn Program>) -> Option<Arc<dyn Program>> {
        let mut inner = self.inner.write();
        inner.insert(name.parse().unwrap(), program)
    }

    pub fn remove(&self, name: &str) -> Option<Arc<dyn Program>> {
        let mut inner = self.inner.write();
        inner.remove(name)
    }

    pub fn list(&self) -> Vec<Arc<dyn Program>> {
        let inner = self.inner.read();
        inner.values().cloned().collect()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RegistryManager {
    pub builtin: BuiltinRegistry,
    pub wasm: WasmRegistry,
}

impl RegistryManager {
    pub fn new() -> Self {
        let reg_mgr = Self {
            builtin: BuiltinRegistry::new(),
            wasm: WasmRegistry::new(),
        };
        reg_mgr.builtin.register_builtin_progs();
        reg_mgr
    }
    pub fn insert_program(
        &self,
        name: &str,
        program: Arc<dyn Program>,
        program_type: Option<ProgramType>,
    ) -> Result<(), String> {
        if self.get_program(name, program_type.clone()).is_some() {
            return Err("Program name already exists in the registry.".to_string());
        }

        match program_type {
            Some(ProgramType::Builtin) => {
                self.builtin.insert(name, program);
            }
            Some(ProgramType::Wasm) => {
                self.wasm.insert(name, program);
            }
            None => {
                self.builtin
                    .insert(name, program.clone())
                    .or_else(|| self.wasm.insert(name, program.clone()));
            }
        }

        Ok(())
    }

    pub fn remove_program(
        &self,
        name: &str,
        program_type: Option<ProgramType>,
    ) -> Option<Arc<dyn Program>> {
        match program_type {
            Some(ProgramType::Builtin) => self.builtin.remove(name),
            Some(ProgramType::Wasm) => self.wasm.remove(name),
            None => self.builtin.remove(name).or_else(|| self.wasm.remove(name)),
        }
    }

    pub fn get_program(
        &self,
        name: &str,
        program_type: Option<ProgramType>,
    ) -> Option<Arc<dyn Program>> {
        match program_type {
            Some(ProgramType::Builtin) => self.builtin.get(name),
            Some(ProgramType::Wasm) => self.wasm.get(name),
            None => self.builtin.get(name).or_else(|| self.wasm.get(name)),
        }
    }

    pub fn list_programs(&self, list_filter: ListFilter) -> Vec<Arc<dyn Program>> {
        let mut programs = self.builtin.list();
        programs.extend(self.wasm.list());
        programs
            .into_iter()
            .filter(|prog| list_filter.matches(prog.clone()))
            .collect()
    }
}
