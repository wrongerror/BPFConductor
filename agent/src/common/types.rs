use crate::progs::types::Program;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    pub(crate) program_type: Option<u32>,
    pub(crate) metadata_selector: HashMap<String, String>,
}

impl ListFilter {
    pub fn new(program_type: Option<u32>, metadata: HashMap<String, String>) -> Self {
        Self {
            program_type,
            metadata_selector: metadata,
        }
    }

    pub(crate) fn matches(&self, prog: Arc<dyn Program>) -> bool {
        let program_type: u32 = match prog.get_type().try_into() {
            Ok(t) => t,
            Err(_) => return false,
        };
        if let Some(filter_type) = self.program_type {
            if filter_type != program_type {
                return false;
            }
        }

        for (key, value) in self.metadata_selector.iter() {
            if let Some(v) = prog.get_metadata().get(key) {
                if *v != *value {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }
}
