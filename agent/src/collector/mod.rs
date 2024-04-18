use std::fmt::Debug;

use prometheus_client::collector::Collector as PrometheusCollector;
use prometheus_client::encoding::DescriptorEncoder;

use crate::managers::registry::RegistryManager;
use agent_api::ProgramState;

#[derive(Debug)]
pub(crate) struct Collector {
    registry_manager: RegistryManager,
}

impl Collector {
    pub(crate) fn new(registry_manager: RegistryManager) -> Self {
        Self { registry_manager }
    }
}

impl PrometheusCollector for Collector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let progs = self.registry_manager.builtin.list();

        // 筛选出状态为 Running 的 progs
        let running_progs: Vec<_> = progs
            .iter()
            .filter(|prog| prog.get_state() == ProgramState::Running)
            .collect();

        for prog in running_progs {
            if let Err(e) = prog.collect(&mut encoder) {
                eprintln!("Failed to collect metrics: {:?}", e);
            }
        }

        Ok(())
    }
}
