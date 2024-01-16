use bpflet_api::ProgramType;

use crate::errors::BpfletError;
use crate::helper::{bytes_to_bool, bytes_to_i32, bytes_to_string, bytes_to_u64};
use crate::program::program::ProgramData;

#[derive(Debug, Clone)]
pub(crate) struct UprobeProgram {
    pub(crate) data: ProgramData,
}

impl UprobeProgram {
    pub(crate) fn new(
        data: ProgramData,
        fn_name: Option<String>,
        offset: u64,
        target: String,
        retprobe: bool,
        pid: Option<i32>,
        container_pid: Option<i32>,
    ) -> Result<Self, BpfletError> {
        let mut uprobe_prog = Self { data };

        if fn_name.is_some() {
            uprobe_prog.set_fn_name(fn_name.unwrap())?;
        }

        uprobe_prog.set_offset(offset)?;
        uprobe_prog.set_retprobe(retprobe)?;
        if let Some(p) = container_pid {
            uprobe_prog.set_container_pid(p)?;
        }
        if let Some(p) = pid {
            uprobe_prog.set_pid(p)?;
        }
        uprobe_prog.set_target(target)?;
        uprobe_prog.get_data_mut().set_kind(ProgramType::Probe)?;
        Ok(uprobe_prog)
    }

    pub(crate) fn set_fn_name(&mut self, fn_name: String) -> Result<(), BpfletError> {
        self.data.insert("uprobe_fn_name", fn_name.as_bytes())
    }

    pub(crate) fn get_fn_name(&self) -> Result<Option<String>, BpfletError> {
        Ok(self
            .data
            .get_option("uprobe_fn_name")?
            .map(|v| bytes_to_string(&v)))
    }

    pub(crate) fn set_offset(&mut self, offset: u64) -> Result<(), BpfletError> {
        self.data.insert("uprobe_offset", &offset.to_ne_bytes())
    }

    pub(crate) fn get_offset(&self) -> Result<u64, BpfletError> {
        self.data.get("uprobe_offset").map(bytes_to_u64)
    }

    pub(crate) fn set_retprobe(&mut self, retprobe: bool) -> Result<(), BpfletError> {
        self.data
            .insert("uprobe_retprobe", &(retprobe as i8 % 2).to_ne_bytes())
    }

    pub(crate) fn get_retprobe(&self) -> Result<bool, BpfletError> {
        Ok(self
            .data
            .get_option("uprobe_retprobe")?
            .map(|n| bytes_to_bool(n.to_vec()))
            .unwrap_or(false))
    }

    pub(crate) fn set_container_pid(&mut self, container_pid: i32) -> Result<(), BpfletError> {
        self.data
            .insert("uprobe_container_pid", &container_pid.to_ne_bytes())
    }

    pub(crate) fn get_container_pid(&self) -> Result<Option<i32>, BpfletError> {
        Ok(self
            .data
            .get_option("uprobe_container_pid")?
            .map(|v| bytes_to_i32(v.to_vec())))
    }

    pub(crate) fn set_pid(&mut self, pid: i32) -> Result<(), BpfletError> {
        self.data.insert("uprobe_pid", &pid.to_ne_bytes())
    }

    pub(crate) fn get_pid(&self) -> Result<Option<i32>, BpfletError> {
        Ok(self
            .data
            .get_option("uprobe_pid")?
            .map(|v| bytes_to_i32(v.to_vec())))
    }

    pub(crate) fn set_target(&mut self, target: String) -> Result<(), BpfletError> {
        self.data.insert("uprobe_target", target.as_bytes())
    }

    pub(crate) fn get_target(&self) -> Result<String, BpfletError> {
        self.data.get("uprobe_target").map(|v| bytes_to_string(&v))
    }

    pub(crate) fn get_data(&self) -> &ProgramData {
        &self.data
    }

    pub(crate) fn get_data_mut(&mut self) -> &mut ProgramData {
        &mut self.data
    }
}
