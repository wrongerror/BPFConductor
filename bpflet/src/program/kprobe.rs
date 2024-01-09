use bpflet_api::ProgramType;
use crate::errors::BpfletError;
use crate::helper::{bytes_to_bool, bytes_to_i32, bytes_to_string, bytes_to_u64};
use crate::program::program::ProgramData;

#[derive(Debug, Clone)]
pub(crate) struct KprobeProgram {
    pub(crate) data: ProgramData,
}

impl KprobeProgram {
    pub(crate) fn new(
        data: ProgramData,
        fn_name: String,
        offset: u64,
        retprobe: bool,
        container_pid: Option<i32>,
    ) -> Result<Self, BpfletError> {
        let mut kprobe_prog = Self { data };
        kprobe_prog.set_fn_name(fn_name)?;
        kprobe_prog.set_offset(offset)?;
        kprobe_prog.set_retprobe(retprobe)?;
        kprobe_prog.get_data_mut().set_kind(ProgramType::Probe)?;
        if container_pid.is_some() {
            kprobe_prog.set_container_pid(container_pid.unwrap())?;
        }
        Ok(kprobe_prog)
    }

    pub(crate) fn set_fn_name(&mut self, fn_name: String) -> Result<(), BpfletError> {
        self.data.insert("kprobe_fn_name", fn_name.as_bytes())
    }

    pub(crate) fn get_fn_name(&self) -> Result<String, BpfletError> {
        self.data.get("kprobe_fn_name").map(|v| bytes_to_string(&v))
    }

    pub(crate) fn set_offset(&mut self, offset: u64) -> Result<(), BpfletError> {
        self.data.insert("kprobe_offset", &offset.to_ne_bytes())
    }

    pub(crate) fn get_offset(&self) -> Result<u64, BpfletError> {
        self.data.get("kprobe_offset").map(bytes_to_u64)
    }

    pub(crate) fn set_retprobe(&mut self, retprobe: bool) -> Result<(), BpfletError> {
        self.data
            .insert("kprobe_retprobe", &(retprobe as i8 % 2).to_ne_bytes())
    }

    pub(crate) fn get_retprobe(&self) -> Result<bool, BpfletError> {
        Ok(self
            .data
            .get_option("kprobe_retprobe")?
            .map(|n| bytes_to_bool(n.to_vec()))
            .unwrap_or(false))
    }

    pub(crate) fn set_container_pid(&mut self, container_pid: i32) -> Result<(), BpfletError> {
        self.data
            .insert("kprobe_container_pid", &container_pid.to_ne_bytes())
    }

    pub(crate) fn get_container_pid(&self) -> Result<Option<i32>, BpfletError> {
        Ok(self
            .data
            .get_option("kprobe_container_pid")?
            .map(|v| bytes_to_i32(v.to_vec())))
    }

    pub(crate) fn get_data(&self) -> &ProgramData {
        &self.data
    }

    pub(crate) fn get_data_mut(&mut self) -> &mut ProgramData {
        &mut self.data
    }
}
