use bpflet_api::ProgramType;
use crate::errors::BpfletError;
use crate::helper::bytes_to_string;
use crate::program::program::ProgramData;

#[derive(Debug, Clone)]
pub(crate) struct TracepointProgram {
    pub(crate) data: ProgramData,
}

impl TracepointProgram {
    pub(crate) fn new(data: ProgramData, tracepoint: String) -> Result<Self, BpfletError> {
        let mut tp_prog = Self { data };
        tp_prog.set_tracepoint(tracepoint)?;
        tp_prog.get_data_mut().set_kind(ProgramType::Tracepoint)?;

        Ok(tp_prog)
    }

    pub(crate) fn set_tracepoint(&mut self, tracepoint: String) -> Result<(), BpfletError> {
        self.data.insert("tracepoint_name", tracepoint.as_bytes())
    }

    pub(crate) fn get_tracepoint(&self) -> Result<String, BpfletError> {
        self.data
            .get("tracepoint_name")
            .map(|v| bytes_to_string(&v))
    }

    pub(crate) fn get_data(&self) -> &ProgramData {
        &self.data
    }

    pub(crate) fn get_data_mut(&mut self) -> &mut ProgramData {
        &mut self.data
    }
}
