use bpflet_api::{ProgramType, XdpProceedOn, XdpProceedOnEntry};

use crate::errors::BpfletError;
use crate::helper::{bytes_to_bool, bytes_to_i32, bytes_to_string, bytes_to_u32, bytes_to_usize};
use crate::program::program::ProgramData;

#[derive(Debug, Clone)]
pub(crate) struct XdpProgram {
    pub(crate) data: ProgramData,
}

impl XdpProgram {
    pub(crate) fn new(
        data: ProgramData,
        priority: i32,
        iface: String,
        proceed_on: XdpProceedOn,
    ) -> Result<Self, BpfletError> {
        let mut xdp_prog = Self { data };

        xdp_prog.set_priority(priority)?;
        xdp_prog.set_iface(iface)?;
        xdp_prog.set_proceed_on(proceed_on)?;
        xdp_prog.get_data_mut().set_kind(ProgramType::Xdp)?;

        Ok(xdp_prog)
    }

    pub(crate) fn set_priority(&mut self, priority: i32) -> Result<(), BpfletError> {
        self.data.insert("xdp_priority", &priority.to_ne_bytes())
    }

    pub(crate) fn get_priority(&self) -> Result<i32, BpfletError> {
        self.data.get("xdp_priority").map(bytes_to_i32)
    }

    pub(crate) fn set_iface(&mut self, iface: String) -> Result<(), BpfletError> {
        self.data.insert("xdp_iface", iface.as_bytes())
    }

    pub(crate) fn get_iface(&self) -> Result<String, BpfletError> {
        self.data.get("xdp_iface").map(|v| bytes_to_string(&v))
    }

    pub(crate) fn set_proceed_on(&mut self, proceed_on: XdpProceedOn) -> Result<(), BpfletError> {
        proceed_on
            .as_action_vec()
            .iter()
            .enumerate()
            .try_for_each(|(i, v)| {
                self.data
                    .insert(format!("xdp_proceed_on_{i}").as_str(), &v.to_ne_bytes())
            })
    }

    pub(crate) fn get_proceed_on(&self) -> Result<XdpProceedOn, BpfletError> {
        self.data
            .db_tree
            .scan_prefix("xdp_proceed_on_")
            .map(|n| {
                n.map(|(_, v)| XdpProceedOnEntry::try_from(bytes_to_i32(v.to_vec())))
                    .unwrap()
            })
            .map(|n| {
                n.map_err(|e| {
                    BpfletError::DatabaseError(
                        "Failed to get proceed on".to_string(),
                        e.to_string(),
                    )
                })
            })
            .collect()
    }

    pub(crate) fn set_current_position(&mut self, pos: usize) -> Result<(), BpfletError> {
        self.data.insert("xdp_current_position", &pos.to_ne_bytes())
    }

    pub(crate) fn get_current_position(&self) -> Result<Option<usize>, BpfletError> {
        Ok(self
            .data
            .get_option("xdp_current_position")?
            .map(|v| bytes_to_usize(v.to_vec())))
    }

    pub(crate) fn set_if_index(&mut self, if_index: u32) -> Result<(), BpfletError> {
        self.data.insert("xdp_if_index", &if_index.to_ne_bytes())
    }

    pub(crate) fn get_if_index(&self) -> Result<Option<u32>, BpfletError> {
        Ok(self
            .data
            .get_option("xdp_if_index")?
            .map(|v| bytes_to_u32(v.to_vec())))
    }

    pub(crate) fn set_attached(&mut self, attached: bool) -> Result<(), BpfletError> {
        self.data
            .insert("xdp_attached", &(attached as i8).to_ne_bytes())
    }

    pub(crate) fn get_attached(&self) -> Result<bool, BpfletError> {
        Ok(self
            .data
            .get_option("xdp_attached")?
            .map(|n| bytes_to_bool(n.to_vec()))
            .unwrap_or(false))
    }

    pub(crate) fn get_data(&self) -> &ProgramData {
        &self.data
    }

    pub(crate) fn get_data_mut(&mut self) -> &mut ProgramData {
        &mut self.data
    }
}
