use bpflet_api::{ProgramType, TcProceedOn, TcProceedOnEntry};

use crate::errors::BpfletError;
use crate::helper::{bytes_to_bool, bytes_to_i32, bytes_to_string, bytes_to_u32, bytes_to_usize};
use crate::program::program::ProgramData;
use crate::program::Direction;

#[derive(Debug, Clone)]
pub(crate) struct TcProgram {
    pub(crate) data: ProgramData,
}

impl TcProgram {
    pub(crate) fn new(
        data: ProgramData,
        priority: i32,
        iface: String,
        proceed_on: TcProceedOn,
        direction: Direction,
    ) -> Result<Self, BpfletError> {
        let mut tc_prog = Self { data };

        tc_prog.set_priority(priority)?;
        tc_prog.set_iface(iface)?;
        tc_prog.set_proceed_on(proceed_on)?;
        tc_prog.set_direction(direction)?;
        tc_prog.get_data_mut().set_kind(ProgramType::Tc)?;

        Ok(tc_prog)
    }

    pub(crate) fn set_priority(&mut self, priority: i32) -> Result<(), BpfletError> {
        self.data.insert("tc_priority", &priority.to_ne_bytes())
    }

    pub(crate) fn get_priority(&self) -> Result<i32, BpfletError> {
        self.data.get("tc_priority").map(bytes_to_i32)
    }

    pub(crate) fn set_iface(&mut self, iface: String) -> Result<(), BpfletError> {
        self.data.insert("tc_iface", iface.as_bytes())
    }

    pub(crate) fn get_iface(&self) -> Result<String, BpfletError> {
        self.data.get("tc_iface").map(|v| bytes_to_string(&v))
    }

    pub(crate) fn set_proceed_on(&mut self, proceed_on: TcProceedOn) -> Result<(), BpfletError> {
        proceed_on
            .as_action_vec()
            .iter()
            .enumerate()
            .try_for_each(|(i, v)| {
                self.data
                    .insert(format!("tc_proceed_on_{i}").as_str(), &v.to_ne_bytes())
            })
    }

    pub(crate) fn get_proceed_on(&self) -> Result<TcProceedOn, BpfletError> {
        self.data
            .db_tree
            .scan_prefix("tc_proceed_on_")
            .map(|n| n.map(|(_, v)| TcProceedOnEntry::try_from(bytes_to_i32(v.to_vec())).unwrap()))
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
        self.data.insert("tc_current_position", &pos.to_ne_bytes())
    }

    pub(crate) fn get_current_position(&self) -> Result<Option<usize>, BpfletError> {
        Ok(self
            .data
            .get_option("tc_current_position")?
            .map(|v| bytes_to_usize(v.to_vec())))
    }

    pub(crate) fn set_if_index(&mut self, if_index: u32) -> Result<(), BpfletError> {
        self.data.insert("tc_if_index", &if_index.to_ne_bytes())
    }

    pub(crate) fn get_if_index(&self) -> Result<Option<u32>, BpfletError> {
        Ok(self
            .data
            .get_option("tc_if_index")?
            .map(|v| bytes_to_u32(v.to_vec())))
    }

    pub(crate) fn set_attached(&mut self, attached: bool) -> Result<(), BpfletError> {
        self.data
            .insert("tc_attached", &(attached as i8).to_ne_bytes())
    }

    pub(crate) fn get_attached(&self) -> Result<bool, BpfletError> {
        Ok(self
            .data
            .get_option("tc_attached")?
            .map(|n| bytes_to_bool(n.to_vec()))
            .unwrap_or(false))
    }

    pub(crate) fn set_direction(&mut self, direction: Direction) -> Result<(), BpfletError> {
        self.data
            .insert("tc_direction", direction.to_string().as_bytes())
    }

    pub(crate) fn get_direction(&self) -> Result<Direction, BpfletError> {
        self.data
            .get("tc_direction")
            .map(|v| bytes_to_string(&v).to_string().try_into().unwrap())
    }

    pub(crate) fn get_data(&self) -> &ProgramData {
        &self.data
    }

    pub(crate) fn get_data_mut(&mut self) -> &mut ProgramData {
        &mut self.data
    }
}
