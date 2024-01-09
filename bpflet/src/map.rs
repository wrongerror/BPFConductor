use std::path::{Path, PathBuf};
use std::collections::HashMap;
use bpflet_api::{ProgramType, constants::directories::RTDIR_FS_MAPS};
use tokio::fs::create_dir_all;
use crate::dispatcher::{Dispatcher, DispatcherId};
use crate::errors::BpfletError;
use crate::program::Direction;
use crate::program::program::Program;

pub const MAPS_MODE: u32 = 0o0660;

pub(crate) struct ProgramMap {
    programs: HashMap<u32, Program>,
}

impl ProgramMap {
    pub(crate) fn new() -> Self {
        ProgramMap {
            programs: HashMap::new(),
        }
    }

    pub(crate) fn insert(&mut self, id: u32, prog: Program) -> Option<Program> {
        self.programs.insert(id, prog)
    }

    pub(crate) fn remove(&mut self, id: &u32) -> Option<Program> {
        self.programs.remove(id)
    }

    pub(crate) fn get_mut(&mut self, id: &u32) -> Option<&mut Program> {
        self.programs.get_mut(id)
    }

    pub(crate) fn get(&self, id: &u32) -> Option<&Program> {
        self.programs.get(id)
    }

    pub(crate) fn programs_mut<'a>(
        &'a mut self,
        program_type: &'a ProgramType,
        if_index: &'a Option<u32>,
        direction: &'a Option<Direction>,
    ) -> impl Iterator<Item=&'a mut Program> {
        self.programs.values_mut().filter(|p| {
            p.kind() == *program_type
                && p.if_index().unwrap() == *if_index
                && p.direction().unwrap() == *direction
        })
    }

    // Adds a new program and sets the positions of programs that are to be attached via a dispatcher.
    // Positions are set based on order of priority. Ties are broken based on:
    // - Already attached programs are preferred
    // - Program name. Lowest lexical order wins.
    pub(crate) fn add_and_set_program_positions(&mut self, program: &mut Program) {
        let program_type = program.kind();
        let if_index = program.if_index().unwrap();
        let direction = program.direction().unwrap();

        let mut extensions = self
            .programs
            .values_mut()
            .filter(|p| {
                p.kind() == program_type
                    && p.if_index().unwrap() == if_index
                    && p.direction().unwrap() == direction
            })
            .collect::<Vec<&mut Program>>();

        // add program we're loading
        extensions.push(program);

        extensions.sort_by_key(|b| {
            (
                b.priority().unwrap(),
                b.attached(),
                b.get_data().get_name().unwrap().to_owned(),
            )
        });
        for (i, v) in extensions.iter_mut().enumerate() {
            v.set_position(i).expect("unable to set program position");
        }
    }

    // Sets the positions of programs that are to be attached via a dispatcher.
    // Positions are set based on order of priority. Ties are broken based on:
    // - Already attached programs are preferred
    // - Program name. Lowest lexical order wins.
    pub(crate) fn set_program_positions(
        &mut self,
        program_type: ProgramType,
        if_index: u32,
        direction: Option<Direction>,
    ) {
        let mut extensions = self
            .programs
            .values_mut()
            .filter(|p| {
                p.kind() == program_type
                    && p.if_index().unwrap() == Some(if_index)
                    && p.direction().unwrap() == direction
            })
            .collect::<Vec<&mut Program>>();

        extensions.sort_by_key(|b| {
            (
                b.priority().unwrap(),
                b.attached(),
                b.get_data().get_name().unwrap().to_owned(),
            )
        });
        for (i, v) in extensions.iter_mut().enumerate() {
            v.set_position(i).expect("unable to set program position");
        }
    }

    pub(crate) fn get_programs_iter(&self) -> impl Iterator<Item=(u32, &Program)> {
        self.programs
            .values()
            .map(|p| (p.get_data().get_id().unwrap(), p))
    }
}


pub(crate) struct DispatcherMap {
    dispatchers: HashMap<DispatcherId, Dispatcher>,
}

impl DispatcherMap {
    pub(crate) fn new() -> Self {
        DispatcherMap {
            dispatchers: HashMap::new(),
        }
    }

    pub(crate) fn remove(&mut self, id: &DispatcherId) -> Option<Dispatcher> {
        self.dispatchers.remove(id)
    }

    pub(crate) fn insert(&mut self, id: DispatcherId, dis: Dispatcher) -> Option<Dispatcher> {
        self.dispatchers.insert(id, dis)
    }

    /// Returns the number of extension programs currently attached to the dispatcher that
    /// would be used to attach the provided [`Program`].
    pub(crate) fn attached_programs(&self, did: &DispatcherId) -> usize {
        if let Some(d) = self.dispatchers.get(did) {
            d.num_extensions()
        } else {
            0
        }
    }
}

// map_pin_path is a the directory the maps are located. Currently, it
// is a fixed Bpflet location containing the map_index, which is a ID.
// The ID is either the programs ID, or the ID of another program
// that map_owner_id references.
pub fn calc_map_pin_path(id: u32) -> PathBuf {
    PathBuf::from(format!("{RTDIR_FS_MAPS}/{}", id))
}

// Create the map_pin_path for a given program.
pub async fn create_map_pin_path(p: &Path) -> Result<(), BpfletError> {
    create_dir_all(p)
        .await
        .map_err(|e| BpfletError::Error(format!("can't create map dir: {e}")))
}

// BpfMap represents a single map pin path used by a Program.  It has to be a
// separate object because it's lifetime is slightly different from a Program.
// More specifically a BpfMap can outlive a Program if other Programs are using
// it.
#[derive(Debug, Clone)]
pub(crate) struct BpfMap {
    pub(crate) used_by: Vec<u32>,
}
