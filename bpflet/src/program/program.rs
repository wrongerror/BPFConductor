use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use aya::programs::ProgramInfo as AyaProgInfo;
use chrono::{DateTime, Local};
use log::info;
use rand::Rng;
use tokio::sync::mpsc::Sender;

use bpflet_api::v1::{
    attach_info::Info, bytecode_location::Location as V1Location, AttachInfo, BytecodeLocation,
    KernelProgramInfo as V1KernelProgramInfo, KprobeAttachInfo, ProgramInfo as V1ProgramInfo,
    TcAttachInfo, TracepointAttachInfo, UprobeAttachInfo, XdpAttachInfo,
};
use bpflet_api::{constants::directories::*, ProgramType};

use crate::dispatcher::{DispatcherId, DispatcherInfo};
use crate::errors::BpfletError;
use crate::helper::{bytes_to_bool, bytes_to_string, bytes_to_u32};
use crate::oci::manager::{BytecodeImage, Command as ImageManagerCommand};
use crate::program::{
    kprobe::KprobeProgram, tc::TcProgram, tracepoint::TracepointProgram, uprobe::UprobeProgram,
    xdp::XdpProgram, Direction, Location,
};
use crate::BPFLET_DB;

#[derive(Debug, Clone)]
pub(crate) enum Program {
    Xdp(XdpProgram),
    Tc(TcProgram),
    Tracepoint(TracepointProgram),
    Kprobe(KprobeProgram),
    Uprobe(UprobeProgram),
    Unsupported(ProgramData),
}

impl Program {
    pub(crate) fn kind(&self) -> ProgramType {
        match self {
            Program::Xdp(_) => ProgramType::Xdp,
            Program::Tc(_) => ProgramType::Tc,
            Program::Tracepoint(_) => ProgramType::Tracepoint,
            Program::Kprobe(_) => ProgramType::Probe,
            Program::Uprobe(_) => ProgramType::Probe,
            Program::Unsupported(i) => i.get_kernel_program_type().unwrap().try_into().unwrap(),
        }
    }

    pub(crate) fn dispatcher_id(&self) -> Result<Option<DispatcherId>, BpfletError> {
        Ok(match self {
            Program::Xdp(p) => Some(DispatcherId::Xdp(DispatcherInfo(
                p.get_if_index()?
                    .expect("if_index should be known at this point"),
                None,
            ))),
            Program::Tc(p) => Some(DispatcherId::Tc(DispatcherInfo(
                p.get_if_index()?
                    .expect("if_index should be known at this point"),
                Some(p.get_direction()?),
            ))),
            _ => None,
        })
    }

    pub(crate) fn get_data_mut(&mut self) -> &mut ProgramData {
        match self {
            Program::Xdp(p) => &mut p.data,
            Program::Tracepoint(p) => &mut p.data,
            Program::Tc(p) => &mut p.data,
            Program::Kprobe(p) => &mut p.data,
            Program::Uprobe(p) => &mut p.data,
            Program::Unsupported(p) => p,
        }
    }

    pub(crate) fn attached(&self) -> bool {
        match self {
            Program::Xdp(p) => p.get_attached().unwrap(),
            Program::Tc(p) => p.get_attached().unwrap(),
            _ => false,
        }
    }

    pub(crate) fn set_attached(&mut self) {
        match self {
            Program::Xdp(p) => p.set_attached(true).unwrap(),
            Program::Tc(p) => p.set_attached(true).unwrap(),
            _ => (),
        };
    }

    pub(crate) fn set_position(&mut self, pos: usize) -> Result<(), BpfletError> {
        match self {
            Program::Xdp(p) => p.set_current_position(pos),
            Program::Tc(p) => p.set_current_position(pos),
            _ => Err(BpfletError::Error(
                "cannot set position on programs other than TC or XDP".to_string(),
            )),
        }
    }

    pub(crate) fn delete(&self) -> Result<(), anyhow::Error> {
        let id = self.get_data().get_id()?;
        BPFLET_DB.drop_tree(id.to_string())?;

        let path = format!("{RTDIR_FS}/prog_{id}");
        if PathBuf::from(&path).exists() {
            fs::remove_file(path)?;
        }
        let path = format!("{RTDIR_FS}/prog_{id}_link");
        if PathBuf::from(&path).exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    pub(crate) fn if_index(&self) -> Result<Option<u32>, BpfletError> {
        match self {
            Program::Xdp(p) => p.get_if_index(),
            Program::Tc(p) => p.get_if_index(),
            _ => Err(BpfletError::Error(
                "cannot get if_index on programs other than TC or XDP".to_string(),
            )),
        }
    }

    pub(crate) fn set_if_index(&mut self, if_index: u32) -> Result<(), BpfletError> {
        match self {
            Program::Xdp(p) => p.set_if_index(if_index),
            Program::Tc(p) => p.set_if_index(if_index),
            _ => Err(BpfletError::Error(
                "cannot set if_index on programs other than TC or XDP".to_string(),
            )),
        }
    }

    pub(crate) fn if_name(&self) -> Result<String, BpfletError> {
        match self {
            Program::Xdp(p) => p.get_iface(),
            Program::Tc(p) => p.get_iface(),
            _ => Err(BpfletError::Error(
                "cannot get interface on programs other than TC or XDP".to_string(),
            )),
        }
    }

    pub(crate) fn priority(&self) -> Result<i32, BpfletError> {
        match self {
            Program::Xdp(p) => p.get_priority(),
            Program::Tc(p) => p.get_priority(),
            _ => Err(BpfletError::Error(
                "cannot get priority on programs other than TC or XDP".to_string(),
            )),
        }
    }

    pub(crate) fn location(&self) -> Result<Location, BpfletError> {
        match self {
            Program::Xdp(p) => p.data.get_location(),
            Program::Tracepoint(p) => p.data.get_location(),
            Program::Tc(p) => p.data.get_location(),
            Program::Kprobe(p) => p.data.get_location(),
            Program::Uprobe(p) => p.data.get_location(),
            Program::Unsupported(_) => Err(BpfletError::Error(
                "cannot get location for unsupported programs".to_string(),
            )),
        }
    }

    pub(crate) fn direction(&self) -> Result<Option<Direction>, BpfletError> {
        match self {
            Program::Tc(p) => Ok(Some(p.get_direction()?)),
            _ => Ok(None),
        }
    }

    pub(crate) fn get_data(&self) -> &ProgramData {
        match self {
            Program::Xdp(p) => p.get_data(),
            Program::Tracepoint(p) => p.get_data(),
            Program::Tc(p) => p.get_data(),
            Program::Kprobe(p) => p.get_data(),
            Program::Uprobe(p) => p.get_data(),
            Program::Unsupported(p) => p,
        }
    }

    pub(crate) fn new_from_db(id: u32, tree: sled::Tree) -> Result<Self, BpfletError> {
        let data = ProgramData::new(tree, id);

        if data.get_id()? != id {
            return Err(BpfletError::Error(
                "Program id does not match database id program isn't fully loaded".to_string(),
            ));
        }
        match data.get_kind()? {
            Some(p) => match p {
                ProgramType::Xdp => Ok(Program::Xdp(XdpProgram { data })),
                ProgramType::Tc => Ok(Program::Tc(TcProgram { data })),
                ProgramType::Tracepoint => Ok(Program::Tracepoint(TracepointProgram { data })),
                // kernel does not distinguish between kprobe and uprobe program types
                ProgramType::Probe => {
                    if data.db_tree.get("uprobe_offset").unwrap().is_some() {
                        Ok(Program::Uprobe(UprobeProgram { data }))
                    } else {
                        Ok(Program::Kprobe(KprobeProgram { data }))
                    }
                }
                _ => Err(BpfletError::Error("Unsupported program type".to_string())),
            },
            None => Err(BpfletError::Error("Unsupported program type".to_string())),
        }
    }
}

/// ProgramInfo stores information about bpf programs that are loaded and managed
/// by bpflet.
#[derive(Debug, Clone)]
pub(crate) struct ProgramData {
    // Prior to load this will be a temporary Tree with a random ID, following
    // load it will be replaced with the main program database tree.
    pub(crate) db_tree: sled::Tree,

    // populated after load, randomly generated prior to load.
    id: u32,

    // program_bytes is used to temporarily cache the raw program data during
    // the loading process.  It MUST be cleared following a load so that there
    // is not a long lived copy of the program data living on the heap.
    program_bytes: Vec<u8>,
}

impl ProgramData {
    pub(crate) fn new(tree: sled::Tree, id: u32) -> Self {
        Self {
            db_tree: tree,
            id,
            program_bytes: Vec::new(),
        }
    }
    pub(crate) fn new_pre_load(
        location: Location,
        name: String,
        metadata: HashMap<String, String>,
        global_data: HashMap<String, Vec<u8>>,
        map_owner_id: Option<u32>,
    ) -> Result<Self, BpfletError> {
        let mut rng = rand::thread_rng();
        let id_rand = rng.gen::<u32>();

        let db_tree = BPFLET_DB
            .open_tree(id_rand.to_string())
            .expect("Unable to open program database tree");

        let mut pd = Self {
            db_tree,
            id: id_rand,
            program_bytes: Vec::new(),
        };

        pd.set_location(location)?;
        pd.set_name(&name)?;
        pd.set_metadata(metadata)?;
        pd.set_global_data(global_data)?;
        if let Some(id) = map_owner_id {
            pd.set_map_owner_id(id)?;
        };

        Ok(pd)
    }

    pub(crate) fn swap_tree(&mut self, new_id: u32) -> Result<(), BpfletError> {
        let new_tree = BPFLET_DB
            .open_tree(new_id.to_string())
            .expect("Unable to open program database tree");

        // Copy over all key's and values to new tree
        for r in self.db_tree.into_iter() {
            let (k, v) = r.expect("unable to iterate db_tree");
            new_tree.insert(k, v).map_err(|e| {
                BpfletError::DatabaseError(
                    "unable to insert entry during copy".to_string(),
                    e.to_string(),
                )
            })?;
        }

        BPFLET_DB
            .drop_tree(self.db_tree.name())
            .expect("unable to delete temporary program tree");

        self.db_tree = new_tree;
        self.id = new_id;

        Ok(())
    }

    pub(crate) fn get(&self, key: &str) -> Result<Vec<u8>, BpfletError> {
        let value = self.db_tree.get(key).map_err(|e| {
            BpfletError::DatabaseError(
                format!(
                    "Unable to get database entry {key} from tree {}",
                    bytes_to_string(&self.db_tree.name())
                ),
                e.to_string(),
            )
        })?;

        match value.clone() {
            Some(v) => Ok(v.to_vec()),
            None => Err(BpfletError::DatabaseError(
                format!(
                    "Database entry {key} does not exist in tree {:?}",
                    bytes_to_string(&self.db_tree.name())
                ),
                "".to_string(),
            )),
        }
    }

    pub(crate) fn get_option(&self, key: &str) -> Result<Option<sled::IVec>, BpfletError> {
        self.db_tree.get(key).map_err(|e| {
            BpfletError::DatabaseError(
                format!(
                    "Unable to get database entry {key} from tree {} {}",
                    bytes_to_string(&self.db_tree.name()),
                    BPFLET_DB
                        .tree_names()
                        .iter()
                        .map(|n| bytes_to_string(n))
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                e.to_string(),
            )
        })
    }

    pub(crate) fn insert(&self, key: &str, value: &[u8]) -> Result<(), BpfletError> {
        self.db_tree.insert(key, value).map(|_| ()).map_err(|e| {
            BpfletError::DatabaseError(
                format!(
                    "Unable to insert database entry {key} into tree {:?}",
                    self.db_tree.name()
                ),
                e.to_string(),
            )
        })
    }

    /*
     * Methods for setting and getting program data for programs managed by
     * bpflet.
     */

    // A programData's kind could be different from the kernel_program_type value
    // since the TC and XDP programs loaded by bpflet will have a ProgramType::Ext
    // rather than ProgramType::Xdp or ProgramType::Tc.
    // Kind should only be set on programs loaded by bpflet.
    pub(crate) fn set_kind(&mut self, kind: ProgramType) -> Result<(), BpfletError> {
        self.insert("kind", &Into::<u32>::into(kind).to_ne_bytes())
    }

    pub(crate) fn get_kind(&self) -> Result<Option<ProgramType>, BpfletError> {
        self.get_option("kind")
            .map(|v| v.map(|v| bytes_to_u32(v.to_vec()).try_into().unwrap()))
    }

    pub(crate) fn set_name(&mut self, name: &str) -> Result<(), BpfletError> {
        self.insert("name", name.as_bytes())
    }

    pub(crate) fn get_name(&self) -> Result<String, BpfletError> {
        self.get("name").map(|v| bytes_to_string(&v))
    }

    pub(crate) fn set_id(&mut self, id: u32) -> Result<(), BpfletError> {
        // set db and local cache
        self.id = id;
        self.insert("id", &id.to_ne_bytes())
    }

    pub(crate) fn get_id(&self) -> Result<u32, BpfletError> {
        self.get("id").map(|v| bytes_to_u32(v.to_vec()))
    }

    pub(crate) fn set_location(&mut self, loc: Location) -> Result<(), BpfletError> {
        match loc {
            Location::File(l) => self.insert("location_filename", l.as_bytes()),
            Location::Image(l) => {
                self.insert("location_image_url", l.image_url.as_bytes())?;
                self.insert(
                    "location_image_pull_policy",
                    l.image_pull_policy.to_string().as_bytes(),
                )?;
                if let Some(u) = l.username {
                    self.insert("location_username", u.as_bytes())?;
                };

                if let Some(p) = l.password {
                    self.insert("location_password", p.as_bytes())?;
                };
                Ok(())
            }
        }
        .map_err(|e| {
            BpfletError::DatabaseError(
                format!(
                    "Unable to insert location database entries into tree {:?}",
                    self.db_tree.name()
                ),
                e.to_string(),
            )
        })
    }

    pub(crate) fn get_location(&self) -> Result<Location, BpfletError> {
        if let Ok(l) = self.get("location_filename") {
            Ok(Location::File(bytes_to_string(&l).to_string()))
        } else {
            Ok(Location::Image(BytecodeImage {
                image_url: bytes_to_string(&self.get("location_image_url")?).to_string(),
                image_pull_policy: bytes_to_string(&self.get("location_image_pull_policy")?)
                    .as_str()
                    .try_into()
                    .unwrap(),
                username: self
                    .get_option("location_username")?
                    .map(|v| bytes_to_string(&v)),
                password: self
                    .get_option("location_password")?
                    .map(|v| bytes_to_string(&v)),
            }))
        }
    }

    pub(crate) fn set_global_data(
        &mut self,
        data: HashMap<String, Vec<u8>>,
    ) -> Result<(), BpfletError> {
        data.iter()
            .try_for_each(|(k, v)| self.insert(format!("global_data_{k}").as_str(), v))
    }

    pub(crate) fn get_global_data(&self) -> Result<HashMap<String, Vec<u8>>, BpfletError> {
        self.db_tree
            .scan_prefix("global_data_")
            .map(|n| {
                n.map(|(k, v)| {
                    (
                        bytes_to_string(&k)
                            .strip_prefix("global_data_")
                            .unwrap()
                            .to_string(),
                        v.to_vec(),
                    )
                })
            })
            .map(|n| {
                n.map_err(|e| {
                    BpfletError::DatabaseError(
                        "Failed to get global data".to_string(),
                        e.to_string(),
                    )
                })
            })
            .collect()
    }

    pub(crate) fn set_metadata(
        &mut self,
        data: HashMap<String, String>,
    ) -> Result<(), BpfletError> {
        data.iter()
            .try_for_each(|(k, v)| self.insert(format!("metadata_{k}").as_str(), v.as_bytes()))
    }

    pub(crate) fn get_metadata(&self) -> Result<HashMap<String, String>, BpfletError> {
        self.db_tree
            .scan_prefix("metadata_")
            .map(|n| {
                n.map(|(k, v)| {
                    (
                        bytes_to_string(&k)
                            .strip_prefix("metadata_")
                            .unwrap()
                            .to_string(),
                        bytes_to_string(&v).to_string(),
                    )
                })
            })
            .map(|n| {
                n.map_err(|e| {
                    BpfletError::DatabaseError("Failed to get metadata".to_string(), e.to_string())
                })
            })
            .collect()
    }

    pub(crate) fn set_map_owner_id(&mut self, id: u32) -> Result<(), BpfletError> {
        self.insert("map_owner_id", &id.to_ne_bytes())
    }

    pub(crate) fn get_map_owner_id(&self) -> Result<Option<u32>, BpfletError> {
        self.get_option("map_owner_id")
            .map(|v| v.map(|v| bytes_to_u32(v.to_vec())))
    }

    pub(crate) fn set_map_pin_path(&mut self, path: &Path) -> Result<(), BpfletError> {
        self.insert("map_pin_path", path.to_str().unwrap().as_bytes())
    }

    pub(crate) fn get_map_pin_path(&self) -> Result<Option<PathBuf>, BpfletError> {
        self.get_option("map_pin_path")
            .map(|v| v.map(|f| PathBuf::from(bytes_to_string(&f))))
    }

    // set_maps_used_by differs from other setters in that it's explicitly idempotent.
    pub(crate) fn set_maps_used_by(&mut self, ids: Vec<u32>) -> Result<(), BpfletError> {
        self.clear_maps_used_by();

        ids.iter().enumerate().try_for_each(|(i, v)| {
            self.insert(format!("maps_used_by_{i}").as_str(), &v.to_ne_bytes())
        })
    }

    pub(crate) fn get_maps_used_by(&self) -> Result<Vec<u32>, BpfletError> {
        self.db_tree
            .scan_prefix("maps_used_by_")
            .map(|n| n.map(|(_, v)| bytes_to_u32(v.to_vec())))
            .map(|n| {
                n.map_err(|e| {
                    BpfletError::DatabaseError(
                        "Failed to get maps used by".to_string(),
                        e.to_string(),
                    )
                })
            })
            .collect()
    }

    pub(crate) fn clear_maps_used_by(&self) {
        self.db_tree.scan_prefix("maps_used_by_").for_each(|n| {
            self.db_tree
                .remove(n.unwrap().0)
                .expect("unable to clear maps used by");
        });
    }

    /*
     * End bpflet program info getters/setters.
     */

    /*
     * Methods for setting and getting kernel information.
     */

    pub(crate) fn get_kernel_name(&self) -> Result<String, BpfletError> {
        self.get("kernel_name").map(|n| bytes_to_string(&n))
    }

    pub(crate) fn set_kernel_name(&mut self, name: &str) -> Result<(), BpfletError> {
        self.insert("kernel_name", name.as_bytes())
    }

    pub(crate) fn get_kernel_program_type(&self) -> Result<u32, BpfletError> {
        self.get("kernel_program_type").map(bytes_to_u32)
    }

    pub(crate) fn set_kernel_program_type(&mut self, program_type: u32) -> Result<(), BpfletError> {
        self.insert("kernel_program_type", &program_type.to_ne_bytes())
    }

    pub(crate) fn get_kernel_loaded_at(&self) -> Result<String, BpfletError> {
        self.get("kernel_loaded_at").map(|n| bytes_to_string(&n))
    }

    pub(crate) fn set_kernel_loaded_at(
        &mut self,
        loaded_at: SystemTime,
    ) -> Result<(), BpfletError> {
        self.insert(
            "kernel_loaded_at",
            DateTime::<Local>::from(loaded_at)
                .format("%Y-%m-%dT%H:%M:%S%z")
                .to_string()
                .as_bytes(),
        )
    }

    pub(crate) fn get_kernel_tag(&self) -> Result<String, BpfletError> {
        self.get("kernel_tag").map(|n| bytes_to_string(&n))
    }

    pub(crate) fn set_kernel_tag(&mut self, tag: u64) -> Result<(), BpfletError> {
        self.insert("kernel_tag", format!("{:x}", tag).as_str().as_bytes())
    }

    pub(crate) fn set_kernel_gpl_compatible(
        &mut self,
        gpl_compatible: bool,
    ) -> Result<(), BpfletError> {
        self.insert(
            "kernel_gpl_compatible",
            &(gpl_compatible as i8 % 2).to_ne_bytes(),
        )
    }

    pub(crate) fn get_kernel_gpl_compatible(&self) -> Result<bool, BpfletError> {
        self.get("kernel_gpl_compatible").map(bytes_to_bool)
    }

    pub(crate) fn get_kernel_map_ids(&self) -> Result<Vec<u32>, BpfletError> {
        self.db_tree
            .scan_prefix("kernel_map_ids_".as_bytes())
            .map(|n| n.map(|(_, v)| bytes_to_u32(v.to_vec())))
            .map(|n| {
                n.map_err(|e| {
                    BpfletError::DatabaseError("Failed to get map ids".to_string(), e.to_string())
                })
            })
            .collect()
    }

    pub(crate) fn set_kernel_map_ids(&mut self, map_ids: Vec<u32>) -> Result<(), BpfletError> {
        let map_ids = map_ids.iter().map(|i| i.to_ne_bytes()).collect::<Vec<_>>();

        map_ids
            .iter()
            .enumerate()
            .try_for_each(|(i, v)| self.insert(format!("kernel_map_ids_{i}").as_str(), v))
    }

    pub(crate) fn get_kernel_btf_id(&self) -> Result<u32, BpfletError> {
        self.get("kernel_btf_id").map(bytes_to_u32)
    }

    pub(crate) fn set_kernel_btf_id(&mut self, btf_id: u32) -> Result<(), BpfletError> {
        self.insert("kernel_btf_id", &btf_id.to_ne_bytes())
    }

    pub(crate) fn get_kernel_bytes_xlated(&self) -> Result<u32, BpfletError> {
        self.get("kernel_bytes_xlated").map(bytes_to_u32)
    }

    pub(crate) fn set_kernel_bytes_xlated(&mut self, bytes_xlated: u32) -> Result<(), BpfletError> {
        self.insert("kernel_bytes_xlated", &bytes_xlated.to_ne_bytes())
    }

    pub(crate) fn get_kernel_jited(&self) -> Result<bool, BpfletError> {
        self.get("kernel_jited").map(bytes_to_bool)
    }

    pub(crate) fn set_kernel_jited(&mut self, jited: bool) -> Result<(), BpfletError> {
        self.insert("kernel_jited", &(jited as i8 % 2).to_ne_bytes())
    }

    pub(crate) fn get_kernel_bytes_jited(&self) -> Result<u32, BpfletError> {
        self.get("kernel_bytes_jited").map(bytes_to_u32)
    }

    pub(crate) fn set_kernel_bytes_jited(&mut self, bytes_jited: u32) -> Result<(), BpfletError> {
        self.insert("kernel_bytes_jited", &bytes_jited.to_ne_bytes())
    }

    pub(crate) fn get_kernel_bytes_memlock(&self) -> Result<u32, BpfletError> {
        self.get("kernel_bytes_memlock").map(bytes_to_u32)
    }

    pub(crate) fn set_kernel_bytes_memlock(
        &mut self,
        bytes_memlock: u32,
    ) -> Result<(), BpfletError> {
        self.insert("kernel_bytes_memlock", &bytes_memlock.to_ne_bytes())
    }

    pub(crate) fn get_kernel_verified_insns(&self) -> Result<u32, BpfletError> {
        self.get("kernel_verified_insns").map(bytes_to_u32)
    }

    pub(crate) fn set_kernel_verified_insns(
        &mut self,
        verified_insns: u32,
    ) -> Result<(), BpfletError> {
        self.insert("kernel_verified_insns", &verified_insns.to_ne_bytes())
    }

    pub(crate) fn set_kernel_info(&mut self, prog: &AyaProgInfo) -> Result<(), BpfletError> {
        self.set_id(prog.id())?;
        self.set_kernel_name(
            prog.name_as_str()
                .expect("Program name is not valid unicode"),
        )?;
        self.set_kernel_program_type(prog.program_type())?;
        self.set_kernel_loaded_at(prog.loaded_at())?;
        self.set_kernel_tag(prog.tag())?;
        self.set_kernel_gpl_compatible(prog.gpl_compatible())?;
        self.set_kernel_map_ids(prog.map_ids().map_err(BpfletError::BpfProgramError)?)?;
        self.set_kernel_btf_id(prog.btf_id().map_or(0, |n| n.into()))?;
        self.set_kernel_bytes_xlated(prog.size_translated())?;
        self.set_kernel_jited(prog.size_jitted() != 0)?;
        self.set_kernel_bytes_jited(prog.size_jitted())?;
        self.set_kernel_bytes_memlock(prog.memory_locked().map_err(BpfletError::BpfProgramError)?)?;
        self.set_kernel_verified_insns(prog.verified_instruction_count())?;

        Ok(())
    }

    /*
     * End kernel info getters/setters.
     */

    pub(crate) fn program_bytes(&self) -> &[u8] {
        &self.program_bytes
    }

    // In order to ensure that the program bytes, which can be a large amount
    // of data is only stored for as long as needed, make sure to call
    // clear_program_bytes following a load.
    pub(crate) fn clear_program_bytes(&mut self) {
        self.program_bytes = Vec::new();
    }

    pub(crate) async fn set_program_bytes(
        &mut self,
        image_manager: Sender<ImageManagerCommand>,
    ) -> Result<(), BpfletError> {
        let loc = self.get_location()?;
        match loc.get_program_bytes(image_manager).await {
            Err(e) => Err(e),
            Ok((v, s)) => {
                match loc {
                    Location::Image(l) => {
                        info!(
                            "Loading program bytecode from container image: {}",
                            l.get_url()
                        );
                        // If program name isn't provided and we're loading from a container
                        // image use the program name provided in the image metadata, otherwise
                        // always use the provided program name.
                        let provided_name = self.get_name()?.clone();

                        if provided_name.is_empty() {
                            self.set_name(&s)?;
                        } else if s != provided_name {
                            return Err(BpfletError::BytecodeMetaDataMismatch {
                                image_prog_name: s,
                                provided_prog_name: provided_name.to_string(),
                            });
                        }
                    }
                    Location::File(l) => {
                        info!("Loading program bytecode from file: {}", l);
                    }
                }
                self.program_bytes = v;
                Ok(())
            }
        }
    }
}

impl TryFrom<&Program> for V1ProgramInfo {
    type Error = BpfletError;

    fn try_from(program: &Program) -> Result<Self, Self::Error> {
        let data: &ProgramData = program.get_data();

        let bytecode = match program.location()? {
            Location::Image(m) => {
                Some(BytecodeLocation {
                    location: Some(V1Location::Image(bpflet_api::v1::BytecodeImage {
                        url: m.get_url().to_string(),
                        image_pull_policy: m.get_pull_policy().to_owned() as i32,
                        // Never dump Plaintext Credentials
                        username: Some(String::new()),
                        password: Some(String::new()),
                    })),
                })
            }
            Location::File(m) => Some(BytecodeLocation {
                location: Some(V1Location::File(m.to_string())),
            }),
        };

        let attach_info = AttachInfo {
            info: match program.clone() {
                Program::Xdp(p) => Some(Info::XdpAttachInfo(XdpAttachInfo {
                    priority: p.get_priority()?,
                    iface: p.get_iface()?.to_string(),
                    position: p.get_current_position()?.unwrap_or(0) as i32,
                    proceed_on: p.get_proceed_on()?.as_action_vec(),
                })),
                Program::Tc(p) => Some(Info::TcAttachInfo(TcAttachInfo {
                    priority: p.get_priority()?,
                    iface: p.get_iface()?.to_string(),
                    position: p.get_current_position()?.unwrap_or(0) as i32,
                    direction: p.get_direction()?.to_string(),
                    proceed_on: p.get_proceed_on()?.as_action_vec(),
                })),
                Program::Tracepoint(p) => Some(Info::TracepointAttachInfo(TracepointAttachInfo {
                    tracepoint: p.get_tracepoint()?.to_string(),
                })),
                Program::Kprobe(p) => Some(Info::KprobeAttachInfo(KprobeAttachInfo {
                    fn_name: p.get_fn_name()?.to_string(),
                    offset: p.get_offset()?,
                    retprobe: p.get_retprobe()?,
                    container_pid: p.get_container_pid()?,
                })),
                Program::Uprobe(p) => Some(Info::UprobeAttachInfo(UprobeAttachInfo {
                    fn_name: p.get_fn_name()?.map(|v| v.to_string()),
                    offset: p.get_offset()?,
                    target: p.get_target()?.to_string(),
                    retprobe: p.get_retprobe()?,
                    pid: p.get_pid()?,
                    container_pid: p.get_container_pid()?,
                })),
                Program::Unsupported(_) => None,
            },
        };

        // Populate the Program Info with bpflet data
        Ok(V1ProgramInfo {
            name: data.get_name()?.to_string(),
            bytecode,
            attach: Some(attach_info),
            global_data: data.get_global_data()?,
            map_owner_id: data.get_map_owner_id()?,
            map_pin_path: data
                .get_map_pin_path()?
                .map_or(String::new(), |v| v.to_str().unwrap().to_string()),
            map_used_by: data
                .get_maps_used_by()?
                .iter()
                .map(|m| m.to_string())
                .collect(),
            metadata: data.get_metadata()?,
        })
    }
}

impl TryFrom<&Program> for V1KernelProgramInfo {
    type Error = BpfletError;

    fn try_from(program: &Program) -> Result<Self, Self::Error> {
        // Get the Kernel Info.
        let data: &ProgramData = program.get_data();

        // Populate the Kernel Info.
        Ok(V1KernelProgramInfo {
            id: data.get_id()?,
            name: data.get_kernel_name()?.to_string(),
            program_type: program.kind() as u32,
            loaded_at: data.get_kernel_loaded_at()?.to_string(),
            tag: data.get_kernel_tag()?.to_string(),
            gpl_compatible: data.get_kernel_gpl_compatible()?,
            map_ids: data.get_kernel_map_ids()?,
            btf_id: data.get_kernel_btf_id()?,
            bytes_xlated: data.get_kernel_bytes_xlated()?,
            jited: data.get_kernel_jited()?,
            bytes_jited: data.get_kernel_bytes_jited()?,
            bytes_memlock: data.get_kernel_bytes_memlock()?,
            verified_insns: data.get_kernel_verified_insns()?,
        })
    }
}
