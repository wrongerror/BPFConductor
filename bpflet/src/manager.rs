use std::{
    collections::HashMap,
    convert::TryInto,
    path::{Path, PathBuf},
};

use aya::{
    programs::{
        kprobe::KProbeLink, links::FdLink, loaded_programs, trace_point::TracePointLink,
        uprobe::UProbeLink, KProbe, TracePoint, UProbe,
    },
    BpfLoader,
};
use bpflet_api::{
    config::Config,
    util::directories::*,
    ProbeType::{self, *},
    ProgramType,
};
use log::{debug, info, warn};
use sled::Db;
use tokio::{
    fs::{create_dir_all, read_dir, remove_dir_all},
    select,
    sync::{
        mpsc::{Receiver, Sender},
        oneshot,
    },
};

use crate::{
    command::{
        BpfMap, Command, Direction,
        Program, PullBytecodeArgs, UnloadArgs,
    },
    errors::BpfletError,
    oci::image_manager::Command as ImageManagerCommand,
    serve::shutdown_handler,
    utils::{get_ifindex, set_dir_permissions, should_map_be_pinned},
};

const MAPS_MODE: u32 = 0o0660;

pub(crate) struct BpfManager {
    config: Config,
    programs: ProgramMap,
    maps: HashMap<u32, BpfMap>,
    commands: Receiver<Command>,
    image_manager: Sender<ImageManagerCommand>,
    _database: Db,
}

pub(crate) struct ProgramMap {
    programs: HashMap<u32, Program>,
}

impl ProgramMap {
    fn new() -> Self {
        ProgramMap {
            programs: HashMap::new(),
        }
    }

    fn insert(&mut self, id: u32, prog: Program) -> Option<Program> {
        self.programs.insert(id, prog)
    }

    fn remove(&mut self, id: &u32) -> Option<Program> {
        self.programs.remove(id)
    }

    fn get_mut(&mut self, id: &u32) -> Option<&mut Program> {
        self.programs.get_mut(id)
    }

    fn get(&self, id: &u32) -> Option<&Program> {
        self.programs.get(id)
    }

    fn programs_mut<'a>(
        &'a mut self,
        program_type: &'a ProgramType,
        if_index: &'a Option<u32>,
        direction: &'a Option<Direction>,
    ) -> impl Iterator<Item = &'a mut Program> {
        self.programs.values_mut().filter(|p| {
            p.kind() == *program_type && p.if_index() == *if_index && p.direction() == *direction
        })
    }

    // Sets the positions of programs that are to be attached via a dispatcher.
    // Positions are set based on order of priority. Ties are broken based on:
    // - Already attached programs are preferred
    // - Program name. Lowest lexical order wins.
    fn set_program_positions(&mut self, program: &mut Program, is_add: bool) {
        let program_type = program.kind();
        let if_index = program.if_index();
        let direction = program.direction();

        let mut extensions = self
            .programs
            .values_mut()
            .filter(|p| {
                p.kind() == program_type && p.if_index() == if_index && p.direction() == direction
            })
            .collect::<Vec<&mut Program>>();

        if is_add {
            // add program we're loading
            extensions.push(program);
        }

        extensions.sort_by_key(|b| {
            (
                b.priority(),
                b.attached().unwrap(),
                b.data()
                    .expect("All Bpflet programs should have ProgramData")
                    .name()
                    .to_owned(),
            )
        });
        for (i, v) in extensions.iter_mut().enumerate() {
            v.set_position(Some(i));
        }
    }

    fn get_programs_iter(&self) -> impl Iterator<Item = (u32, &Program)> {
        self.programs.values().map(|p| {
            let kernel_info = p
                .data()
                .expect("All Bpflet programs should have ProgramData")
                .kernel_info()
                .expect("Loaded Bpflet programs should have kernel information");

            (kernel_info.id, p)
        })
    }
}


impl BpfManager {
    pub(crate) fn new(
        config: Config,
        commands: Receiver<Command>,
        image_manager: Sender<ImageManagerCommand>,
        database: Db,
    ) -> Self {
        Self {
            config,
            programs: ProgramMap::new(),
            maps: HashMap::new(),
            commands,
            image_manager,
            _database: database,
        }
    }

    pub(crate) async fn rebuild_state(&mut self) -> Result<(), anyhow::Error> {
        debug!("BpfManager::rebuild_state()");
        let mut programs_dir = read_dir(RTDIR_PROGRAMS).await?;
        while let Some(entry) = programs_dir.next_entry().await? {
            let id = entry.file_name().to_string_lossy().parse().unwrap();
            let mut program = Program::load(id)
                .map_err(|e| BpfletError::Error(format!("cant read program state {e}")))?;
            // TODO: Should probably check for pinned prog on bpffs rather than assuming they are attached
            program.set_attached();
            debug!("rebuilding state for program {}", id);
            self.rebuild_map_entry(id, &mut program).await;
            self.programs.insert(id, program);
        }

        Ok(())
    }

    pub(crate) async fn add_program(
        &mut self,
        mut program: Program,
    ) -> Result<Program, BpfletError> {
        let map_owner_id = program.data()?.map_owner_id();
        // Set map_pin_path if we're using another program's maps
        if let Some(map_owner_id) = map_owner_id {
            let map_pin_path = self.is_map_owner_id_valid(map_owner_id)?;
            program
                .data_mut()?
                .set_map_pin_path(Some(map_pin_path.clone()));
        }

        program
            .data_mut()?
            .set_program_bytes(self.image_manager.clone())
            .await?;

        let result = match program {
            Program::Xdp(_) | Program::Tc(_) => {
                program.set_if_index(get_ifindex(&program.if_name().unwrap())?);

                // self.add_multi_attach_program(&mut program).await
                self.add_single_attach_program(&mut program).await
            }
            Program::Tracepoint(_) | Program::Kprobe(_) | Program::Uprobe(_) => {
                self.add_single_attach_program(&mut program).await
            }
            Program::Unsupported(_) => panic!("Cannot add unsupported program"),
        };

        // Program bytes MUST be cleared after load.
        program.data_mut()?.clear_program_bytes();

        match result {
            Ok(id) => {
                info!(
                    "Added {} program with name: {} and id: {id}",
                    program.kind(),
                    program.data()?.name()
                );

                // Now that program is successfully loaded, update the id, maps hash table,
                // and allow access to all maps by Bpflet group members.
                self.save_map(&mut program, id, map_owner_id).await?;

                // Only add program to bpfManager if we've completed all mutations and it's successfully loaded.
                self.programs.insert(id, program.to_owned());

                Ok(program)
            }
            Err(e) => {
                // Cleanup any directories associated with the map_pin_path.
                // Data and map_pin_path may or may not exist depending on where the original
                // error occured, so don't error if not there and preserve original error.
                if let Ok(data) = program.data() {
                    if let Some(pin_path) = data.map_pin_path() {
                        let _ = self.cleanup_map_pin_path(pin_path, map_owner_id).await;
                    }
                }
                Err(e)
            }
        }
    }

    pub(crate) async fn add_single_attach_program(
        &mut self,
        p: &mut Program,
    ) -> Result<u32, BpfletError> {
        debug!("BpfManager::add_single_attach_program()");
        let name = p.data()?.name();
        let mut bpf = BpfLoader::new();

        for (key, value) in p.data()?.global_data() {
            bpf.set_global(key, value.as_slice(), true);
        }

        // If map_pin_path is set already it means we need to use a pin
        // path which should already exist on the system.
        if let Some(map_pin_path) = p.data()?.map_pin_path() {
            debug!(
                "single-attach program {name} is using maps from {:?}",
                map_pin_path
            );
            bpf.map_pin_path(map_pin_path);
        }

        let mut loader = bpf
            .allow_unsupported_maps()
            .load(p.data()?.program_bytes())?;

        let raw_program = loader
            .program_mut(name)
            .ok_or(BpfletError::BpfFunctionNameNotValid(name.to_owned()))?;

        let res = match p {
            Program::Tracepoint(ref mut program) => {
                let parts: Vec<&str> = program.tracepoint.split('/').collect();
                if parts.len() != 2 {
                    return Err(BpfletError::InvalidAttach(program.tracepoint.to_string()));
                }
                let category = parts[0].to_owned();
                let name = parts[1].to_owned();

                let tracepoint: &mut TracePoint = raw_program.try_into()?;

                tracepoint.load()?;
                program
                    .data
                    .set_kernel_info(Some(tracepoint.info()?.try_into()?));

                let link_id = tracepoint.attach(&category, &name)?;

                let owned_link: TracePointLink = tracepoint.take_link(link_id)?;
                let fd_link: FdLink = owned_link
                    .try_into()
                    .expect("unable to get owned tracepoint attach link");

                let id = program.data.id().expect("id should be set after load");

                fd_link
                    .pin(format!("{RTDIR_FS}/prog_{}_link", id))
                    .map_err(BpfletError::UnableToPinLink)?;

                tracepoint
                    .pin(format!("{RTDIR_FS}/prog_{id}"))
                    .map_err(BpfletError::UnableToPinProgram)?;

                Ok(id)
            }
            Program::Kprobe(ref mut program) => {
                let requested_probe_type = match program.retprobe {
                    true => Kretprobe,
                    false => Kprobe,
                };

                if requested_probe_type == Kretprobe && program.offset != 0 {
                    return Err(BpfletError::Error(format!(
                        "offset not allowed for {Kretprobe}"
                    )));
                }

                let kprobe: &mut KProbe = raw_program.try_into()?;
                kprobe.load()?;

                // verify that the program loaded was the same type as the
                // user requested
                let loaded_probe_type = ProbeType::from(kprobe.kind());
                if requested_probe_type != loaded_probe_type {
                    return Err(BpfletError::Error(format!(
                        "expected {requested_probe_type}, loaded program is {loaded_probe_type}"
                    )));
                }

                program
                    .data
                    .set_kernel_info(Some(kprobe.info()?.try_into()?));

                let link_id = kprobe.attach(program.fn_name.as_str(), program.offset)?;

                let owned_link: KProbeLink = kprobe.take_link(link_id)?;
                let fd_link: FdLink = owned_link
                    .try_into()
                    .expect("unable to get owned kprobe attach link");

                let id = program.data.id().expect("id should be set after load");

                fd_link
                    .pin(format!("{RTDIR_FS}/prog_{}_link", id))
                    .map_err(BpfletError::UnableToPinLink)?;

                kprobe
                    .pin(format!("{RTDIR_FS}/prog_{id}"))
                    .map_err(BpfletError::UnableToPinProgram)?;

                Ok(id)
            }
            Program::Uprobe(ref mut program) => {
                let requested_probe_type = match program.retprobe {
                    true => Uretprobe,
                    false => Uprobe,
                };

                let uprobe: &mut UProbe = raw_program.try_into()?;
                uprobe.load()?;

                // verify that the program loaded was the same type as the
                // user requested
                let loaded_probe_type = ProbeType::from(uprobe.kind());
                if requested_probe_type != loaded_probe_type {
                    return Err(BpfletError::Error(format!(
                        "expected {requested_probe_type}, loaded program is {loaded_probe_type}"
                    )));
                }

                program
                    .data
                    .set_kernel_info(Some(uprobe.info()?.try_into()?));

                let id = program.data.id().expect("id should be set after load");

                let program_pin_path = format!("{RTDIR_FS}/prog_{id}");

                uprobe
                    .pin(program_pin_path.clone())
                    .map_err(BpfletError::UnableToPinProgram)?;

                match program.container_pid {
                    None => {
                        // Attach uprobe in same container as the Bpflet process
                        let link_id = uprobe.attach(
                            program.fn_name.as_deref(),
                            program.offset,
                            program.target.clone(),
                            None,
                        )?;

                        let owned_link: UProbeLink = uprobe.take_link(link_id)?;
                        let fd_link: FdLink = owned_link
                            .try_into()
                            .expect("unable to get owned uprobe attach link");

                        fd_link
                            .pin(format!("{RTDIR_FS}/prog_{}_link", id))
                            .map_err(BpfletError::UnableToPinLink)?;
                    }
                    Some(p) => {
                        // Attach uprobe in different container from the Bpflet process
                        let offset = program.offset.to_string();
                        let container_pid = p.to_string();
                        let mut prog_args = vec![
                            "uprobe".to_string(),
                            "--program-pin-path".to_string(),
                            program_pin_path,
                            "--offset".to_string(),
                            offset,
                            "--target".to_string(),
                            program.target.clone(),
                            "--container-pid".to_string(),
                            container_pid,
                        ];

                        if let Some(fn_name) = &program.fn_name {
                            prog_args.extend(["--fn-name".to_string(), fn_name.to_string()])
                        }

                        if program.retprobe {
                            prog_args.push("--retprobe".to_string());
                        }

                        if let Some(pid) = program.pid {
                            prog_args.extend(["--pid".to_string(), pid.to_string()])
                        }

                        let status = std::process::Command::new("./target/debug/Bpflet-ns")
                            .args(prog_args)
                            .status()
                            .expect("Bpflet-ns call failed to return status");

                        debug!("Bpflet-ns status: {:?}", status);

                        if !status.success() {
                            return Err(BpfletError::ContainerAttachError {
                                program_type: "uprobe".to_string(),
                                container_pid: program.container_pid.unwrap(),
                            });
                        }
                    }
                };

                Ok(id)
            }
            _ => panic!("not a supported single attach program"),
        };

        match res {
            Ok(id) => {
                // If this program is the map(s) owner pin all maps (except for .rodata and .bss) by name.
                if p.data()?.map_pin_path().is_none() {
                    let map_pin_path = calc_map_pin_path(id);
                    p.data_mut()?.set_map_pin_path(Some(map_pin_path.clone()));
                    create_map_pin_path(&map_pin_path).await?;

                    for (name, map) in loader.maps_mut() {
                        if !should_map_be_pinned(name) {
                            continue;
                        }
                        debug!(
                            "Pinning map: {name} to path: {}",
                            map_pin_path.join(name).display()
                        );
                        map.pin(map_pin_path.join(name))
                            .map_err(BpfletError::UnableToPinMap)?;
                    }
                }

                p.save(id)
                    // we might want to log or ignore this error instead of returning here...
                    // because otherwise it will hide the original error (from res above)
                    .map_err(|_| {
                        BpfletError::Error("unable to persist program data".to_string())
                    })?;
            }
            Err(_) => {
                // If kernel ID was never set there's no pins to cleanup here so just continue
                if let Some(info) = p.kernel_info() {
                    p.delete(info.id)
                        .map_err(BpfletError::BpfletProgramDeleteError)?;
                };
            }
        };

        res
    }

    pub(crate) async fn remove_program(&mut self, id: u32) -> Result<(), BpfletError> {
        info!("Removing program with id: {id}");
        let prog = match self.programs.remove(&id) {
            Some(p) => p,
            None => {
                return Err(BpfletError::Error(format!(
                    "Program {0} does not exist or was not created by Bpflet",
                    id,
                )));
            }
        };

        let map_owner_id = prog.data()?.map_owner_id();

        prog.delete(id)
            .map_err(BpfletError::BpfletProgramDeleteError)?;

        match prog {
            // Program::Xdp(_) | Program::Tc(_) => self.remove_multi_attach_program(&mut prog).await?,
            Program::Xdp(_) | Program::Tc(_) => (),
            Program::Tracepoint(_)
            | Program::Kprobe(_)
            | Program::Uprobe(_)
            | Program::Unsupported(_) => (),
        }

        self.delete_map(id, map_owner_id).await?;
        Ok(())
    }

    pub(crate) fn list_programs(&mut self) -> Result<Vec<Program>, BpfletError> {
        debug!("BpfManager::list_programs()");

        // Get an iterator for the Bpflet load programs, a hash map indexed by program id.
        let mut bpflet_progs: HashMap<u32, &Program> = self.programs.get_programs_iter().collect();

        // Call Aya to get ALL the loaded eBPF programs, and loop through each one.
        loaded_programs()
            .map(|p| {
                let prog = p.map_err(BpfletError::BpfProgramError)?;
                let prog_id = prog.id();

                // If the program was loaded by Bpflet (check the hash map), then us it.
                // Otherwise, convert the data returned from Aya into an Unsupported Program Object.
                match bpflet_progs.remove(&prog_id) {
                    Some(p) => Ok(p.to_owned()),
                    None => Ok(Program::Unsupported(prog.try_into()?)),
                }
            })
            .collect()
    }

    pub(crate) fn get_program(&mut self, id: u32) -> Result<Program, BpfletError> {
        debug!("Getting program with id: {id}");
        // If the program was loaded by Bpflet, then use it.
        // Otherwise, call Aya to get ALL the loaded eBPF programs, and convert the data
        // returned from Aya into an Unsupported Program Object.
        match self.programs.get(&id) {
            Some(p) => Ok(p.to_owned()),
            None => loaded_programs()
                .find_map(|p| {
                    let prog = p.ok()?;
                    if prog.id() == id {
                        Some(Program::Unsupported(prog.try_into().ok()?))
                    } else {
                        None
                    }
                })
                .ok_or(BpfletError::Error(format!(
                    "Program {0} does not exist",
                    id
                ))),
        }
    }

    async fn pull_bytecode(&self, args: PullBytecodeArgs) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.image_manager
            .send(ImageManagerCommand::Pull {
                image: args.image.image_url,
                pull_policy: args.image.image_pull_policy.clone(),
                username: args.image.username.clone(),
                password: args.image.password.clone(),
                resp: tx,
            })
            .await?;
        let res = match rx.await? {
            Ok(_) => {
                info!("Successfully pulled bytecode");
                Ok(())
            }
            Err(e) => Err(BpfletError::BpfBytecodeError(e)),
        };
        let _ = args.responder.send(res);
        Ok(())
    }

    pub(crate) async fn run(&mut self) {
        loop {
            // Start receiving messages
            select! {
                biased;
                _ = shutdown_handler() => {
                    info!("Signal received to stop command processing");
                    self._database.flush().expect("Unable to flush database to disk before shutting down BpfManager");
                    break;
                }
                Some(cmd) = self.commands.recv() => {
                    match cmd {
                        Command::Load( args) => {
                            let prog = self.add_program(args.program).await;
                            // Ignore errors as they'll be propagated to caller in the RPC status
                            let _ = args.responder.send(prog);
                        },
                        Command::Unload(args) => self.unload_command(args).await.unwrap(),
                        Command::List { responder } => {
                            let progs = self.list_programs();
                            // Ignore errors as they'll be propagated to caller in the RPC status
                            let _ = responder.send(progs);
                        }
                        Command::Get(args) => {
                            let prog = self.get_program(args.id);
                            // Ignore errors as they'll be propagated to caller in the RPC status
                            let _ = args.responder.send(prog);
                        },
                        Command::PullBytecode (args) => self.pull_bytecode(args).await.unwrap(),
                    }
                }
            }
        }
        info!("Stopping processing commands");
    }

    async fn unload_command(&mut self, args: UnloadArgs) -> anyhow::Result<()> {
        let res = self.remove_program(args.id).await;
        // Ignore errors as they'll be propagated to caller in the RPC status
        let _ = args.responder.send(res);
        Ok(())
    }

    // This function checks to see if the user provided map_owner_id is valid.
    fn is_map_owner_id_valid(&mut self, map_owner_id: u32) -> Result<PathBuf, BpfletError> {
        let map_pin_path = calc_map_pin_path(map_owner_id);

        if self.maps.contains_key(&map_owner_id) {
            // Return the map_pin_path
            return Ok(map_pin_path);
        }
        Err(BpfletError::Error(
            "map_owner_id does not exists".to_string(),
        ))
    }

    // This function is called if the program's map directory was created,
    // but the eBPF program failed to load. save_map() has not been called,
    // so self.maps has not been updated for this program.
    // If the user provided a ID of program to share a map with,
    // then map the directory is still in use and there is nothing to do.
    // Otherwise, the map directory was created so it must
    // deleted.
    async fn cleanup_map_pin_path(
        &mut self,
        map_pin_path: &Path,
        map_owner_id: Option<u32>,
    ) -> Result<(), BpfletError> {
        if map_owner_id.is_none() {
            let _ = remove_dir_all(map_pin_path)
                .await
                .map_err(|e| BpfletError::Error(format!("can't delete map dir: {e}")));
            Ok(())
        } else {
            Ok(())
        }
    }

    // This function writes the map to the map hash table. If this eBPF
    // program is the map owner, then a new entry is add to the map hash
    // table and permissions on the directory are updated to grant Bpflet
    // user group access to all the maps in the directory. If this eBPF
    // program is not the owner, then the eBPF program ID is added to
    // the Used-By array.

    // TODO this should probably be program.save_map not bpfmanager.save_map
    async fn save_map(
        &mut self,
        program: &mut Program,
        id: u32,
        map_owner_id: Option<u32>,
    ) -> Result<(), BpfletError> {
        let data = program.data_mut()?;

        match map_owner_id {
            Some(m) => {
                if let Some(map) = self.maps.get_mut(&m) {
                    map.used_by.push(id);

                    // This program has no been inserted yet, so set map_used_by to
                    // newly updated list.
                    data.set_maps_used_by(Some(map.used_by.clone()));

                    // Update all the programs using the same map with the updated map_used_by.
                    for used_by_id in map.used_by.iter() {
                        if let Some(program) = self.programs.get_mut(used_by_id) {
                            if let Ok(data) = program.data_mut() {
                                data.set_maps_used_by(Some(map.used_by.clone()));
                            } else {
                                return Err(BpfletError::Error(
                                    "unable to retrieve data for {id}".to_string(),
                                ));
                            }
                        }
                    }
                } else {
                    return Err(BpfletError::Error(
                        "map_owner_id does not exists".to_string(),
                    ));
                }
            }
            None => {
                let map = BpfMap { used_by: vec![id] };

                self.maps.insert(id, map);

                // Update this program with the updated map_used_by
                data.set_maps_used_by(Some(vec![id]));

                // Set the permissions on the map_pin_path directory.
                if let Some(map_pin_path) = data.map_pin_path() {
                    if let Some(path) = map_pin_path.to_str() {
                        debug!("bpf set dir permissions for {}", path);
                        set_dir_permissions(path, MAPS_MODE).await;
                    } else {
                        return Err(BpfletError::Error(format!(
                            "invalid map_pin_path {} for {}",
                            map_pin_path.display(),
                            id
                        )));
                    }
                } else {
                    return Err(BpfletError::Error(format!(
                        "map_pin_path should be set for {}",
                        id
                    )));
                }
            }
        }

        Ok(())
    }

    // This function cleans up a map entry when an eBPF program is
    // being unloaded. If the eBPF program is the map owner, then
    // the map is removed from the hash table and the associated
    // directory is removed. If this eBPF program is referencing a
    // map from another eBPF program, then this eBPF programs ID
    // is removed from the UsedBy array.
    async fn delete_map(&mut self, id: u32, map_owner_id: Option<u32>) -> Result<(), BpfletError> {
        let index = map_owner_id.unwrap_or_else(|| id);

        if let Some(map) = self.maps.get_mut(&index.clone()) {
            if let Some(index) = map.used_by.iter().position(|value| *value == id) {
                map.used_by.swap_remove(index);
            }

            if map.used_by.is_empty() {
                // No more programs using this map, so remove the entry from the map list.
                let path = calc_map_pin_path(index);
                self.maps.remove(&index.clone());
                remove_dir_all(path)
                    .await
                    .map_err(|e| BpfletError::Error(format!("can't delete map dir: {e}")))?;
            } else {
                // Update all the programs still using the same map with the updated map_used_by.
                for id in map.used_by.iter() {
                    if let Some(program) = self.programs.get_mut(id) {
                        if let Ok(data) = program.data_mut() {
                            data.set_maps_used_by(Some(map.used_by.clone()));
                        }
                    }
                }
            }
        } else {
            return Err(BpfletError::Error(
                "map_pin_path does not exists".to_string(),
            ));
        }

        Ok(())
    }

    async fn rebuild_map_entry(&mut self, id: u32, program: &mut Program) {
        let map_owner_id = match program.data() {
            Ok(data) => data.map_owner_id(),
            Err(_) => {
                warn!("unable to retrieve data for {id} retrieving map_owner_id on rebuild");
                return;
            }
        };
        let index = map_owner_id.unwrap_or_else(|| id);

        if let Some(map) = self.maps.get_mut(&index) {
            map.used_by.push(id);

            // This program has not been inserted yet, so update it with the
            // updated map_used_by.
            if let Ok(data) = program.data_mut() {
                data.set_maps_used_by(Some(map.used_by.clone()));
            } else {
                warn!("unable to retrieve data for {id} during rebuild of maps");
            }

            // Update all the other programs using the same map with the updated map_used_by.
            for used_by_id in map.used_by.iter() {
                // program may not exist yet on rebuild, so ignore if not there
                if let Some(prog) = self.programs.get_mut(used_by_id) {
                    if let Ok(data) = prog.data_mut() {
                        data.set_maps_used_by(Some(map.used_by.clone()));
                    } else {
                        warn!("unable to retrieve data for {used_by_id} when setting map_used_by on rebuild");
                    }
                }
            }
        } else {
            let map = BpfMap { used_by: vec![id] };
            self.maps.insert(index, map);

            if let Ok(data) = program.data_mut() {
                data.set_maps_used_by(Some(vec![id]));
            } else {
                warn!("unable to retrieve data for {id} during rebuild of maps");
            }
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
