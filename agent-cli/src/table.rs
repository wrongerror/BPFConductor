use anyhow::bail;
use comfy_table::{Cell, Color, Table};

use agent_api::ProgramType::Builtin;
use agent_api::{
    v1::{bytecode_location::Location, list_response::ListResult, ProgramInfo},
    ImagePullPolicy, ProgramType,
};

pub(crate) struct ProgTable(Table);

impl ProgTable {
    pub(crate) fn new_program(r: &Option<ProgramInfo>) -> Result<Self, anyhow::Error> {
        let mut table = Table::new();

        table.load_preset(comfy_table::presets::NOTHING);
        table.set_header(vec![Cell::new("eBPFConductor State")
            .add_attribute(comfy_table::Attribute::Bold)
            .add_attribute(comfy_table::Attribute::Underlined)
            .fg(Color::Green)]);

        if r.is_none() {
            table.add_row(vec!["NONE"]);
            return Ok(ProgTable(table));
        }
        let info = r.clone().unwrap();

        if info.name.clone().is_empty() {
            table.add_row(vec!["Name:", "None"]);
        } else {
            table.add_row(vec!["Name:", &info.name.clone()]);
        }

        match info.program_type.try_into()? {
            Builtin => {
                table.add_row(vec!["Type:", "Builtin"]);
            }
            ProgramType::Wasm => {
                table.add_row(vec!["Type:", "Wasm"]);
                if info.bytecode.is_none() {
                    table.add_row(vec!["NONE"]);
                    return Ok(ProgTable(table));
                }

                match info.bytecode.clone().unwrap().location.clone() {
                    Some(l) => match l {
                        Location::Image(i) => {
                            table.add_row(vec!["Image URL:", &i.url]);
                            table.add_row(vec!["Pull Policy:", &format!{ "{}", TryInto::<ImagePullPolicy>::try_into(i.image_pull_policy)?}]);
                        }
                        Location::File(p) => {
                            table.add_row(vec!["Path:", &p]);
                        }
                    },
                    None => {
                        table.add_row(vec!["NONE"]);
                        return Ok(ProgTable(table));
                    }
                }
            }
        }

        if info.ebpf_maps.is_empty() {
            table.add_row(vec!["Maps:", "None"]);
        } else {
            let mut first = true;
            for (map_name, prog_id) in info.ebpf_maps.clone() {
                let data = &format! {"map_name={map_name}, prog_id={prog_id}"};
                if first {
                    first = false;
                    table.add_row(vec!["eBPF Maps:", data]);
                } else {
                    table.add_row(vec!["", data]);
                }
            }
        }

        if info.metadata.is_empty() {
            table.add_row(vec!["Metadata:", "None"]);
        } else {
            let mut first = true;
            for (key, value) in info.metadata.clone() {
                let data = &format! {"{key}={value}"};
                if first {
                    first = false;
                    table.add_row(vec!["Metadata:", data]);
                } else {
                    table.add_row(vec!["", data]);
                }
            }
        }

        Ok(ProgTable(table))
    }

    pub(crate) fn new_list() -> Self {
        let mut table = Table::new();

        table.load_preset(comfy_table::presets::NOTHING);
        table.set_header(vec!["Program Name", "Type", "State"]);
        ProgTable(table)
    }

    pub(crate) fn add_row_list(&mut self, name: String, type_: String, state: String) {
        self.0.add_row(vec![name, type_, state]);
    }

    pub(crate) fn add_response_prog(&mut self, r: ListResult) -> anyhow::Result<()> {
        if r.info.is_none() {
            self.0.add_row(vec!["NONE"]);
            return Ok(());
        }

        let info = r.info.unwrap();

        self.add_row_list(
            info.name.clone(),
            info.program_type.to_string(),
            info.state.to_string(),
        );

        Ok(())
    }

    pub(crate) fn print(&self) {
        println!("{self}\n")
    }
}

impl std::fmt::Display for ProgTable {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
