#[derive(Clone, Debug)]
pub enum ProgramType {
    Builtin,
    Wasm,
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ProgramState {
    Uninitialized,
    Initialized,
    Running,
    Stopped,
    Failed,
}
