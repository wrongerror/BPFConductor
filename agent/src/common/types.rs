use crate::errors::ParseError;

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

impl TryFrom<u32> for ProgramType {
    type Error = ParseError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ProgramType::Builtin),
            1 => Ok(ProgramType::Wasm),
            _ => Err(ParseError::InvalidProgramType {
                program_type: value,
            }),
        }
    }
}

impl TryFrom<ProgramType> for u32 {
    type Error = ParseError;

    fn try_from(value: ProgramType) -> Result<Self, Self::Error> {
        match value {
            ProgramType::Builtin => Ok(0),
            ProgramType::Wasm => Ok(1),
        }
    }
}

impl TryFrom<u32> for ProgramState {
    type Error = ParseError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ProgramState::Uninitialized),
            1 => Ok(ProgramState::Initialized),
            2 => Ok(ProgramState::Running),
            3 => Ok(ProgramState::Stopped),
            4 => Ok(ProgramState::Failed),
            _ => Err(ParseError::InvalidProgramState {
                program_state: value,
            }),
        }
    }
}

impl TryFrom<ProgramState> for u32 {
    type Error = ParseError;

    fn try_from(value: ProgramState) -> Result<Self, Self::Error> {
        match value {
            ProgramState::Uninitialized => Ok(0),
            ProgramState::Initialized => Ok(1),
            ProgramState::Running => Ok(2),
            ProgramState::Stopped => Ok(3),
            ProgramState::Failed => Ok(4),
        }
    }
}
