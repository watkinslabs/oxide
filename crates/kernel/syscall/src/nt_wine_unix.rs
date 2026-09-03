//! Ordered Wine Unix-call ABI slots shared by the native dispatcher and userspace.

/// Function table published through `__wine_unixlib_handle`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum WineUnixFunction {
    LoadSoDll = 0,
    UnwindBuiltinDll = 1,
    WineDbgWrite = 2,
    WineServerCall = 3,
    WineServerFdToHandle = 4,
    WineServerHandleToFd = 5,
    WineSpawnVp = 6,
    SystemTimePrecise = 7,
}

impl WineUnixFunction {
    /// Decode a table slot without allowing a widened or unknown selector.
    pub const fn decode(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::LoadSoDll),
            1 => Some(Self::UnwindBuiltinDll),
            2 => Some(Self::WineDbgWrite),
            3 => Some(Self::WineServerCall),
            4 => Some(Self::WineServerFdToHandle),
            5 => Some(Self::WineServerHandleToFd),
            6 => Some(Self::WineSpawnVp),
            7 => Some(Self::SystemTimePrecise),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WineUnixFunction;

    #[test]
    fn decodes_the_complete_ordered_table() {
        let expected = [
            WineUnixFunction::LoadSoDll,
            WineUnixFunction::UnwindBuiltinDll,
            WineUnixFunction::WineDbgWrite,
            WineUnixFunction::WineServerCall,
            WineUnixFunction::WineServerFdToHandle,
            WineUnixFunction::WineServerHandleToFd,
            WineUnixFunction::WineSpawnVp,
            WineUnixFunction::SystemTimePrecise,
        ];
        for (slot, function) in expected.into_iter().enumerate() {
            assert_eq!(WineUnixFunction::decode(slot as u64), Some(function));
        }
    }

    #[test]
    fn rejects_unknown_and_widened_slots() {
        assert_eq!(WineUnixFunction::decode(8), None);
        assert_eq!(WineUnixFunction::decode(u64::MAX), None);
    }
}
