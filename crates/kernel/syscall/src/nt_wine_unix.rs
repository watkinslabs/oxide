//! Ordered Wine Unix-call ABI slots shared by the native dispatcher and userspace.

use crate::UserPtr;

/// x86-64 layout of Wine's `load_so_dll_params` request.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WineLoadSoDllParams {
    pub nt_name: WineUnicodeString,
    pub module: UserPtr<u64>,
}

/// x86-64 layout of Wine's builtin-unwind request. The pointed-to dispatcher
/// and context retain their native Wine layouts and are validated by the
/// owner that implements the unwind operation.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WineUnwindBuiltinDllParams {
    pub unwind_type: u32,
    pub padding: u32,
    pub dispatch: UserPtr<u8>,
    pub context: UserPtr<u8>,
}

/// Windows `UNICODE_STRING` embedded in a Wine Unix-call request.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WineUnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub padding: u32,
    pub buffer: UserPtr<u16>,
}

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

/// Number of entries in Wine's native NTDLL Unix-call table.
pub const WINE_UNIX_FUNCTION_COUNT: usize = 8;

/// Private memory-query class used by a userspace ELF loader to publish one
/// already initialized Unixlib table for the native Wine loader.
pub const MEMORY_WINE_REGISTER_UNIXLIB: u32 = 1005;

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
    use super::{WineLoadSoDllParams, WineUnicodeString, WineUnixFunction, WineUnwindBuiltinDllParams};

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

    #[test]
    fn load_so_dll_request_preserves_x64_nested_pointer_shape() {
        assert_eq!(core::mem::size_of::<WineUnicodeString>(), 16);
        assert_eq!(core::mem::size_of::<WineLoadSoDllParams>(), 24);
        assert_eq!(core::mem::offset_of!(WineLoadSoDllParams, nt_name), 0);
        assert_eq!(core::mem::offset_of!(WineLoadSoDllParams, module), 16);
    }

    #[test]
    fn builtin_unwind_request_preserves_x64_pointer_alignment() {
        assert_eq!(core::mem::size_of::<WineUnwindBuiltinDllParams>(), 24);
        assert_eq!(core::mem::offset_of!(WineUnwindBuiltinDllParams, unwind_type), 0);
        assert_eq!(core::mem::offset_of!(WineUnwindBuiltinDllParams, dispatch), 8);
        assert_eq!(core::mem::offset_of!(WineUnwindBuiltinDllParams, context), 16);
    }
}
