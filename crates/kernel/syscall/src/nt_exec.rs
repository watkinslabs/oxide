//! ABI records for a runtime-owned PE execution handoff.

use crate::UserPtr;

/// Maximum number of runtime-supplied DLL records accepted by the native
/// execution handoff. Shared by the builder and kernel validator.
pub const MAX_EXEC_MODULES: usize = 64;

/// One copied module supplied by the NT userspace runtime.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtExecModule {
    pub name: UserPtr<u8>,
    pub name_len: u32,
    pub _padding: u32,
    pub image: UserPtr<u8>,
    pub image_len: u64,
}

/// Root image plus an explicit DLL catalog supplied by the runtime.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtExecRequest {
    pub image: UserPtr<u8>,
    pub image_len: u64,
    pub image_path: UserPtr<u8>,
    pub image_path_len: u32,
    pub _path_padding: u32,
    pub command_line: UserPtr<u8>,
    pub command_line_len: u32,
    pub _command_padding: u32,
    pub environment: UserPtr<u8>,
    pub environment_len: u32,
    pub _environment_padding: u32,
    pub modules: UserPtr<NtExecModule>,
    pub module_count: u32,
    pub _modules_padding: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_records_are_fixed_x86_64_layouts() {
        assert_eq!(core::mem::size_of::<NtExecModule>(), 32);
        assert_eq!(core::mem::align_of::<NtExecModule>(), 8);
        assert_eq!(core::mem::size_of::<NtExecRequest>(), 80);
        assert_eq!(core::mem::align_of::<NtExecRequest>(), 8);
    }
}
