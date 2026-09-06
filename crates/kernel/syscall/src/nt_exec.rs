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

/// One runtime-supplied native Wine ELF source record.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtExecUnixlib {
    pub name: UserPtr<u8>,
    pub name_len: u32,
    pub path: UserPtr<u8>,
    pub path_len: u32,
    pub image: UserPtr<u8>,
    pub image_len: u64,
}

/// User-space dynamic-loader registration for one already mapped Wine ELF
/// module. The kernel validates the table and publishes only its identity;
/// relocation, TLS, constructors, and loader lifetime stay in user space.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtWineUnixlibRegistration {
    pub name: UserPtr<u8>,
    pub name_len: u32,
    pub _name_padding: u32,
    pub module_base: u64,
    pub module_end: u64,
    pub table: UserPtr<u64>,
    pub entry_count: u32,
    pub _table_padding: u32,
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
    pub unixlibs: UserPtr<NtExecUnixlib>,
    pub unixlib_count: u32,
    pub _unixlibs_padding: u32,
    /// Optional dynamically linked ELF bootstrap entered before the PE image.
    /// Its loader owns native relocation, TLS, constructors, and registration.
    pub bootstrap: UserPtr<u8>,
    pub bootstrap_len: u64,
    /// Registry endpoint the launcher already connected under its own
    /// credentials in its own namespaces. `NO_REGISTRY_ENDPOINT` supplies
    /// none; the kernel never reopens a path on the process's behalf.
    pub registry_socket: i32,
    pub _registry_padding: u32,
}

/// Absent registry endpoint. A launch may legitimately carry no registry.
pub const NO_REGISTRY_ENDPOINT: i32 = -1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_records_are_fixed_x86_64_layouts() {
        assert_eq!(core::mem::size_of::<NtExecModule>(), 32);
        assert_eq!(core::mem::size_of::<NtExecUnixlib>(), 48);
        assert_eq!(core::mem::size_of::<NtWineUnixlibRegistration>(), 48);
        assert_eq!(core::mem::align_of::<NtExecModule>(), 8);
        assert_eq!(core::mem::size_of::<NtExecRequest>(), 120);
        assert_eq!(core::mem::align_of::<NtExecRequest>(), 8);
    }
}
