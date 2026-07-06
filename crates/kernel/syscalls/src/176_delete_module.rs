// 176 delete_module — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

const MODULE_NAME_MAX: u64 = 64;

/// `delete_module(name, flags)` slot 176.
/// # C: O(N_modules + MODULE_NAME_MAX)
pub fn sys_delete_module(args: &SyscallArgs) -> i64 {
    if args.a0 == 0 { return errno(Errno::Efault); }
    let name_bytes = match syscall::scan_user_cstr(args.a0, MODULE_NAME_MAX, |va|
        // SAFETY: scan_user_cstr validates va < USER_VA_END before every read.
        unsafe { core::ptr::read_volatile(va as *const u8) }
    ) {
        Ok(v) => v,
        Err(e) => return errno(e),
    };
    let name = match core::str::from_utf8(&name_bytes) {
        Ok(s) => s,
        Err(_) => return errno(Errno::Einval),
    };
    match modules::registry::unload_by_name(name) {
        Ok(()) => 0,
        Err(modules::registry::RegistryError::Busy)  => errno(Errno::Ebusy),
        Err(modules::registry::RegistryError::Noent) => errno(Errno::Enoent),
        Err(_) => errno(Errno::Einval),
    }
}

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }
