// 176 delete_module — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use modules::admission::{DELETE_MODULE_FORCE, MODULE_NAME_LEN};

/// `delete_module(name, flags)` slot 176.
///
/// Linux `SYSCALL_DEFINE2(delete_module)` open-codes `may_init_module()`'s pair
/// of tests — `!capable(CAP_SYS_MODULE) || modules_disabled` → EPERM — before
/// touching `name_user`. That test was absent until F757, so any unprivileged
/// process could unload a kernel module.
///
/// The name is copied with `strncpy_from_user(name, name_user,
/// MODULE_NAME_LEN)`; both an EMPTY name and one that fills the buffer (i.e.
/// was truncated) are ENOENT, since neither can match a registered module.
/// # C: O(N_modules + MODULE_NAME_LEN)
pub fn sys_delete_module(args: &SyscallArgs) -> i64 {
    if let Err(rv) = crate::module_admit::may_init_module() { return rv; }
    if args.a0 == 0 { return errno(Errno::Efault); }
    let name_bytes = match syscall::scan_user_cstr(args.a0, MODULE_NAME_LEN as u64, |va|
        // SAFETY: scan_user_cstr validates va < USER_VA_END before every read.
        unsafe { core::ptr::read_volatile(va as *const u8) }
    ) {
        Ok(v) => v,
        Err(e) => return errno(e),
    };
    // Linux: `len == 0 || len == MODULE_NAME_LEN` → ENOENT.
    if name_bytes.is_empty() || name_bytes.len() >= MODULE_NAME_LEN {
        return errno(Errno::Enoent);
    }
    let name = match core::str::from_utf8(&name_bytes) {
        Ok(s) => s,
        // A non-UTF-8 name cannot match a registered module. Linux's byte
        // compare simply misses, which is ENOENT — not EINVAL, which would
        // claim the ARGUMENT was malformed.
        Err(_) => return errno(Errno::Enoent),
    };
    let force = (args.a1 & DELETE_MODULE_FORCE) != 0;
    match modules::registry::unload_by_name_flags(name, force) {
        Ok(()) => 0,
        Err(modules::registry::RegistryError::Busy)  => errno(Errno::Ebusy),
        Err(modules::registry::RegistryError::Noent) => errno(Errno::Enoent),
        Err(_) => errno(Errno::Einval),
    }
}

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }
