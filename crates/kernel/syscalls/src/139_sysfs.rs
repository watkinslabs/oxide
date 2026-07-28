// 139 sysfs — the SysV filesystem-type query (docs/53 §0). NOT sysfs the
// filesystem: this is `fs/filesystems.c`'s three-option lookup over the
// registered `file_systems` list.
//
//   sysfs(1, const char *name)          -> index of that type, EINVAL if absent
//   sysfs(2, unsigned index, char *buf) -> writes name + NUL, EINVAL past end
//   sysfs(3)                            -> count of registered types
//   anything else                       -> EINVAL
//
// The list walked here is `vfs::fs::registered_filesystems()` — the SAME list
// `/proc/filesystems` renders (`procfs::filesystems`), so the two cannot
// disagree about which types exist or in what order they are indexed.
// Option/index decisions live in `crate::sysfs_query`, which is hosted-tested.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::sysfs_query::{SYSFS_GET_FS_INDEX, SYSFS_GET_FS_MAXINDEX, SYSFS_GET_FS_NAME,
    fs_index, fs_maxindex, fs_name_at, option_known};
use crate::userbuf::validate_user_buf_writable;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Fetch the option-1 name argument with Linux `strndup_user(name, PATH_MAX)`
/// error shape: a faulting pointer is EFAULT, and a string with no NUL inside
/// PATH_MAX is EINVAL (`length > n`), NOT ENAMETOOLONG — the pathname errno
/// belongs to the namei path, not to this query.
/// # C: O(strlen)
fn read_type_name(ptr: u64) -> Result<Vec<u8>, i64> {
    // SAFETY: read_user_cstr itself range-checks `ptr` against USER_VA_END and reads only mapped user bytes of the running task's AS, bounded at PATH_MAX.
    let bytes = match unsafe { devfs::read_user_cstr(ptr, vfs::path::PATH_MAX) } {
        Some(b) => b,
        None    => return Err(err(Errno::Efault)),
    };
    if bytes.len() >= vfs::path::PATH_MAX { return Err(err(Errno::Einval)); }
    Ok(bytes.to_vec())
}

/// `sys_sysfs(option, arg1, arg2)` — slot 139.
/// # C: O(N_fs)
pub fn sys_sysfs(args: &SyscallArgs) -> i64 {
    let option = args.a0 as i32;
    if !option_known(option) { return err(Errno::Einval); }

    // One snapshot of the registry backs whichever option runs, so the index a
    // caller gets from option 1 names the same type option 2 hands back.
    let types = vfs::fs::registered_filesystems();
    let names: Vec<&str> = types.iter().map(|t| t.name()).collect();

    match option {
        SYSFS_GET_FS_INDEX => {
            let raw = match read_type_name(args.a1) { Ok(b) => b, Err(rv) => return rv };
            // Linux `strcmp`s the raw user bytes against `fs->name`. A name that
            // is not valid UTF-8 cannot equal any registered type, so it is the
            // same EINVAL a decoded-but-unmatched name gets.
            let name = match core::str::from_utf8(&raw) { Ok(s) => s, Err(_) => return err(Errno::Einval) };
            match fs_index(&names, name) { Ok(i) => i, Err(e) => err(e) }
        }
        SYSFS_GET_FS_NAME => {
            let name = match fs_name_at(&names, args.a1 as u32) { Ok(n) => n, Err(e) => return err(e) };
            let buf = args.a2;
            let n = name.len() as u64 + 1; // Linux copies strlen(name) + 1
            if let Err(rv) = validate_user_buf_writable(buf, n, 1) { return rv; }
            // SAFETY: `buf` validated writable for name.len()+1 bytes in the caller's AS by validate_user_buf_writable; byte writes need no alignment.
            unsafe {
                for (i, b) in name.as_bytes().iter().enumerate() {
                    core::ptr::write_unaligned((buf + i as u64) as *mut u8, *b);
                }
                core::ptr::write_unaligned((buf + name.len() as u64) as *mut u8, 0u8);
            }
            0
        }
        SYSFS_GET_FS_MAXINDEX => fs_maxindex(&names),
        _ => err(Errno::Einval),
    }
}
