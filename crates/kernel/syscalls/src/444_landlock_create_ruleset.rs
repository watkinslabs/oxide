// 444 landlock_create_ruleset — one syscall, one file (docs/53 §0). Moved verbatim from landlock.rs.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use ::security::landlock::{self as ll};
use vfs::{Dentry, File, InodeRef, OpenFlags};

use crate::landlock::LandlockRulesetInode;

/// `sys_landlock_create_ruleset(attr, size, flags)` — slot 444.
/// `attr` points to `struct landlock_ruleset_attr { __u64 handled_access_fs; }`;
/// `size` is `sizeof(attr)`; `flags` = 0 or LANDLOCK_CREATE_RULESET_VERSION
/// (which asks for the supported ABI version).
/// # C: O(1)
pub fn sys_landlock_create_ruleset(args: &SyscallArgs) -> i64 {
    const LANDLOCK_CREATE_RULESET_VERSION: u64 = 1;
    let attr  = args.a0;
    let size  = args.a1;
    let flags = args.a2;
    if (flags & LANDLOCK_CREATE_RULESET_VERSION) != 0 {
        return 1; // ABI v1.
    }
    if attr == 0 || size < 8 || attr >= hal::USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: attr validated < USER_VA_END; 8-byte read of handled_access_fs from caller's AS.
    let handled = unsafe { core::ptr::read_volatile(attr as *const u64) };
    let id = ll::create_ruleset(handled);
    let inode: InodeRef = Arc::new(LandlockRulesetInode { ruleset_id: id });
    let dentry = Dentry::new(None, alloc::string::String::from("landlock"), inode.clone());
    let file = File::new(inode, dentry, OpenFlags::O_RDONLY);
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64) };
    // SAFETY: running task; preempt-off; sole writer of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    match fdt.alloc(file) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}
