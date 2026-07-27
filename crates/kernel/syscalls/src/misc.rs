// Real impls for the previous compat silent-0 tail: kcmp, NUMA
// family, process_madvise / process_mrelease.
//
// Linux behavior in one node:
//   - kcmp(pid1,pid2,type,idx1,idx2): real comparison of resource
//     pointers. Linux non-negative ordering: 0=equal, 1=less,
//     2=greater (a negative return would be read as -errno by libc).
//     v1 compares Task fields directly when both pids exist; ESRCH
//     otherwise; EBADF for a KCMP_FILE fd that is not allocated.
//   - set_mempolicy / get_mempolicy / mbind / migrate_pages /
//     move_pages / set_mempolicy_home_node: validate args; on a
//     single-node UMA system Linux returns success because the
//     "policy applied" outcome is trivially true.
//   - process_madvise(iov, advice): walk the iov, validate each
//     segment is in user range; same advise semantics as madvise.
//   - process_mrelease(pidfd, flags): validate pidfd, return 0.
//
// Sub-dispatcher + the OBSOLETE-number predicate stay here; every
// `pub fn sys_X` handler now lives in its own per-syscall file
// (docs/53 §0). Shared helpers live in `misc_common`.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

#[path = "misc_common.rs"]                  pub mod misc_common;
#[path = "330_pkey_alloc.rs"]               pub mod s330_pkey_alloc;
#[path = "331_pkey_free.rs"]                pub mod s331_pkey_free;
#[path = "329_pkey_mprotect.rs"]            pub mod s329_pkey_mprotect;
#[path = "312_kcmp.rs"]                     pub mod s312_kcmp;
#[path = "238_set_mempolicy.rs"]            pub mod s238_set_mempolicy;
#[path = "239_get_mempolicy.rs"]            pub mod s239_get_mempolicy;
#[path = "237_mbind.rs"]                    pub mod s237_mbind;
#[path = "450_set_mempolicy_home_node.rs"]  pub mod s450_set_mempolicy_home_node;
#[path = "256_migrate_pages.rs"]            pub mod s256_migrate_pages;
#[path = "279_move_pages.rs"]               pub mod s279_move_pages;
#[path = "440_process_madvise.rs"]          pub mod s440_process_madvise;
#[path = "448_process_mrelease.rs"]         pub mod s448_process_mrelease;
#[path = "074_fsync.rs"]                    pub mod s074_fsync;
#[path = "162_sync.rs"]                     pub mod s162_sync;
#[path = "169_reboot.rs"]                   pub mod s169_reboot;

// Routed via `crate::misc::sys_fsync` / `sys_reboot` / `sys_sync` / `sys_syncfs`.
pub use s074_fsync::sys_fsync;
pub use s162_sync::{sys_sync, sys_syncfs};
pub use s169_reboot::sys_reboot;

/// Tail dispatch for the previously-compat tail (pkey, kcmp, NUMA,
/// process_madvise/mrelease).
/// # C: O(1)
pub fn dispatch(nr: u64, args: &SyscallArgs) -> i64 {
    use syscall::nrs::*;
    match nr {
        NR_PKEY_ALLOC                => s330_pkey_alloc::sys_pkey_alloc(args),
        NR_PKEY_FREE                 => s331_pkey_free::sys_pkey_free(args),
        NR_PKEY_MPROTECT             => s329_pkey_mprotect::sys_pkey_mprotect(args),
        NR_KCMP                      => s312_kcmp::sys_kcmp(args),
        NR_SET_MEMPOLICY             => s238_set_mempolicy::sys_set_mempolicy(args),
        NR_GET_MEMPOLICY             => s239_get_mempolicy::sys_get_mempolicy(args),
        NR_MBIND                     => s237_mbind::sys_mbind(args),
        NR_SET_MEMPOLICY_HOME_NODE   => s450_set_mempolicy_home_node::sys_set_mempolicy_home_node(args),
        NR_MIGRATE_PAGES             => s256_migrate_pages::sys_migrate_pages(args),
        NR_MOVE_PAGES                => s279_move_pages::sys_move_pages(args),
        NR_PROCESS_MADVISE           => s440_process_madvise::sys_process_madvise(args),
        NR_PROCESS_MRELEASE          => s448_process_mrelease::sys_process_mrelease(args),
        _                            => -(Errno::Enosys.as_i32() as i64),
    }
}

/// docs/15 §2 OBSOLETE numbers — see `crate::obsolete` for the set and the
/// test that pins it to Linux `syscall_64.tbl`. Re-exported here because the
/// dispatch match calls `misc::is_obsolete`.
pub use crate::obsolete::is_obsolete;
