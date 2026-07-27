// Real POSIX credentials syscalls per `13§5` and docs/14 cred-ABI, tracking
// Linux `kernel/sys.c` (set*id family), `kernel/groups.c` (get/setgroups),
// `kernel/cred.c` (`commit_creds`) and `security/commoncap.c` (the
// capability juggles) statement for statement.
//
// Module manifest:
// - limits:   `(uid_t)-1` sentinel, `uid_valid`, `int` argument narrowing.
// - capfix:   `security_task_fix_setuid` — `cap_emulate_setxuid` (set*uid
//             family) and the disjoint `LSM_SETID_FS` fs-cap drop/raise.
// - commit:   `commit_creds` dumpability + `pdeath_signal` side effects and
//             the canonical `fs.suid_dumpable` cell.
// - uid:      getuid/geteuid/setuid/setreuid/setresuid.
// - gid:      getgid/getegid/setgid/setregid/setresgid.
// - resid:    getresuid/getresgid user writeback.
// - fsid:     setfsuid/setfsgid (never fail; return the previous id).
// - groups:   getgroups/setgroups + `may_setgroups` policy.
// - snapshot: the one `current_cred()` -> `vfs::Cred` construction site.
// - dispatch: cred slot table for `syscall_glue.rs`.
// - caps:     capget/capset.
// - tests:    hosted coverage of every transition, errno, and error order.

mod caps;
mod capfix;
mod commit;
mod dispatch;
mod fsid;
mod gid;
mod groups;
mod limits;
mod resid;
mod snapshot;
mod uid;
#[cfg(test)] mod tests;

pub use commit::{set_suid_dumpable, suid_dumpable};
pub use dispatch::cred_dispatch;
pub use fsid::{sys_setfsgid, sys_setfsuid};
pub use gid::{sys_getegid, sys_getgid, sys_setgid, sys_setregid, sys_setresgid};
pub use groups::{sys_getgroups, sys_setgroups};
pub use resid::{sys_getresgid, sys_getresuid};
pub use snapshot::{current_vfs_cred, current_vfs_file_cred};
pub use uid::{sys_geteuid, sys_getuid, sys_setresuid, sys_setreuid, sys_setuid};
