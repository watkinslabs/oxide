// seccomp per `27` — Linux `kernel/seccomp.c` in Rust.
//
// Module manifest (`08§7`):
//   uapi     — `include/uapi/linux/seccomp.h` numbers + the two internal
//              values `kernel/seccomp.c` adds (`SECCOMP_MODE_DEAD`, the
//              `MAX_ERRNO` cap); AUDIT_ARCH tokens; mode-1 syscall table.
//   flags    — `SECCOMP_FILTER_FLAG_*` + `seccomp_set_mode_filter`'s and
//              `do_seccomp`'s flag ladders.
//   insn     — cBPF opcode numbers, `sock_filter` packing, `seccomp_data`.
//   verifier — `bpf_check_classic` + `check_load_and_stores` +
//              `seccomp_check_filter`.
//   interp   — the cBPF interpreter and `seccomp_run_filters`' chain walk.
//   action   — `__seccomp_filter`'s action switch as a pure `Verdict`, plus
//              action precedence and `__secure_computing_strict`.
//   install  — the install permission ladder and `seccomp_may_assign_mode`.
//   user     — user-memory copies for the install path (EFAULT only).
//   entry    — the running-task glue: `__secure_computing`, `do_seccomp`,
//              `prctl_set_seccomp`, `seccomp_sync_threads`.
//
// The SHIM executes the verdict (`docs/53`): killing a thread or a process
// and raising SIGSYS live in `syscalls::dispatch::seccomp`, because this
// crate cannot reach `do_exit` without a dependency cycle.

pub mod uapi;
pub mod flags;
pub mod insn;
pub mod verifier;
pub mod interp;
pub mod action;
pub mod install;
mod user;
mod entry;

pub use action::{more_restrictive, strict_allows, Sigsys, Verdict};
pub use entry::{check, do_seccomp, mode_of_current, prctl_seccomp_op, prctl_set_seccomp, sys_seccomp};
pub use insn::{SeccompData, SockFilter};
pub use uapi::*;

#[cfg(test)]
mod tests;
