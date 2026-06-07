// Filesystem-shaped syscalls per docs/15§5 + docs/16.
//
// Per-syscall handlers moved to one-file-per-syscall modules
// (docs/53 §0): see NNN_<name>.rs. This file now holds only the
// cross-module re-exports the dispatcher still imports via `crate::fs::*`.

#![cfg(target_os = "oxide-kernel")]

pub use crate::ioctl::sys_ioctl;

pub use crate::newfstatat::sys_newfstatat;

// access(2)/faccessat(2) live in `fs_access.rs` (08§7 cap); dispatcher
// routes NR_ACCESS/NR_FACCESSAT[2] → crate::fs_access::*.

// proc-link helpers (exe/cwd/root/fd/ns) live in syscall_glue_proclink.rs (F112).

/// `sys_poll(fds, nfds, timeout)` — slot 7. v1 non-blocking:
/// reports POLLIN|POLLOUT for CharDev fds (always ready in v1
/// since ConsoleInode reads block at the syscall layer instead
/// of returning EAGAIN); 0 (timeout/no events) for everything
/// else. Returns the number of fds with non-zero revents.
///
/// `pollfd { fd: i32, events: i16, revents: i16 }` = 8 bytes
/// each on Linux x86_64.
pub use crate::poll::{sys_poll, sys_ppoll};

// `sys_fallocate` lives in `syscall_glue_falloc.rs` (F69).
