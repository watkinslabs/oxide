// execve module — split per docs/53§0 into per-syscall files:
//   * sys_execve   (NR_EXECVE=59)   → s059_execve
//   * sys_execveat (NR_EXECVEAT=322) → s322_execveat
//   * shared helpers                 → execve_common
// This module re-exports the handlers so `crate::execve::sys_execve`
// / `crate::execve::sys_execveat` (the dispatch.rs call sites) keep
// resolving without touching dispatch.rs.

#![cfg(target_os = "oxide-kernel")]

pub use crate::s059_execve::sys_execve;
pub use crate::s322_execveat::sys_execveat;
