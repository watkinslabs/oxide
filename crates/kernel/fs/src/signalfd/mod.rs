//! signalfd(2) — a file descriptor that drains this thread's (and its
//! process's) pending signals as fixed 128-byte `signalfd_siginfo` records.
//!
//! Module manifest:
//!   `uapi`     — record size, field offsets, `SFD_*` flags.
//!   `siginfo`  — ungated: `(signo, si_code)` → union arm, and the encoder.
//!   `file`     — inode, readiness, dequeue loop, blocking read, fdinfo.
//!   `wait`     — kernel-only parking for a blocking read.
//!   `syscalls` — `signalfd` / `signalfd4` entry points and error ordering.

pub mod uapi;
pub mod siginfo;
pub mod file;
pub mod syscalls;
#[cfg(target_os = "oxide-kernel")]
mod wait;

pub use file::{SignalfdData, make_signalfd_inode};
pub use syscalls::{sys_signalfd, sys_signalfd4};
pub use uapi::SIGINFO_SIZE;
