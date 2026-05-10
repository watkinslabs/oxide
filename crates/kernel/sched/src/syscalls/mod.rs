//! Linux kernel/* syscalls — process lifecycle, credentials, scheduling.
//! These touch only sched + foundational types so they live alongside
//! the scheduler runtime. Per Linux's `kernel/cred.c`, `kernel/sys.c`,
//! `kernel/rseq.c` etc.

pub mod compat;
pub mod cred;
pub mod falloc;
pub mod prctl;
pub mod proclink;
pub mod rseq;
pub mod timers;
pub mod trace;
pub mod xfer;
