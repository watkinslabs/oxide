//! Kernel-side IPC + synchronization integration per `52§3`.
//!
//! Submodules wrap kernel-internal sched/preempt primitives to
//! provide System V IPC (msg/sem), POSIX mq, and futex syscalls.
//! The hosted-testable bits live in `crates/kernel/ipc`.

#![cfg(target_os = "oxide-kernel")]

pub mod futex;
pub mod posix_mq;
pub mod sysv_msg;
pub mod sysv_sem;
