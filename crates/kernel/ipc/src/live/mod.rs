//! Kernel-side IPC integration. Hooks the kernel sched runtime
//! into the System V IPC + POSIX message-queue + futex syscalls.

#![cfg(target_os = "oxide-kernel")]

pub mod futex;
pub mod posix_mq;
pub mod sysv_msg;
pub mod sysv_sem;
