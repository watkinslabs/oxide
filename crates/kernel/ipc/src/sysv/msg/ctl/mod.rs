//! `msgctl` (`ipc/msg.c` `ksys_msgctl`).
//!
//! Module manifest:
//!   `entry` — `msqid`/`cmd` validation and the command dispatch.
//!   `info`  — `IPC_INFO` / `MSG_INFO`: `struct msginfo`.
//!   `stat`  — `IPC_STAT` / `MSG_STAT` / `MSG_STAT_ANY`: `struct msqid64_ds`.
//!   `down`  — `IPC_SET` / `IPC_RMID`: Linux `msgctl_down`, the owner-gated
//!             commands that mutate or destroy the queue.

pub mod down;
pub mod entry;
pub mod info;
pub mod stat;

pub use entry::{msgctl, sys_msgctl};
