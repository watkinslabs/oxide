//! `semctl(2)` — Linux `ksys_semctl` and the four bodies it fans out to
//! (`ipc/sem.c`).
//!
//! Module manifest:
//!   `dispatch` — `ksys_semctl` command fan-out and the `NR_SEMCTL` shim.
//!   `stat`     — `semctl_stat` (`IPC_STAT`/`SEM_STAT`/`SEM_STAT_ANY`) and
//!                `semctl_info` (`IPC_INFO`/`SEM_INFO`).
//!   `values`   — `semctl_main` (`GETALL`/`SETALL`/`GETVAL`/`GETPID`/
//!                `GETNCNT`/`GETZCNT`) and `semctl_setval`.
//!   `down`     — `semctl_down` (`IPC_SET`/`IPC_RMID`), the owner-gated pair.

mod dispatch;
mod down;
mod stat;
mod values;

pub use self::dispatch::{semctl_in, sys_semctl};
pub use self::down::{semctl_rmid, semctl_set};
pub use self::stat::{semctl_info, semctl_stat};
pub use self::values::{semctl_main, semctl_setval};
