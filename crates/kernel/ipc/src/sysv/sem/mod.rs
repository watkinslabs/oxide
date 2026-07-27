//! System V semaphores per `24` — `semget`/`semop`/`semtimedop`/`semctl` and
//! `SEM_UNDO`, tracking Linux `ipc/sem.c`.
//!
//! Module manifest:
//!   `model` — `struct sem` / `struct sem_array`, the per-namespace registry,
//!             `newary`, `freeary` and namespace teardown.
//!   `get`   — `semget`: `ipcget` key rules and creation bounds.
//!   `op`    — `perform_atomic_semop` and the `semop`/`semtimedop` sleep loop.
//!   `undo`  — per-process `semadj` lists and `exit_sem`.
//!   `ctl`   — `semctl`, one child module per command family.
//!   `tests` — hosted coverage, one file per surface.

pub mod ctl;
pub mod get;
pub mod model;
pub mod op;
pub mod undo;

pub use self::ctl::{semctl_in, sys_semctl};
pub use self::get::{semget_in, sys_semget};
pub use self::op::{semop_in, sys_semop, sys_semtimedop, Sembuf};
pub use self::undo::exit_sem;

pub(crate) use self::model::reap_namespace;

#[cfg(test)]
mod tests;
