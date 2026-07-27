//! Hosted coverage for the semaphore surface.
//!
//! Module manifest:
//!   `common` — serialisation lock, registry reset, credential + namespace
//!              fixtures, and user-buffer helpers.
//!   `get`    — `semget` key/create/permission algebra.
//!   `op`     — `perform_atomic_semop`, batch scanning, the blocking decision
//!              and the `semop` error order.
//!   `undo`   — `semadj` accumulation, bounds, `exit_sem`, `IPC_RMID` invalidation.
//!   `ctl`    — every `semctl` command, including the `semid64_ds` byte layout.
//!   `ns`     — namespace isolation of keys and ids.

mod common;
mod ctl;
mod get;
mod ns;
mod op;
mod undo;
