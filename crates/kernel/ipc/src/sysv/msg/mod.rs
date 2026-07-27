//! System V message queues (`ipc/msg.c`): `msgget` / `msgsnd` / `msgrcv` /
//! `msgctl`.
//!
//! Module manifest:
//!   `model`  — `struct msg_queue`, the per-namespace registry, `freeque`,
//!              namespace teardown, and the identifier lookups.
//!   `select` — `convert_mode` / `testmsg` / `find_msg`: the pure `msgtyp`
//!              selection rules.
//!   `get`    — `msgget` and the `ipcget` key / create rules.
//!   `send`   — `msgsnd`, including `msg_fits_inqueue` blocking.
//!   `recv`   — `msgrcv`, including `MSG_NOERROR` / `MSG_EXCEPT` / `MSG_COPY`.
//!   `ctl`    — `msgctl`: `IPC_STAT` / `MSG_STAT*` / `*_INFO` / `IPC_SET` /
//!              `IPC_RMID`.
//!   `tests`  — hosted coverage, split by surface.

pub mod ctl;
pub mod get;
pub mod model;
pub mod recv;
pub mod select;
pub mod send;

#[cfg(test)]
mod tests;

pub use ctl::sys_msgctl;
pub use get::sys_msgget;
pub use model::reap_namespace;
pub use recv::sys_msgrcv;
pub use send::sys_msgsnd;
