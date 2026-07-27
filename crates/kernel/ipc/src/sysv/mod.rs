//! System V IPC shared substrate per `24` — the pieces Linux keeps in
//! `ipc/util.c` and the `<asm/*buf.h>` UAPI, owned once so `sem`, `msg` and
//! `shm` cannot drift apart.
//!
//! Module manifest:
//!   `limits` — `SEMMSL`/`SEMOPM`/`SEMVMX`/`MSGMAX`/`MSGMNB`/… tunables and
//!              the `IPC_*` / `SEM_*` / `MSG_*` cmd + flag numbers.
//!   `ids`    — `struct ipc_ids`: per-namespace cyclic index + sequence
//!              identifier space (`ipc_checkid` stale-id rejection).
//!   `perm`   — `struct kern_ipc_perm` equivalent, `ipcperms()`,
//!              `ipc_update_perm()`, and the caller-credential snapshot.
//!   `uapi`   — `ipc64_perm` / `semid64_ds` / `msqid64_ds` / `seminfo` /
//!              `msginfo` byte layouts (arch-divergent: see `uapi::arch`).
//!   `user`   — bounded user-buffer copy helpers shared by the ctl paths.
//!   `block`  — park/deadline/signal classification for the sleeping ops.
//!   `sem`    — semget/semop/semtimedop/semctl + SEM_UNDO.
//!   `msg`    — msgget/msgsnd/msgrcv/msgctl.

pub mod block;
pub mod ids;
pub mod limits;
pub mod msg;
pub mod perm;
pub mod sem;
pub mod uapi;
pub mod user;
