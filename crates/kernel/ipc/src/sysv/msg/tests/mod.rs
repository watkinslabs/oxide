//! Hosted coverage for `sysv::msg`.
//!
//! Module manifest:
//!   `support` — namespace / credential / `struct msgbuf` fixtures.
//!   `get`     — `msgget` key, create and permission rules.
//!   `select`  — `convert_mode` / `find_msg` selection rules in isolation.
//!   `send`    — `msgsnd` validation, permissions and the queue-full rule.
//!   `recv`    — `msgrcv` selection, `E2BIG`, `MSG_NOERROR`, `MSG_COPY`.
//!   `ctl`     — every `msgctl` command and its byte layout.
//!   `ns`      — namespace isolation of keys and identifiers.

mod ctl;
mod get;
mod ns;
mod recv;
mod select;
mod send;
mod support;
