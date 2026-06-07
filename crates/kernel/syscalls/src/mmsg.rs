// `sendmmsg` / `recvmmsg` now live in their own per-syscall modules
// (`53§0`): `s307_sendmmsg.rs`, `s299_recvmmsg.rs`. Callers reach
// them via `crate::net::sys_{send,recv}mmsg` re-exports.
#![cfg(target_os = "oxide-kernel")]
