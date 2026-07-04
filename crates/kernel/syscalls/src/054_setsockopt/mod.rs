// Module manifest: `main` owns syscall dispatch + generic socket options;
// `multicast` owns IP multicast parsing/membership; `uapi` owns ABI numbers.
#![cfg(target_os = "oxide-kernel")]

mod main;
mod multicast;
mod uapi;

pub use main::sys_setsockopt;
