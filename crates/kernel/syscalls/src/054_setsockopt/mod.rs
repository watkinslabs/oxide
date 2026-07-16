// Module manifest: `main` owns syscall dispatch + generic socket options;
// `multicast` owns IP multicast parsing/membership; `raw` owns raw IP options;
// `uapi` owns ABI numbers.
#![cfg(target_os = "oxide-kernel")]

mod main;
mod multicast;
mod packet;
mod packet_abi;
mod raw;
mod uapi;

pub use main::sys_setsockopt;
