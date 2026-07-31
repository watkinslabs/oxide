// Module manifest: `main` owns syscall dispatch and the IP/IPV6/TCP option
// arms; `sol_socket` owns SOL_SOCKET argument import and application;
// `multicast` owns IP multicast parsing/membership; `raw` owns raw IP options;
// `uapi` owns ABI numbers.
#![cfg(target_os = "oxide-kernel")]

mod main;
mod sol_socket;
mod multicast;
mod packet;
mod packet_abi;
mod raw;
mod uapi;
mod vsock;

pub use main::sys_setsockopt;
