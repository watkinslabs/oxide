// Module manifest: `main` owns syscall dispatch, the SO_BINDTODEVICE and
// filter-attach paths, and the multicast preflight; `sol_socket` owns
// SOL_SOCKET argument import and application; `ip`/`ipv6`/`tcp`/`udp` own one
// option level each; `multicast` owns IP multicast parsing/membership; `raw`
// owns raw IP options; `optval` owns shared operand import; `uapi` owns ABI
// numbers.
#![cfg(target_os = "oxide-kernel")]

mod main;
mod sol_socket;
mod ip;
mod ipv6;
mod tcp;
mod udp;
mod multicast;
mod optval;
mod packet;
mod packet_abi;
mod raw;
mod uapi;
mod vsock;

pub use main::sys_setsockopt;
