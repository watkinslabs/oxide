// Linux `struct sock_reuseport`: the SO_REUSEPORT member set sharing one bind
// key, its optional selection program, and the socket-facing attach/detach
// ladder that `setsockopt` drives.
//
// Module manifest:
// - group: the group object — program slot, member set, closed/conn bookkeeping.
// - prog: the installed program plus the map set it may name a member through.
// - slot: the per-socket / per-endpoint `sk_reuseport_cb` cell and join/leave.
// - attach: which program types `SO_ATTACH_REUSEPORT_EBPF` accepts.
// - api: socket-level `reuseport_attach_prog` / `reuseport_detach_prog` ladders.
// - tests: errno ladders, bind-time join, member departure, program selection.
// - transport_tests: the same join and selection contract on IPv6 UDP and TCP.
// - select_tests: what the delivery path does with a member a program named.

pub mod attach;
pub mod group;
pub mod prog;
pub mod slot;

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
mod api;

pub use attach::{admit_reuseport_prog, ProgFlavour, SockShape};
pub use group::{family_of, select_udp, ReuseportGroup, Select, SelectInput};
pub use prog::GroupProgram;
pub use slot::{ReuseportSlot, new_slot};

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub use api::{alloc_for_unhashed, attach_prog, detach_prog, group_of, is_hashed};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod transport_tests;
#[cfg(test)]
mod select_tests;
