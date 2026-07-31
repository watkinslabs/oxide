// Module manifest — libaio (206/207/208/209/210/333) decision logic, split out
// of the kernel-gated slots so `cargo test` actually compiles and runs it.
//
//   uapi      — wire constants: iocb, io_event, aio_ring, opcodes, flags
//   layout    — repr(C) mirrors + const assertions binding those constants to
//               a real layout on EVERY target the crate is built for
//   geometry  — io_setup sizing: nr_events rounding, fs.aio-max-nr admission
//   iocb      — iocb decode + the submit validation ladder, in order
//   events    — reap argument rules, timeout decode, interrupted returns
//   ring      — completion-ring index arithmetic and untrusted-index folding
//   poll      — IOCB_CMD_POLL wake arithmetic (keyed vs keyless wakeups)
//
// No user-memory access, no locks, no task state: everything here is a pure
// function over decoded values.

pub mod uapi;
pub mod layout;
pub mod geometry;
pub mod iocb;
pub mod events;
pub mod ring;
pub mod poll;

#[cfg(test)]
#[path = "tests/layout.rs"]
mod layout_tests;
#[cfg(test)]
#[path = "tests/geometry.rs"]
mod geometry_tests;
#[cfg(test)]
#[path = "tests/iocb.rs"]
mod iocb_tests;
#[cfg(test)]
#[path = "tests/events.rs"]
mod events_tests;
#[cfg(test)]
#[path = "tests/ring.rs"]
mod ring_tests;
#[cfg(test)]
#[path = "tests/poll.rs"]
mod poll_tests;
