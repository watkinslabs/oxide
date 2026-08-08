// Kernel audit subsystem (`docs/27`). A record is produced by a kernel
// decision that a security policy wants a durable account of, queued, and
// delivered to the single registered userspace consumer over NETLINK_AUDIT.
//
// Module manifest:
//   uapi       — NETLINK_AUDIT ABI numbers: message types, status masks,
//                feature bits, failure modes, defaults
//   fmt        — record-text primitives (decimal, hex, untrusted strings)
//   record     — a record, its serial, and the `audit(secs.ms:serial)` stamp
//   ratelimit  — the per-second emission ceiling and the lost-warning throttle
//   queue      — the deliverable and hold backlogs, and their admission
//   config     — configuration values and the ladder guarding changes to them
//   consumer   — which process receives records, and the registration ladder
//   admission  — which capability each NETLINK_AUDIT message type requires
//   wire       — `struct audit_status` / `struct audit_features` encoding
//   control    — NETLINK_AUDIT request handling and its effect on the system
//   emit       — the one path a record takes into a queue
//   state      — the single live instance, under one lock
//   clock      — the time source, compiler-gated at the module boundary
//   producers  — record bodies for kernel producers outside this crate
//
// Nothing here reads a task, a socket, or a filesystem: the netlink layer
// gathers the caller's facts and the producers supply theirs, so every
// decision in this crate runs under the hosted test suite.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod uapi;
pub mod fmt;
pub mod record;
pub mod ratelimit;
pub mod queue;
pub mod config;
pub mod consumer;
pub mod admission;
pub mod wire;
pub mod control;
pub mod emit;
pub mod state;
pub mod clock;
pub mod producers;

pub use admission::Caller;
pub use control::{handle, Reply, Request};
pub use emit::{log, log_if_enabled, Admitted, Refusal};
pub use producers::{log_fanotify, log_seccomp, FanotifyInfo, SeccompEvent};
pub use record::Record;
