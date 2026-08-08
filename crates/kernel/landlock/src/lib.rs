// Landlock (`docs/27`). Unprivileged, stackable, hierarchy-scoped access
// control. A thread builds a ruleset, enforces it on itself, and thereafter
// every path, port and scoped-IPC operation it performs is filtered by the
// resulting domain — which can only ever get narrower.
//
// Module manifest:
//   uapi     — ABI constants: access rights, scopes, flags, limits, sizes
//   abi      — pure argument admission for slots 444/445/446
//   eval     — per-layer mask algebra: unmasking, reparenting comparisons
//   ruleset  — the mutable object behind a ruleset fd (one layer)
//   domain   — the enforced immutable layer stack and its access checks
//   refer    — link/rename reparenting admission
//   netcheck — socket-address admission for port rules
//   access   — per-operation request masks and the open-time recorded mask
//   walk     — object-to-root hierarchy walk across mount points
//   logging  — per-layer denial-reporting configuration and live state
//   audit    — denial records: what to report, what to suppress, what to say
//
// Nothing here reads task state; the caller supplies the domain. That keeps
// this crate below `sched`, which stores the domain on the task.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod uapi;
pub mod logging;
pub mod audit;
pub mod abi;
pub mod eval;
pub mod ruleset;
pub mod domain;
pub mod refer;
pub mod netcheck;
pub mod access;
pub mod walk;

pub use domain::Domain;
pub use ruleset::{FsRule, NetRule, Ruleset};
pub use logging::{DomainDetails, LogConfig, LogStatus};
pub use uapi::AccessMask;
