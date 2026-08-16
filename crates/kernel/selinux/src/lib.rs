// SELinux mandatory access control (`docs/63`).
//
// A pure decision engine: it reads a binary policy image, resolves security
// contexts to SIDs, and answers "may this subject do this to this object".
// It reads no task state, touches no filesystem and logs nothing itself —
// callers supply the SIDs and act on the verdict. That keeps the whole engine
// hosted-testable, which matters more here than anywhere else in the tree,
// because every defect in it is an access silently granted.
//
// Module manifest:
//   uapi      — ABI constants: classes, permissions, initial SIDs, versions
//   error     — refusal reasons for a malformed policy or unanswerable query
//   reader    — little-endian cursor over a policy image
//   ebitmap   — sparse bit sets: attributes, categories, type sets
//   mls       — sensitivity levels, categories, and the dominance relation
//   context   — user/role/type triples and retained unmapped contexts
//   avtab     — type-enforcement rules and their lookup index
//   policydb  — the loaded policy: symbols, rules, transitions, contexts
//   mapping   — kernel class/permission numbering to policy numbering
//   sidtab    — SID allocation and context lookup
//   avc       — access-vector cache in front of the decision engine
//   services  — decision computation, transitions, context parse and render
//   status    — enforcing state and the reload sequence number
//   server    — the one owner of policy, SID table, cache and enforcement

#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]

extern crate alloc;

pub mod uapi;
pub mod error;
pub mod reader;
pub mod ebitmap;
pub mod mls;
pub mod context;
pub mod avtab;
pub mod policydb;
pub mod mapping;
pub mod sidtab;
pub mod avc;
pub mod services;
pub mod status;
pub mod server;

pub use context::{Context, ValidContext};
pub use error::{Error, Result};
pub use policydb::Policydb;
pub use avc::{Avc, AvDecision, AVD_FLAGS_NEVERAUDIT, AVD_FLAGS_PERMISSIVE};
pub use sidtab::{Sidtab, Sid};
pub use status::{BootConfig, Enforcing, SecurityState};
pub use server::{SecurityServer, Verdict};
