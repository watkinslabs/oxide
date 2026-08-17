// The security-module framework: one place every module is reached from.
//
// Before this crate each module wired its own call sites by hand, which made
// "both modules must agree" a property of each call site remembering to ask
// both rather than a property of the kernel. A check point that consulted one
// module and not another was a silent grant, and nothing was red.
//
// Three things live here and nowhere else: which modules run and in what
// order, which slot of an object each module owns, and what asking every
// module means. Everything in this crate is a value — no target gate, no
// running kernel needed — so all three are checkable hosted. `registry` is
// the single live instance of it.
//
// Module manifest:
//   uapi      — identities, attribute selectors and the context record
//   limits    — how many modules may run
//   module    — what a module tells the framework about itself
//   modules   — the modules this kernel carries, and the built-in order
//   order     — which modules run, and in what order
//   blob      — per-object slot allocation
//   store     — the slots themselves, on one object
//   hooks     — one hook list, and what asking every module means
//   framework — the resolved framework as a value
//   cmdline   — boot-line selection
//   registry  — the one live framework

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod blob;
pub mod cmdline;
pub mod framework;
pub mod hooks;
pub mod limits;
pub mod module;
pub mod modules;
pub mod order;
pub mod registry;
pub mod store;
pub mod uapi;

pub use blob::{BlobGrant, BlobKind, BlobRequest, BlobSizes};
pub use framework::Framework;
pub use hooks::{call_all, call_first_decisive, call_first_decisive_by, HookError, HookList};
pub use limits::MAX_LSM_COUNT;
pub use module::{LsmId, LsmInfo, Order, LSM_FLAG_EXCLUSIVE, LSM_FLAG_LEGACY_MAJOR};
pub use order::{Ordered, Selection, Skipped};
pub use store::{Blob, BlobStore};
