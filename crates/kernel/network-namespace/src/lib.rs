// Module manifest:
// - owner: immutable namespace identity and lifetime object.
// - registry: init pin, monotonic allocation, weak lookup, dead-ID harvest.
// - callback: install-once lockless final-drop notification.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod callback;
mod owner;
mod registry;

pub use callback::{install_final_drop_callback, FinalDropCallback, InstallError};
pub use owner::{NamespaceIdentity, NetworkNamespace, NetworkNamespaceId};
pub use registry::{allocate, initial, live_snapshot, lookup, take_dead_namespace_ids, AllocError};

pub type NetworkNamespaceRef = alloc::sync::Arc<NetworkNamespace>;

#[cfg(test)]
mod tests;
