// Linux USER namespace uid_map/gid_map/setgroups state keyed by canonical
// namespace identity (`docs/26§2` invariant 6, `docs/26§3.6`, `docs/52§5.6`).
//
// Module manifest:
// - uapi: `UID_GID_MAP_MAX_EXTENTS`, overflow uid/gid, initial identity extent.
// - extent: one map line + Linux `mappings_overlap`-equivalent batch validation.
// - translate: ns-id<->host-id translation over a validated extent slice.
// - engine: the canonical per-namespace map/setgroups state + write rules.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod engine;
mod extent;
mod translate;
mod uapi;

pub use engine::{setgroups_policy, snapshot_map, write_map, write_setgroups, IdMapKind,
    SetgroupsPolicy, UserNsError};
pub use extent::{validate_extents, ExtentError, IdMapExtent};
pub use translate::{to_host, to_ns, OverflowId};
pub use uapi::{OVERFLOW_GID, OVERFLOW_UID, UID_GID_MAP_MAX_EXTENTS};

#[cfg(test)]
mod tests;
