// Inode metadata writeback + the `lazytime` deferral (`16§2`).
//
// Module manifest:
//   policy — pure state/clock arithmetic: which dirty bit a timestamp earns,
//            the `__mark_inode_dirty` transition, the expiry predicate
//   dirty  — applying those rules to a live inode: `__mark_inode_dirty`,
//            `sync_lazytime`, the timestamp-stamping entry point
//   flush  — the pass: `__writeback_single_inode`, the per-sb sweep, the
//            whole-system dirtytime expiry sweep
//
// Nothing here is target-gated: the whole ladder runs under hosted `cargo test`.

pub mod policy;
pub mod dirty;
pub mod flush;

pub use policy::{dirtytime_expired, forces_lazytime, harvest_dirty, is_eager_timestamp,
    mark_dirty_transition, needs_write_inode, time_dirty_flag, DirtyTransition,
    DIRTYTIME_EXPIRE_SECS, NSEC_PER_SEC};
pub use dirty::{inode_update_time, mark_inode_dirty, mark_inode_dirty_on, sync_lazytime_on};
pub use flush::dirtytime_expire_pass;
