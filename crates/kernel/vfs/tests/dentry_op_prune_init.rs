//! dcache d_op completeness: the `d_init` + `d_prune` hooks (Linux
//! `dentry_operations::d_init` / `d_prune`). `d_init` fires once when a dentry is
//! allocated (Linux `__d_alloc` after `d_set_d_op`) so the fs can stamp its
//! per-dentry private state; `d_prune` fires when a dentry is about to be killed
//! out of the cache (Linux `__dentry_kill`, before the unhash) so the fs can drop
//! cache-side bookkeeping. The `D_OP_PRUNE` presence bit lets `dentry_kill` skip
//! the `d_op` deref for the common no-prune fs.
//!
//! Single-test (no intra-binary parallelism) so the binary-global hook counters
//! are deterministic.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use vfs::dentry::{Dentry, DentryOps, D_OP_PRUNE};
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

struct Dir { ino: u64 }
impl Inode for Dir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn dir(ino: u64) -> InodeRef { Arc::new(Dir { ino }) }

static INIT_COUNT:  AtomicUsize = AtomicUsize::new(0);
static PRUNE_COUNT: AtomicUsize = AtomicUsize::new(0);

// d_init stamps a sentinel into d_fsdata to prove it actually ran on the dentry.
const FSDATA_SENTINEL: u64 = 0xA11C_0DE5;
fn on_init(d: &Dentry)  { INIT_COUNT.fetch_add(1, Ordering::SeqCst); d.set_d_fsdata(FSDATA_SENTINEL); }
fn on_prune(_d: &Dentry) { PRUNE_COUNT.fetch_add(1, Ordering::SeqCst); }

static OPS: DentryOps = DentryOps {
    d_init: Some(on_init), d_prune: Some(on_prune),
    d_hash: None, d_compare: None, d_revalidate: None, d_delete: None, d_release: None, d_iput: None, d_dname: None,
};

#[test]
fn d_init_at_alloc_and_d_prune_at_kill() {
    // set_d_op rebuilds the root WITH ops -> d_init fires once; the presence bit
    // is stamped from the non-NULL hooks.
    let root = Dentry::new_root(dir(1)).set_d_op(&OPS);
    assert_eq!(INIT_COUNT.load(Ordering::SeqCst), 1, "d_init fires once at root alloc");
    assert_eq!(root.d_fsdata(), FSDATA_SENTINEL, "d_init stamped d_fsdata");
    assert!(root.d_has_op_prune(), "D_OP_PRUNE presence bit set from non-NULL d_prune");
    assert_ne!(root.flags() & D_OP_PRUNE, 0, "D_OP_PRUNE in d_flags");

    // A child inherits parent.d_op (Linux s_d_op at d_alloc) -> d_init fires
    // again, stamping the child's own d_fsdata.
    let child = vfs::dcache::d_alloc(&root, "k"); // negative, UNHASHED, inherits OPS
    assert_eq!(INIT_COUNT.load(Ordering::SeqCst), 2, "d_init fires per allocated dentry");
    assert_eq!(child.d_fsdata(), FSDATA_SENTINEL, "d_init ran on the inherited child");
    assert!(child.d_has_op_prune());

    // Final dput of an UNHASHED dentry routes through dentry_kill (Linux
    // __dentry_kill) -> d_prune fires before the unhash.
    assert_eq!(PRUNE_COUNT.load(Ordering::SeqCst), 0, "no prune yet");
    let g = vfs::dget(&child);    // d_count 0 -> 1
    vfs::dput(g);                 // 1 -> 0, unhashed -> dentry_kill -> d_prune
    assert_eq!(PRUNE_COUNT.load(Ordering::SeqCst), 1, "d_prune fires on the kill route");

    // The shrinker eviction route also funnels through dentry_kill: a hashed
    // negative dropped to the LRU then reclaimed fires d_prune too.
    let neg = vfs::d_add_negative(&root, "n"); // hashed, inherits OPS, d_count 0
    let g2 = vfs::dget(&neg);  // sets D_REFERENCED
    vfs::dput(g2);             // -> LRU (referenced)
    vfs::dcache::shrink_dcache(100); // first pass clears referenced (rotate), frees 0
    vfs::dcache::shrink_dcache(100); // second pass reclaims -> dentry_kill -> d_prune
    assert!(PRUNE_COUNT.load(Ordering::SeqCst) >= 2, "d_prune fires on the shrinker route");
}

// A default-ops dentry never fires the hooks and carries no presence bit — zero
// regression for the common all-None case.
#[test]
fn default_ops_no_prune_bit() {
    let plain = Dentry::new_root(dir(2));
    assert!(!plain.d_has_op_prune(), "no d_op ⇒ no D_OP_PRUNE bit");
    assert_eq!(plain.flags() & D_OP_PRUNE, 0);
}
