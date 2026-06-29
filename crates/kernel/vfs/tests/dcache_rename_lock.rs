//! dcache-D20: the GLOBAL rename seqlock (Linux `rename_lock`). `d_move`
//! brackets its rehome under a single process-wide seqcount (in addition to the
//! per-dentry `d_seq`), so a lock-free WHOLE-PATH walker detects ANY concurrent
//! rename — not just one on the single renamed component — and retries the walk.

use std::sync::Arc;

use vfs::dcache::{rename_lock_read_begin, rename_lock_retry};
use vfs::{d_add, d_lookup, d_move, Dentry, FileType, InodeRef};

fn dir(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755), vfs::default_inode_ops(), vfs::default_file_ops()).build()
}

#[test]
fn read_begin_returns_even_quiescent_snapshot() {
    // read_seqbegin spins until the seqcount is EVEN (no d_move in flight).
    let s = rename_lock_read_begin();
    assert_eq!(s & 1, 0, "read_seqbegin must return an even/quiescent value");
}

#[test]
fn d_move_advances_global_rename_seqcount() {
    let r = Dentry::new_root(dir(1));
    let dst = d_add(&r, "dst", dir(20));
    d_add(&r, "old", dir(21));

    // A whole-path walker snapshots the global rename seqcount before reading
    // the path's components.
    let before = rename_lock_read_begin();

    // A d_move rehomes a name under the global rename_lock.
    let old = d_lookup(&r, "old").expect("old present");
    let moved = d_move(&old, &dst, "new");
    assert!(d_lookup(&r, "old").is_none());
    assert!(Arc::ptr_eq(&d_lookup(&dst, "new").unwrap(), &moved));

    // The walker's pre-move snapshot is now stale: rename_lock_retry must report
    // the race so the walk restarts. (Robust under parallel tests: the seqcount
    // only ever advances, so != before holds regardless of other movers.)
    assert!(rename_lock_retry(before), "d_move must invalidate the in-flight path walk");
}
