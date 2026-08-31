//! A file created between a lookup's backend miss and its negative-cache
//! insert must still be found.
//!
//! The create path flushes the leaf's negative entry, but the flush and the
//! resolver's insert are not ordered: a create landing in that window runs
//! its flush FIRST, the resolver then publishes the stale negative, and the
//! new file is masked until something evicts it. Measured live as a bus-
//! socket lookup answering ENOENT 25ms after bind(2) created it, which left
//! the resolver's bus reconnect waiting forever -- the last cause of the
//! boot's unreliable DNS.
//!
//! The backend below IS that interleaving, deterministically: its first
//! lookup of the leaf misses (and the "create" completes at that instant, its
//! flush finding nothing to remove), every later lookup finds the file. The
//! walk must answer Found, and the poisoned negative must not remain hashed.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use vfs::{Dentry, FileType, Inode, InodeRef, KResult, LookupFlags, VfsError};

static SERIAL: Mutex<()> = Mutex::new(());

static LEAF_LOOKUPS: AtomicU32 = AtomicU32::new(0);

struct RacingDirOps;
impl vfs::InodeOps for RacingDirOps {
    // The gate admits ext4/tmpfs/ramfs by superblock; this synthetic root has
    // none, so it opts in the way /run's tmpfs is admitted in the live case.
    fn negative_dentry_ok(&self, _inode: &Inode, _name: &str) -> bool { true }
    fn lookup(&self, _inode: &Inode, n: &str) -> KResult<InodeRef> {
        if n != "system_bus_socket" { return Err(VfsError::Enoent); }
        // First backend consultation: the miss the resolver saw before the
        // create. Everything after it: the created file.
        if LEAF_LOOKUPS.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(VfsError::Enoent);
        }
        Ok(vfs::InodeBuilder::new(0x51F0, vfs::mk_mode(FileType::Socket, 0o666),
            vfs::default_inode_ops(), vfs::default_file_ops()).build())
    }
}

fn root() -> Arc<Dentry> {
    Dentry::new_root(vfs::InodeBuilder::new(0x51F1, vfs::mk_mode(FileType::Directory, 0o755),
        Arc::new(RacingDirOps), vfs::default_file_ops()).build())
}

#[test]
fn a_create_racing_the_negative_insert_is_still_found() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    LEAF_LOOKUPS.store(0, Ordering::SeqCst);
    let r = root();
    let found = vfs::path_lookup(r.clone(), r.clone(), "/system_bus_socket", LookupFlags::default());
    assert!(found.is_ok(),
        "the walk must find a file whose creation raced the negative insert");
    assert!(LEAF_LOOKUPS.load(Ordering::SeqCst) >= 2,
        "the recheck must consult the backend again after publishing the negative");
    // And nothing stale may remain: the next walk answers from a POSITIVE entry.
    let again = vfs::path_lookup(r.clone(), r.clone(), "/system_bus_socket", LookupFlags::default());
    assert!(again.is_ok(), "no stale negative may mask the file afterwards");
}
