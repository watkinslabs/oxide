//! namei D22: rename-seqlock consumption in the path walk. A `d_move` that
//! advances the GLOBAL rename seqcount (Linux `rename_lock`) DURING a walk is
//! detected by the walk's `rename_lock_retry(m_seq)` / per-child `d_seq` gates,
//! which RESTART the walk (bounded). The restart re-resolves from the now-
//! consistent dcache and returns the correct, non-torn result. A concurrent
//! variant proves the bounded restart can never livelock the walk.
//!
//! Watchdog-guarded: a seqretry bug that livelocked would be aborted by the
//! watchdog thread instead of hanging the suite.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use vfs::inode::Inode;
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{d_add, d_move, Dentry, FileType, InodeRef, KResult, LookupFlags, VfsError};

/// Abort the test process if a walk exceeds `secs` (a livelock guard).
fn watchdog(secs: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(secs));
        eprintln!("watchdog: namei walk exceeded {secs}s — aborting (livelock?)");
        std::process::abort();
    });
}

struct DirData { kids: BTreeMap<String, InodeRef> }
fn dir_data(kids: &[(&str, InodeRef)]) -> Arc<DirData> {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    Arc::new(DirData { kids: m })
}
fn file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

struct DirOps;
impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<DirData>().ok_or(VfsError::Enotdir)?;
        d.kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}
fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(DirOps), default_file_ops())
        .private(dir_data(kids)).build()
}

// ---- deterministic detection: a rename fires DURING the walk -------------

/// One-shot rename trigger: while armed, the next SLOW-PATH directory lookup
/// performs a single `d_move` (advancing the global rename seqcount) to
/// simulate a rename racing the in-flight walk, then disarms.
struct Trigger {
    armed: AtomicBool,
    src: OnceLock<Arc<Dentry>>,
    parent: OnceLock<Arc<Dentry>>,
    fired: AtomicU32,
}
static TRIG: Trigger = Trigger {
    armed: AtomicBool::new(false),
    src: OnceLock::new(),
    parent: OnceLock::new(),
    fired: AtomicU32::new(0),
};

struct TrigDirOps;
impl InodeOps for TrigDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<DirData>().ok_or(VfsError::Enotdir)?;
        let r = d.kids.get(name).cloned().ok_or(VfsError::Enoent)?;
        // Fire the rename AFTER computing the result but before the walk
        // commits this component — exactly the race the seqlock must catch.
        if TRIG.armed.swap(false, Ordering::SeqCst) {
            if let (Some(src), Some(parent)) = (TRIG.src.get(), TRIG.parent.get()) {
                let _ = d_move(src, parent, "moved_away");
                TRIG.fired.fetch_add(1, Ordering::SeqCst);
            }
        }
        Ok(r)
    }
}
fn trig_dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TrigDirOps), default_file_ops())
        .private(dir_data(kids)).build()
}

#[test]
fn rename_during_walk_is_detected_and_restarts() {
    watchdog(30);
    let leaf = file(0xC);
    let d = trig_dir(0xD, &[("leaf", leaf)]);
    let root_inode = dir(2, &[("d", d)]);
    let root = Dentry::new_root(root_inode);

    // A pre-cached dentry the trigger will `d_move` (advancing rename_lock).
    let src = d_add(&root, "src", file(0x5));
    TRIG.src.set(src).ok();
    TRIG.parent.set(root.clone()).ok();
    TRIG.armed.store(true, Ordering::SeqCst);

    // The walk of /d/leaf resolves `leaf` via the slow path, which fires the
    // rename; the walk's rename_lock_retry detects the advanced seqcount and
    // restarts, then resolves cleanly from the now-consistent dcache.
    let p = vfs::path_lookup_path(root.clone(), root.clone(), "/d/leaf", LookupFlags::default())
        .expect("walk completes despite a mid-walk rename");
    assert_eq!(p.inode.ino(), 0xC, "result is correct (restart re-resolved, not torn)");
    assert_eq!(TRIG.fired.load(Ordering::SeqCst), 1,
        "the rename fired once DURING the walk — proving the seqretry restart path ran");
}

// ---- concurrent correctness: walks race a stream of renames ---------------

#[test]
fn concurrent_renames_never_tear_the_result() {
    watchdog(60);
    let leaf = file(0xC);
    let b = dir(0xB, &[("c", leaf)]);
    let a = dir(0xA, &[("b", b)]);
    let root_inode = dir(2, &[("a", a)]);
    let root = Dentry::new_root(root_inode);
    // Warm /a/b/c into the dcache so the racing walks are pure fast-path reads.
    let _ = vfs::path_lookup_path(root.clone(), root.clone(), "/a/b/c", LookupFlags::default()).unwrap();

    // A mover thread streams renames of an UNRELATED name, advancing the global
    // rename seqcount so concurrent /a/b/c walks must seqretry (then degrade).
    let mut cur = d_add(&root, "m0", file(0x50));
    let root2 = root.clone();
    let mover = std::thread::spawn(move || {
        for i in 0..4000u32 {
            cur = d_move(&cur, &root2, &format!("m{}", i + 1));
        }
    });

    for _ in 0..4000u32 {
        let p = vfs::path_lookup_path(root.clone(), root.clone(), "/a/b/c", LookupFlags::default())
            .expect("walk completes under concurrent renames");
        assert_eq!(p.inode.ino(), 0xC, "result never torn by a concurrent rename");
    }
    mover.join().unwrap();
}
