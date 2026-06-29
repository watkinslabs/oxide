//! namei D22 bounded-degrade valve. The rename-seqretry restart is BOUNDED
//! (`MAX_WALK_RESTARTS`): under relentless concurrent renames a walk that keeps
//! losing the seqretry race exhausts its restart budget and then PROCEEDS with
//! the Arc-walk result (seqretries ignored on the final pass) — the `Arc`
//! already guarantees memory safety. So the walk ALWAYS terminates and returns
//! the correct result; it can NEVER livelock the boot path. This is the apex
//! boot-safety property of the D22 work.
//!
//! Watchdog-guarded: were the valve absent (unbounded restart), the relentless
//! mover would livelock the walk and the watchdog would abort instead of hang.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use vfs::inode::Inode;
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{d_add, d_move, Dentry, FileType, InodeRef, KResult, LookupFlags, VfsError};

fn watchdog(secs: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(secs));
        eprintln!("watchdog: bounded-retry valve exceeded {secs}s — aborting (livelock!)");
        std::process::abort();
    });
}

struct DirData { kids: BTreeMap<String, InodeRef> }
fn dir_data(kids: &[(&str, InodeRef)]) -> Arc<DirData> {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    Arc::new(DirData { kids: m })
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
fn file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

#[test]
fn relentless_renames_still_terminate_with_correct_result() {
    watchdog(30);
    let leaf = file(0xC);
    let b = dir(0xB, &[("c", leaf)]);
    let a = dir(0xA, &[("b", b)]);
    let root = Dentry::new_root(dir(2, &[("a", a)]));
    // Warm /a/b/c so the racing walks are pure fast-path reads.
    let _ = vfs::path_lookup_path(root.clone(), root.clone(), "/a/b/c", LookupFlags::default()).unwrap();

    // A TIGHT mover loop ping-pongs one name, advancing the global rename
    // seqcount as fast as possible so most walks exhaust their restart budget
    // and exercise the degrade valve.
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let root2 = root.clone();
    let mover = std::thread::spawn(move || {
        let mut cur = d_add(&root2, "p", file(0x70));
        let mut flip = false;
        while !stop2.load(Ordering::Relaxed) {
            let n = if flip { "q" } else { "p" };
            cur = d_move(&cur, &root2, n);
            flip = !flip;
        }
    });

    // Every walk must complete (valve, not livelock) and return the correct,
    // un-torn result regardless of how many restarts it burned.
    for _ in 0..3000u32 {
        let p = vfs::path_lookup_path(root.clone(), root.clone(), "/a/b/c", LookupFlags::default())
            .expect("walk terminates via the bounded-degrade valve");
        assert_eq!(p.inode.ino(), 0xC, "degraded result is still correct (Arc-walk is mem-safe)");
    }
    stop.store(true, Ordering::Relaxed);
    mover.join().unwrap();
}
