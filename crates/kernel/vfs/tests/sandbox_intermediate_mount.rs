//! REGRESSION (udevd mount-ns NAMESPACE/226): the engine-internal `descend`
//! that materialises SYNTHESIZED mount positions must CROSS an intermediate
//! mount it walks THROUGH — resolving the remaining components in that mount's
//! root, exactly as `namei` later walks them — not in the covered underlay.
//!
//! The discriminating path is a COLD descent (no syscall pre-walked it) that
//! passes through a live intermediate mount: recursive-bind submount mirroring.
//! `bind_submounts_rec` clones every submount of `src` under `tgt`; the deeper
//! submount `/src/a/b` mirrors to `/stage/a/b`, whose descent crosses the
//! freshly-created `/stage/a` clone mount. With the pre-fix non-crossing
//! `descend`, `descend("/stage","a/b")` read the empty `/stage/a` UNDERLAY,
//! hit ENOENT on `b`, and DROPPED the clone — the same orphaning that left
//! udevd's relocated procfs unreachable so `/proc/sys/kernel/domainname`
//! ENOENT'd → systemd EXIT_NAMESPACE(226).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{Dentry, FileType, InodeRef, KResult, LookupFlags, VfsError};

static SERIAL: Mutex<()> = Mutex::new(());

/// Backend state (`i_private`): the static child table this directory resolves.
struct DirData { kids: BTreeMap<String, InodeRef> }

/// `i_op->lookup` over the static `DirData` child table.
struct DirOps;
impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<DirData>().ok_or(VfsError::Enotdir)?;
        d.kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}
fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(DirOps), default_file_ops())
        .private(Arc::new(DirData { kids: m })).build()
}
fn file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

struct NamedFs { n: &'static str, root: InodeRef }
impl FileSystem for NamedFs {
    fn name(&self) -> &str { self.n }
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
}

static ROOT: OnceLock<Arc<Dentry>> = OnceLock::new();
fn root_provider() -> Option<Arc<Dentry>> { ROOT.get().cloned() }

fn guard() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn descend_crosses_intermediate_mount_in_cold_synthesis() {
    let _g = guard();
    const NS: u64 = 0x5A11_BEEF;
    vfs::mount::set_current_ns_provider(|| NS);

    // ext4-root tree. `/stage` underlay owns `a` (so the first, shallow clone
    // lands) but NOT `a/b` (the deep clone must come from CROSSING `/stage/a`).
    let root_inode = dir(2, &[
        ("src", dir(0x30, &[])),
        ("stage", dir(0x20, &[("a", dir(0x21, &[]))])),
    ]);
    let root = ROOT.get_or_init(|| Dentry::new_root(root_inode.clone())).clone();
    vfs::set_root_dentry_provider(root_provider);

    // ns root mount.
    vfs::mount::register(None, Arc::new(NamedFs { n: "ext4", root: root_inode }))
        .expect("root mount");

    // Nested mounts under /src: /src (owns a) -> /src/a (owns b) -> /src/a/b
    // (owns leaf). Each registered on the namei-walked (crossing) dentry.
    let src_root = dir(0x300, &[("a", dir(0x302, &[]))]);
    let a_root = dir(0x400, &[("b", dir(0x402, &[]))]);
    let b_root = dir(0x500, &[("leaf", file(0x501))]);

    let (_, src_d) = vfs::path_lookup(root.clone(), root.clone(), "/src", LookupFlags::default()).expect("/src");
    vfs::mount::register_bind(Some(src_d.clone()), Arc::new(NamedFs { n: "srcfs", root: src_root.clone() }), src_root).expect("mount /src");
    let (_, a_d) = vfs::path_lookup(root.clone(), root.clone(), "/src/a", LookupFlags::default()).expect("/src/a");
    vfs::mount::register_bind(Some(a_d.clone()), Arc::new(NamedFs { n: "afs", root: a_root.clone() }), a_root).expect("mount /src/a");
    let (_, b_d) = vfs::path_lookup(root.clone(), root.clone(), "/src/a/b", LookupFlags::default()).expect("/src/a/b");
    vfs::mount::register_bind(Some(b_d.clone()), Arc::new(NamedFs { n: "bfs", root: b_root.clone() }), b_root).expect("mount /src/a/b");

    // Recursive bind: clone /src's submounts under /stage (a plain dir, so no
    // base crossing is involved — the descent's intermediate crossing is what
    // is under test).
    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/stage", LookupFlags::default()).expect("/stage");
    let n = vfs::mount::bind_submounts_rec(&src_d, &stage_d);
    assert_eq!(n, 2, "both /src/a and the deeper /src/a/b clone (the deep one needs crossing /stage/a)");

    // End-to-end: a crossing walk of /stage/a/b/leaf resolves through the deep
    // clone — proving the clone was wired on the dentry namei visits.
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/stage/a/b/leaf", LookupFlags::default())
        .expect("cross /stage/a -> /stage/a/b and resolve leaf");
    assert_eq!(i.ino(), 0x501, "leaf resolved across the cloned intermediate mount");
}
