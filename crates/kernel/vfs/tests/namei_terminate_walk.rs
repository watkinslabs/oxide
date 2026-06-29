//! namei D28: `terminate_walk` — the SINGLE error/teardown exit of the path
//! walk. An error mid-walk must release ALL transiently-held state (in the
//! Arc-walk substrate: any `unlazy_walk` legitimize pin + the LOOKUP_RCU read
//! side) and leave the dcache uncorrupted, so a subsequent walk still works and
//! no dentry on the failed path leaks a `d_count`. Error semantics must be
//! IDENTICAL in ref and rcu (opt-in) modes — terminate_walk's rcu unwind never
//! changes the returned errno.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use vfs::inode::Inode;
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{d_lookup, Dentry, FileType, InodeRef, KResult, LookupFlags, VfsError};

fn watchdog(secs: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(secs));
        eprintln!("watchdog: terminate_walk test exceeded {secs}s — aborting");
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
fn sym(ino: u64, t: &str) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Symlink, 0o777), default_inode_ops(), default_file_ops())
        .size(t.len() as u64).link(t.as_bytes().to_vec().into_boxed_slice()).build()
}
fn rcu() -> LookupFlags { let mut f = LookupFlags::default(); f.rcu = true; f }

fn build() -> Arc<Dentry> {
    // /a/hostname (file), /a/loop -> loop (self symlink → ELOOP).
    let a = dir(0xA, &[("hostname", file(0xC)), ("loop", sym(0x31, "loop"))]);
    let root_inode = dir(2, &[("a", a)]);
    Dentry::new_root(root_inode)
}

#[test]
fn error_exit_leaves_dcache_usable() {
    watchdog(30);
    let root = build();
    // A missing leaf errors ENOENT; the walk's single terminate_walk exit must
    // not corrupt the cache — a subsequent valid walk still resolves.
    assert_eq!(
        vfs::path_lookup_path(root.clone(), root.clone(), "/a/nope", LookupFlags::default()).err(),
        Some(VfsError::Enoent));
    let ok = vfs::path_lookup_path(root.clone(), root.clone(), "/a/hostname", LookupFlags::default())
        .expect("cache usable after an erroring walk");
    assert_eq!(ok.inode.ino(), 0xC);
}

#[test]
fn error_exit_releases_dcount_no_leak() {
    watchdog(30);
    let root = build();
    // An ELOOP mid-walk (self-referential symlink) must release every transient
    // pin terminate_walk/unlazy_walk took. Run it in rcu (opt-in) mode so the
    // legitimize path is exercised, then assert no dentry on the attempted path
    // retains a leaked d_count.
    assert_eq!(
        vfs::path_lookup_path(root.clone(), root.clone(), "/a/loop", rcu()).err(),
        Some(VfsError::Eloop), "self-symlink is ELOOP");
    let a = d_lookup(&root, "a").expect("`a` was cached by the failed walk");
    assert_eq!(a.d_count(), 0, "parent dir holds no leaked pin after the error exit");
    if let Some(lp) = d_lookup(&a, "loop") {
        assert_eq!(lp.d_count(), 0, "symlink dentry holds no leaked pin after the error exit");
    }
}

#[test]
fn error_semantics_identical_ref_and_rcu() {
    watchdog(30);
    let root = build();
    for path in ["/a/nope", "/a/loop", "/a/hostname/x"] {
        let r_ref = vfs::path_lookup_path(root.clone(), root.clone(), path, LookupFlags::default()).err();
        let r_rcu = vfs::path_lookup_path(root.clone(), root.clone(), path, rcu()).err();
        assert_eq!(r_ref, r_rcu, "rcu unwind must not change the errno for {path}");
    }
}
