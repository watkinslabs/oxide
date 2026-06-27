//! Hosted-test DentryResolver fixture (`docs/16§3`). The real kernel
//! installs `pathresolve::resolve_dentry` (a full `path_lookup` to the
//! canonical mountpoint dentry) via `set_dentry_resolver`; without an
//! equivalent here, `Mount.mountpoint` is always `None` and the
//! dentry-identity mount engine (parent/child/exact-mount-here, mount
//! crossing) has nothing to key on. This fixture builds a REAL global
//! Dentry tree on demand: every absolute path maps to ONE canonical
//! `Arc<Dentry>` with a correct parent chain, so `resolve_dentry(p)` is
//! stable by identity and ancestor walks find covering mounts — exactly
//! what the migrated engine needs to be exercised in `cargo test`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use vfs::inode::Inode;
use vfs::{Dentry, FileType, InodeRef, KResult, VfsError};

/// A plain directory inode for fixture dentries. Per-component `lookup`
/// is unused: the fixture resolver synthesises the whole tree itself, so
/// resolution never falls through to `Inode::lookup`.
struct FixDir(u64);
impl Inode for FixDir {
    fn ino(&self) -> vfs::Ino { self.0 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}

/// Process-global canonical dentry tree, keyed by absolute path. One node
/// per path, parent-linked, so identity is stable across `resolve_dentry`
/// calls — the dcache invariant the engine relies on.
static TREE: Mutex<Option<BTreeMap<String, Arc<Dentry>>>> = Mutex::new(None);

/// Split an absolute path into (parent, final-component).
fn split_parent(path: &str) -> (&str, &str) {
    let t = path.trim_end_matches('/');
    match t.rfind('/') {
        Some(0) => ("/", &t[1..]),
        Some(i) => (&t[..i], &t[i + 1..]),
        _ => ("/", t),
    }
}

/// Get-or-build the canonical dentry for `path`, building the parent
/// chain first so `dentry.parent()` is a real link.
fn build(map: &mut BTreeMap<String, Arc<Dentry>>, path: &str) -> Arc<Dentry> {
    if let Some(d) = map.get(path) { return d.clone(); }
    if path == "/" {
        let d = Dentry::new_root(Arc::new(FixDir(2)));
        map.insert(String::from("/"), d.clone());
        return d;
    }
    let (parent, name) = split_parent(path);
    let pd = build(map, parent);
    let ino = 0x1000 + map.len() as u64;
    let d = Dentry::new(Some(pd), String::from(name), Arc::new(FixDir(ino)));
    map.insert(String::from(path), d.clone());
    d
}

/// The installed `DentryResolver`: absolute path → canonical dentry.
pub fn resolver(path: &str) -> Option<Arc<Dentry>> {
    if !path.starts_with('/') { return None; }
    let mut g = TREE.lock().unwrap_or_else(|e| e.into_inner());
    let map = g.get_or_insert_with(BTreeMap::new);
    Some(build(map, path))
}

/// Install the fixture resolver (idempotent; last wins). Call from every
/// test entry so the engine runs against dentry identity, not the table
/// string column.
pub fn install_dentry_resolver() {
    vfs::mount::set_dentry_resolver(resolver);
}
