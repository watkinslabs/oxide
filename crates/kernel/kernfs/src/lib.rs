//! Generic pseudo-filesystem tree (Linux `fs/kernfs` shape). `PseudoDir`
//! is a real per-component `vfs::Inode`: its `children` BTreeMap IS the
//! directory and resolution is per-component `i_op->lookup`, never a
//! whole-path key. Lifted from devfs's `DevDir` (D1) and given a `Weak<
//! SuperBlock>` (`i_sb`, the tmpfs `TmpfsDir` precedent) plus an optional
//! per-dir ext4-overlay so each pseudo-fs (devfs/sysfs/procfs/tracefs/
//! devpts) can OWN its own tree under its SuperBlock instead of a shared
//! global path registry (D1b).
//!
//! `readdir` enumerates its (sorted) BTreeMap children THEN, when
//! `overlay` is set, the ext4 overlay for its own path (skipping
//! synthetic-shadowed names) — mirroring devtmpfs's `/dev` + `/etc`
//! merge. Trees that have no on-disk backing (sysfs/procfs subtrees)
//! leave `overlay` off and emit children only.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};
use vfs::superblock::SuperBlock;
use vfs::{FileType, Ino, Inode, InodeBuilder, InodeRef, KResult, VfsError};
use vfs::{DirContext, FileOps, InodeOps, default_file_ops, default_inode_ops, mk_mode};

// ---------------------------------------------------------------------------
// ext4 directory-overlay hook (installed once at boot by the kernel).
// ---------------------------------------------------------------------------

/// Directory-overlay hook: emits real on-disk children (the rootfs) under a
/// path prefix, so synthetic dirs (`/dev`, `/etc`) overlay ext4 without
/// kernfs depending on a filesystem driver (would cycle kernfs->ext4->
/// block->cgroup->...). The kernel installs an ext4 adapter at boot (docs/56).
static DIR_OVERLAY: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
type OverlayFn = fn(&[u8], &mut dyn FnMut(&[u8], FileType));

/// Install the rootfs directory-overlay adapter. Boot, once.
/// # C: O(1)
pub fn set_dir_overlay(f: OverlayFn) { DIR_OVERLAY.store(f as *mut (), Ordering::Release); }

/// Emit on-disk ext4 children under `prefix` via the installed adapter.
/// Called by `PseudoDir::readdir` (overlay dirs only) to merge real entries
/// with synthetic ones. # C: O(N ext4 children)
fn dir_overlay(prefix: &[u8], emit: &mut dyn FnMut(&[u8], FileType)) {
    let p = DIR_OVERLAY.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: p was stored from an OverlayFn via set_dir_overlay; the fn
    // pointer type round-trips through *mut () unchanged.
    let f: OverlayFn = unsafe { core::mem::transmute(p) };
    f(prefix, emit);
}

// ---------------------------------------------------------------------------
// Inode-number derivation (FNV-1a, tagged into the synthetic-dir range).
// ---------------------------------------------------------------------------

/// Deterministic inode number from a path (FNV-1a, tagged into the
/// synthetic-dir range so it never collides with leaf inodes). # C: O(len)
pub fn dir_ino(path: &str) -> Ino {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in path.as_bytes() { h ^= *b as u64; h = h.wrapping_mul(0x0000_0100_0000_01b3); }
    0x5000_0000_0000_0000 | (h & 0x0fff_ffff_ffff_ffff)
}

/// Split an absolute path into non-empty components. # C: O(len)
fn components(path: &str) -> Vec<&str> {
    path.split('/').filter(|c| !c.is_empty()).collect()
}

// ---------------------------------------------------------------------------
// PseudoSymlink
// ---------------------------------------------------------------------------

/// A symlink leaf in a pseudo-fs tree (lifted from devfs `DevSymlink`).
/// The target is the inline `i_link` fast-symlink body (`get_link` reads it
/// directly), so no custom `i_op->readlink` is needed. Leaf symlinks were
/// never SB-stamped by `set_sb` (it recurses dirs only), so `fsid` is the
/// fallback id passed at creation.
pub struct PseudoSymlink;

impl PseudoSymlink {
    /// Build a symlink inode (`S_IFLNK|0o777`, inline `i_link` = `target`).
    /// Returns the concrete [`InodeRef`]. # C: O(target)
    pub fn new(ino: Ino, fsid: u64, target: &[u8]) -> InodeRef {
        InodeBuilder::new(ino, mk_mode(FileType::Symlink, 0o777), default_inode_ops(), default_file_ops())
            .fsid(fsid)
            .size(target.len() as u64)
            .link(target.to_vec().into_boxed_slice())
            .build()
    }
}

// ---------------------------------------------------------------------------
// PseudoDir
// ---------------------------------------------------------------------------

/// A child of a `PseudoDir`: a subdirectory or a registered leaf inode
/// (device node, symlink, static/dynamic file).
enum PseudoEntry { Dir(Arc<PseudoDir>), Leaf(InodeRef) }

impl PseudoEntry {
    fn file_type(&self) -> FileType {
        match self { PseudoEntry::Dir(_) => FileType::Directory, PseudoEntry::Leaf(i) => i.file_type() }
    }
    /// The entry's inode number WITHOUT materialising a dir inode. # C: O(1)
    fn ino(&self) -> Ino {
        match self { PseudoEntry::Dir(d) => d.ino, PseudoEntry::Leaf(i) => i.ino() }
    }
    /// Materialise the entry as an [`InodeRef`]: a dir builds (or reuses) its
    /// backing `vfs::Inode`; a leaf is already one. # C: O(1)
    fn as_inode(&self) -> InodeRef {
        match self { PseudoEntry::Dir(d) => d.as_inode(), PseudoEntry::Leaf(i) => Arc::clone(i) }
    }
}

/// A mutable directory in a pseudo-fs tree. Drivers register nodes at
/// runtime, so `children` is behind a spinlock. `path` is the dir's
/// absolute path (root = ""), used to drive the ext4 overlay. `fsid` is the
/// fallback filesystem id when no `SuperBlock` is stamped; once `set_sb`
/// runs at `fill_super`, `fsid`/`i_sb` derive from the SB's `s_dev`.
/// `overlay` gates the ext4 readdir merge (devtmpfs `/dev`, rootfs `/etc`).
pub struct PseudoDir {
    ino:      Ino,
    path:     String,
    fsid:     u64,
    overlay:  bool,
    sb:       Spinlock<Weak<SuperBlock>, TaskListClass>,
    children: Spinlock<BTreeMap<String, PseudoEntry>, TaskListClass>,
    /// Cached backing `vfs::Inode` (lazily built by [`PseudoDir::as_inode`]).
    /// `Weak` so the Inode (whose `i_private` holds a strong `Arc<PseudoDir>`)
    /// is freed when no dcache/dentry references it; the next `as_inode`
    /// rebuilds an identical one. Cleared by `set_sb` so a re-stamp re-derives
    /// `i_sb`/`fsid`.
    inode:    Spinlock<Weak<Inode>, TaskListClass>,
}

impl PseudoDir {
    /// A fresh root dir (`path == ""`). `root_ino` is the stable root inode
    /// number; `fsid` the fallback filesystem id; `overlay` whether readdir
    /// merges the ext4 overlay for this subtree. # C: O(1)
    pub fn new_root(root_ino: Ino, fsid: u64, overlay: bool) -> Arc<PseudoDir> {
        Arc::new(PseudoDir {
            ino: root_ino, path: String::new(), fsid, overlay,
            sb: Spinlock::new(Weak::new()),
            children: Spinlock::new(BTreeMap::new()),
            inode: Spinlock::new(Weak::new()),
        })
    }

    /// Internal: a non-root dir at `path` inheriting `fsid`/`overlay`/`sb`.
    /// # C: O(1)
    fn child_at(path: String, fsid: u64, overlay: bool, sb: Weak<SuperBlock>) -> Arc<PseudoDir> {
        Arc::new(PseudoDir {
            ino: dir_ino(&path), path, fsid, overlay,
            sb: Spinlock::new(sb),
            children: Spinlock::new(BTreeMap::new()),
            inode: Spinlock::new(Weak::new()),
        })
    }

    /// Stamp the owning SB (`fill_super`); after this `fsid`/`i_sb` derive
    /// from `s_dev`. Clears the cached inode so the next `as_inode` re-derives
    /// `i_sb`/`fsid`. Recurses into existing children so a whole pre-built
    /// tree adopts the SB. # C: O(tree)
    pub fn set_sb(&self, sb: Weak<SuperBlock>) {
        *self.sb.lock() = sb.clone();
        *self.inode.lock() = Weak::new();
        let g = self.children.lock();
        for v in g.values() {
            if let PseudoEntry::Dir(d) = v { d.set_sb(sb.clone()); }
        }
    }

    /// Materialise (or reuse) this dir's backing `vfs::Inode`. The Inode's
    /// `i_private` holds a strong `Arc<PseudoDir>`; the dir back-refs it
    /// `Weak`, so identity is stable while any dcache/dentry holds it and is
    /// rebuilt identically afterwards. `i_sb` reflects the current stamp;
    /// `fsid` falls back to `self.fsid` only when no SB is stamped (matching
    /// the old live `fsid()`). # C: O(1)
    pub fn as_inode(self: &Arc<PseudoDir>) -> InodeRef {
        let mut g = self.inode.lock();
        if let Some(i) = g.upgrade() { return i; }
        let sbw = self.sb.lock().clone();
        let mut b = InodeBuilder::new(self.ino, mk_mode(FileType::Directory, 0o755),
            Arc::new(PseudoDirOps), Arc::new(PseudoDirFileOps))
            .private(Arc::clone(self) as Arc<dyn core::any::Any + Send + Sync>)
            .sb(sbw.clone());
        // No SB stamped → report the fallback fsid (the old `fsid()` path).
        if sbw.upgrade().is_none() { b = b.fsid(self.fsid); }
        let inode = b.build();
        *g = Arc::downgrade(&inode);
        inode
    }

    /// This dir's owning-SB weak (handed to children it creates). # C: O(1)
    fn sb_weak(&self) -> Weak<SuperBlock> { self.sb.lock().clone() }

    /// Get-or-create the subdirectory `name`, building its absolute path.
    /// # C: O(log children)
    fn child_dir(self: &Arc<PseudoDir>, name: &str) -> Arc<PseudoDir> {
        let mut g = self.children.lock();
        if let Some(PseudoEntry::Dir(d)) = g.get(name) { return Arc::clone(d); }
        let mut cp = self.path.clone();
        cp.push('/');
        cp.push_str(name);
        let d = PseudoDir::child_at(cp, self.fsid, self.overlay, self.sb_weak());
        g.insert(String::from(name), PseudoEntry::Dir(Arc::clone(&d)));
        d
    }

    /// Register `full_path` → `inode`. Walks/creates the intermediate dirs
    /// and inserts a `Leaf` at the last component. A `Dir` already present at
    /// the leaf name is kept (registering a node where an intermediate dir
    /// was auto-created is not a conflict). Re-registration overwrites a leaf.
    /// (= old `tree::register`.) # C: O(depth)
    pub fn insert_path(self: &Arc<PseudoDir>, full_path: &str, inode: InodeRef) {
        let comps = components(full_path);
        if comps.is_empty() { return; }
        let mut dir = Arc::clone(self);
        for c in &comps[..comps.len() - 1] { dir = dir.child_dir(c); }
        let leaf = comps[comps.len() - 1];
        let mut g = dir.children.lock();
        match g.get(leaf) {
            Some(PseudoEntry::Dir(_)) => {}
            _ => { g.insert(String::from(leaf), PseudoEntry::Leaf(inode)); }
        }
    }

    /// Create the directory chain `path` as empty dirs — for mount points
    /// with no registered leaf children (e.g. `/sys/fs/cgroup`). The walked
    /// mountpoint dentry is what the mount engine takes. (= old
    /// `tree::register_dir`.) # C: O(components)
    pub fn ensure_dir_path(self: &Arc<PseudoDir>, path: &str) {
        let comps = components(path);
        let mut dir = Arc::clone(self);
        for c in &comps { dir = dir.child_dir(c); }
        let _ = dir;
    }

    /// Resolve `full_path` from this root. A leaf mid-path → `None`; a dir as
    /// the final component → the dir; the empty path → this root. (= old
    /// `tree::lookup`.) # C: O(depth)
    pub fn lookup_path(self: &Arc<PseudoDir>, full_path: &str) -> Option<InodeRef> {
        let comps = components(full_path);
        if comps.is_empty() { return Some(self.as_inode()); }
        let mut dir = Arc::clone(self);
        for (i, c) in comps.iter().enumerate() {
            let g = dir.children.lock();
            match g.get(*c) {
                Some(PseudoEntry::Leaf(inode)) => {
                    if i == comps.len() - 1 { return Some(Arc::clone(inode)); }
                    return None; // leaf mid-path
                }
                Some(PseudoEntry::Dir(d)) => {
                    let d = Arc::clone(d);
                    drop(g);
                    if i == comps.len() - 1 { return Some(d.as_inode()); }
                    dir = d;
                }
                None => return None,
            }
        }
        None
    }

    /// Remove the entry at `path` (and its subtree — dropping the
    /// `Arc<PseudoDir>` drops its children). Returns 1 if removed, else 0.
    /// (= old `tree::unregister_subtree`.) # C: O(depth)
    pub fn remove_subtree(self: &Arc<PseudoDir>, path: &str) -> usize {
        let comps = components(path);
        if comps.is_empty() { return 0; }
        let mut dir = Arc::clone(self);
        for c in &comps[..comps.len() - 1] {
            let next = { let g = dir.children.lock();
                match g.get(*c) { Some(PseudoEntry::Dir(d)) => Arc::clone(d), _ => return 0 } };
            dir = next;
        }
        let leaf = comps[comps.len() - 1];
        if dir.children.lock().remove(leaf).is_some() { 1 } else { 0 }
    }

    /// Recursively deep-clone this dir (subdirs cloned, leaf Arcs shared).
    /// Used by clone(CLONE_NEWNS)/unshare. (= old `tree::snapshot_ns` core.)
    /// # C: O(tree)
    pub fn deep_clone(&self) -> Arc<PseudoDir> {
        let g = self.children.lock();
        let mut nc: BTreeMap<String, PseudoEntry> = BTreeMap::new();
        for (k, v) in g.iter() {
            let nv = match v {
                PseudoEntry::Dir(d)  => PseudoEntry::Dir(d.deep_clone()),
                PseudoEntry::Leaf(i) => PseudoEntry::Leaf(Arc::clone(i)),
            };
            nc.insert(k.clone(), nv);
        }
        Arc::new(PseudoDir {
            ino: self.ino, path: self.path.clone(), fsid: self.fsid, overlay: self.overlay,
            sb: Spinlock::new(self.sb.lock().clone()),
            children: Spinlock::new(nc),
            inode: Spinlock::new(Weak::new()),
        })
    }

    // ---- VFS op bodies (driven by `PseudoDirOps`/`PseudoDirFileOps` off the
    //      inode's `i_private`) ------------------------------------------------

    /// `i_op->lookup`. # C: O(log children)
    fn op_lookup(&self, name: &str) -> KResult<InodeRef> {
        let g = self.children.lock();
        g.get(name).map(|e| e.as_inode()).ok_or(VfsError::Enoent)
    }

    /// `i_op->mkdir`. Pseudo-fs dirs are mutable: systemd/tmpfiles create
    /// mountpoint dirs and runtime symlinks (e.g. `/dev/log`) during early
    /// boot. # C: O(log children)
    fn op_mkdir(&self, name: &str) -> KResult<InodeRef> {
        let mut g = self.children.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        let mut cp = self.path.clone();
        cp.push('/');
        cp.push_str(name);
        let d = PseudoDir::child_at(cp, self.fsid, self.overlay, self.sb_weak());
        g.insert(String::from(name), PseudoEntry::Dir(Arc::clone(&d)));
        Ok(d.as_inode())
    }

    /// `i_op->symlink`. # C: O(log children + target)
    fn op_symlink(&self, name: &str, target: &[u8]) -> KResult<()> {
        let mut g = self.children.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        let mut cp = self.path.clone();
        cp.push('/');
        cp.push_str(name);
        let link = PseudoSymlink::new(dir_ino(&cp), self.fsid, target);
        g.insert(String::from(name), PseudoEntry::Leaf(link));
        Ok(())
    }

    /// `f_op->iterate`/readdir. # C: O(children + overlay)
    fn op_readdir(&self, inode: &Inode, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        // Synthetic children first (BTreeMap → sorted, stable order). Capture
        // each child's real ino so getdents reports a non-zero `d_ino`.
        let kids: Vec<(String, u64, FileType)> = {
            let g = self.children.lock();
            g.iter().map(|(k, v)| (k.clone(), v.ino(), v.file_type())).collect()
        };
        let r_len = kids.len() as u64;
        let mut idx = off as usize;
        while idx < kids.len() {
            let (name, ino, ft) = &kids[idx];
            let next = idx as u64 + 1;
            if !f(*ino, next, name, *ft) { return Ok(next); }
            idx += 1;
        }
        if !self.overlay { return Ok(r_len); }
        // ext4 overlay for this dir's path, skipping synthetic-shadowed names.
        let mut ext4_seen: u64 = 0;
        let mut stopped = false;
        let mut stop_off: u64 = (idx as u64).max(r_len);
        let prefix: &str = if self.path.is_empty() { "/" } else { &self.path };
        dir_overlay(prefix.as_bytes(), &mut |name_bytes, ftype| {
            if stopped { return; }
            ext4_seen += 1;
            if r_len + ext4_seen <= off { return; }
            let name = match core::str::from_utf8(name_bytes) { Ok(s) => s, Err(_) => return };
            if kids.iter().any(|(k, _, _)| k.as_str() == name) { return; }
            let next = r_len + ext4_seen;
            // Resolve the overlay child's real (ext4) ino for `d_ino`; the
            // children lock is already released, so this lookup is deadlock-free.
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, name, ftype) { stopped = true; stop_off = next; }
        });
        if stopped { return Ok(stop_off); }
        Ok(r_len + ext4_seen)
    }
}

/// `inode_operations` for a `PseudoDir` — namespace ops dispatch to the
/// `Arc<PseudoDir>` stored in `i_private`. # C: O(1) dispatch
struct PseudoDirOps;

/// Recover the backing `PseudoDir` from an inode's `i_private`. # C: O(1)
fn pdir(inode: &Inode) -> KResult<&PseudoDir> {
    inode.private::<PseudoDir>().ok_or(VfsError::Einval)
}

impl InodeOps for PseudoDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> { pdir(inode)?.op_lookup(name) }
    fn mkdir(&self, inode: &Inode, name: &str, _mode: u32, _ctx: &vfs::CreateCtx) -> KResult<InodeRef> { pdir(inode)?.op_mkdir(name) }
    fn symlink(&self, inode: &Inode, name: &str, target: &[u8], _ctx: &vfs::CreateCtx) -> KResult<()> { pdir(inode)?.op_symlink(name, target) }
}

/// `file_operations` for a `PseudoDir` — only the directory iterate path.
/// # C: O(1) dispatch
struct PseudoDirFileOps;

impl FileOps for PseudoDirFileOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        // Adapt the kernfs-internal `op_readdir` (legacy closure form) to the
        // dir_context actor: each entry is forwarded through `ctx.emit`, which
        // advances `ctx.pos` and signals buffer-full (false) back to stop.
        let off = ctx.pos;
        pdir(inode)?.op_readdir(inode, off, &mut |ino, next, name, ft| ctx.emit(name, ino, ft, next))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PseudoFs — a whole kernfs-class filesystem instance (Linux ramfs/kernfs
// `mount_nodev` + `simple_fill_super` shape).
// ---------------------------------------------------------------------------

/// A whole pseudo-filesystem instance: a fresh empty `PseudoDir` root under
/// its own `SuperBlock`, carrying the fstype's `s_magic`. The Linux shape for
/// the simple kernfs/ramfs-class api-fses (securityfs, bpf, configfs, mqueue,
/// hugetlbfs, pstore, efivarfs, fusectl) — mounted EMPTY, then populated by
/// the kernel/userspace after mount. Implementing `FileSystem` (non-`None`
/// `root()`) is what makes such a mount enter the unified mount table, appear
/// in `/proc/self/mountinfo`, and report its `s_magic` via `statfs` `f_type` —
/// replacing the old admit-noop `=> 0` that registered NOTHING (mount(2)
/// returned 0 but the mount was invisible → libmount post-mount verify failed).
pub struct PseudoFs {
    name: &'static str,
    magic: u64,
    root: Arc<PseudoDir>,
}

/// Fixed root inode number for every kernfs/ramfs-class pseudo-fs, matching
/// Linux `pseudo_fs_fill_super` (`fs/libfs.c`: `root->i_ino = 1`). Target-
/// INDEPENDENT, so the SB realized at `fsconfig(CMD_CREATE)` (which does not
/// yet know the mount target) is byte-identical to what `mount_fstype` grafts —
/// the precondition for adding these fstypes to `fstype_converted`. Child
/// inode numbering is unaffected: child paths are seeded from the empty root
/// path (`PseudoDir::new_root` sets `path == ""`), never from the target.
pub const PSEUDO_ROOT_INO: Ino = 1;

impl PseudoFs {
    /// Build a fresh instance. `name` is the fstype string, `magic` its
    /// `linux/magic.h` `s_magic`. The root inode number is the fixed Linux
    /// pseudo-fs root ino ([`PSEUDO_ROOT_INO`] = 1), NOT derived from the mount
    /// target, so two distinct mounts of the same fstype get identical root
    /// inos under distinct SBs (distinct `s_dev`) — Linux-faithful and target-
    /// independent. # C: O(1)
    pub fn new(name: &'static str, magic: u64) -> Arc<Self> {
        let root = PseudoDir::new_root(PSEUDO_ROOT_INO, magic, false);
        Arc::new(Self { name, magic, root })
    }

    /// The mount's root directory (tree-population entry point). # C: O(1)
    pub fn root_dir(&self) -> &Arc<PseudoDir> { &self.root }
}

impl vfs::fs::FileSystem for PseudoFs {
    /// # C: O(1)
    fn name(&self) -> &str { self.name }
    /// # C: O(1)
    fn magic(&self) -> u64 { self.magic }
    /// Non-`None` directory root: the walk crosses into the mount and the
    /// post-mount verify accepts it. # C: O(1)
    fn root(&self) -> Option<InodeRef> { Some(self.root.as_inode()) }
    /// Back-stamp the SB so the tree's inodes report `s_dev` (`fill_super`).
    /// # C: O(tree)
    fn set_sb(&self, sb: Weak<SuperBlock>) { self.root.set_sb(sb); }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> Arc<PseudoDir> { PseudoDir::new_root(0x5000_0001, 0xDEAD, false) }

    #[test]
    fn insert_then_lookup_per_component() {
        let r = root();
        let leaf = PseudoSymlink::new(1, 0xDEAD, b"/target");
        r.insert_path("/sys/kernel/osrelease", leaf);
        // Per-component walk resolves the leaf.
        let got = r.lookup_path("/sys/kernel/osrelease").expect("leaf");
        assert_eq!(got.file_type(), FileType::Symlink);
        // Intermediate dirs were auto-created and are walkable.
        let kdir = r.lookup_path("/sys/kernel").expect("intermediate dir");
        assert_eq!(kdir.file_type(), FileType::Directory);
        // Direct per-component lookup matches whole-path resolution.
        let sys = r.as_inode().lookup("sys").expect("sys child");
        assert_eq!(sys.lookup("kernel").expect("kernel child").file_type(), FileType::Directory);
    }

    #[test]
    fn leaf_mid_path_is_none() {
        let r = root();
        r.insert_path("/a/b", PseudoSymlink::new(2, 0, b"x"));
        // /a/b is a leaf; resolving through it must fail.
        assert!(r.lookup_path("/a/b/c").is_none());
    }

    #[test]
    fn readdir_sorted_and_no_overlay_when_off() {
        let r = root();
        r.insert_path("/z", PseudoSymlink::new(3, 0, b"z"));
        r.insert_path("/a", PseudoSymlink::new(4, 0, b"a"));
        r.insert_path("/m", PseudoSymlink::new(5, 0, b"m"));
        let mut names = std::vec::Vec::new();
        {
            struct Collect<'a>(&'a mut std::vec::Vec<std::string::String>);
            impl<'a> vfs::DirEmit for Collect<'a> {
                fn emit(&mut self, name: &str, _ino: u64, _d: vfs::FileType, _next: u64) -> bool {
                    self.0.push(std::string::String::from(name)); true
                }
            }
            let mut actor = Collect(&mut names);
            let mut ctx = vfs::DirContext::new(0, &mut actor);
            r.as_inode().readdir(&mut ctx).unwrap();
        }
        // BTreeMap → sorted; overlay off → exactly the 3 synthetic children.
        assert_eq!(names, std::vec!["a", "m", "z"]);
    }

    #[test]
    fn ensure_dir_path_creates_empty_mountpoint() {
        let r = root();
        r.ensure_dir_path("/sys/fs/cgroup");
        let d = r.lookup_path("/sys/fs/cgroup").expect("mountpoint dir");
        assert_eq!(d.file_type(), FileType::Directory);
    }

    #[test]
    fn deep_clone_is_independent() {
        let r = root();
        r.insert_path("/dev/null", PseudoSymlink::new(6, 0, b"n"));
        let c = r.deep_clone();
        // Mutating the clone does not affect the source.
        c.insert_path("/dev/extra", PseudoSymlink::new(7, 0, b"e"));
        assert!(c.lookup_path("/dev/extra").is_some());
        assert!(r.lookup_path("/dev/extra").is_none());
        // Shared leaves still present in both.
        assert!(r.lookup_path("/dev/null").is_some());
        assert!(c.lookup_path("/dev/null").is_some());
    }

    #[test]
    fn own_roots_are_isolated() {
        // D1c property the shared ROOTS write-bus violated: a write into one
        // fs's own root is NOT visible from another fs's root. Mirrors sysfs
        // SYS_ROOT vs tracefs TRACE_ROOT (each `new_root`, distinct fsid).
        let sys = PseudoDir::new_root(dir_ino("/sys"), 0x2, false);
        let trace = PseudoDir::new_root(dir_ino("/sys/kernel/tracing"), 0x3, false);
        // sysfs-style writers insert mount-relative (the "/sys" prefix stripped).
        sys.insert_path("class/net", PseudoSymlink::new(10, 0x2, b"net"));
        sys.insert_path("kernel/osrelease", PseudoSymlink::new(11, 0x2, b"v"));
        // tracefs-style writer inserts into its OWN root.
        trace.insert_path("current_tracer", PseudoSymlink::new(12, 0x3, b"nop"));
        // Multi-component resolution from each own root.
        assert!(sys.lookup_path("class/net").is_some());
        assert!(sys.lookup_path("kernel/osrelease").is_some());
        assert!(trace.lookup_path("current_tracer").is_some());
        // Isolation: neither root sees the other's entries.
        assert!(sys.lookup_path("current_tracer").is_none());
        assert!(trace.lookup_path("class/net").is_none());
        // Distinct identity (the per-fs st_dev the shared tree collapsed).
        assert_ne!(sys.as_inode().fsid(), trace.as_inode().fsid());
    }

    #[test]
    fn pseudofs_root_ino_is_fixed_and_target_independent() {
        use vfs::fs::FileSystem;
        // Two distinct mounts of the same fstype (what fsopen/fsconfig and the
        // legacy mount_fstype path each build) must expose the SAME fixed root
        // ino — Linux pseudo_fs_fill_super root->i_ino = 1 — never a target hash.
        let a = PseudoFs::new("bpf", 0xcafe_4a11);
        let b = PseudoFs::new("bpf", 0xcafe_4a11);
        assert_eq!(a.root().unwrap().ino(), PSEUDO_ROOT_INO);
        assert_eq!(b.root().unwrap().ino(), PSEUDO_ROOT_INO);
        assert_eq!(PSEUDO_ROOT_INO, 1);
        // Root ino does not depend on construction order/identity.
        assert_eq!(a.root().unwrap().ino(), b.root().unwrap().ino());
        // Child inode numbering is unaffected (still in the tagged dir range).
        a.root_dir().ensure_dir_path("sub");
        let child = a.root_dir().lookup_path("sub").expect("child dir");
        assert_ne!(child.ino(), PSEUDO_ROOT_INO);
        assert_eq!(child.ino(), dir_ino("/sub"));
    }

    #[test]
    fn remove_subtree_drops_branch() {
        let r = root();
        r.insert_path("/dev/pts/0", PseudoSymlink::new(8, 0, b"0"));
        assert_eq!(r.remove_subtree("/dev/pts"), 1);
        assert!(r.lookup_path("/dev/pts").is_none());
        assert_eq!(r.remove_subtree("/dev/pts"), 0);
    }
}
