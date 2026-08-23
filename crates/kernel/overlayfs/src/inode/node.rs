//! The per-object state behind an overlay inode.
//!
//! The object list changes under the inode — a copy-up gives it an upper half
//! it did not have — so it lives behind a lock rather than being baked into
//! the inode's fields. The inode's own metadata is refreshed from the real
//! object after any change, which is what makes `stat` agree with what the
//! next read will actually return.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Spinlock, TaskList};
use vfs::file_ops::FileOps;
use vfs::inode::InodeBuilder;
use vfs::inode_ops::InodeOps;
use vfs::types::{FileType, S_IFDIR};
use vfs::{Idmap, InodeRef};

use crate::layers::{LayerStack, OvlEntry};
use crate::xino;

/// One merged object.
pub struct OvlInode {
    pub stack: Arc<LayerStack>,
    /// The layers this object is made of. Replaced whole by a copy-up.
    pub entry: Spinlock<OvlEntry, TaskList>,
    /// The containing directory's state, absent only for the mount root.
    /// Copying an object up needs its ancestors copied up first, and this is
    /// the only path back to them. It is the SHARED state rather than a fresh
    /// copy, so an ancestor copied up here is copied up for every object that
    /// reaches it.
    pub parent: Option<Arc<OvlInode>>,
    /// A handle on this state, so a child can be given the shared one.
    me: Weak<OvlInode>,
    /// Reverse link used by exportfs's parent walk.
    self_inode: Spinlock<Option<Weak<vfs::Inode>>, TaskList>,
    /// This object's name inside that directory.
    pub name: String,
}

impl OvlInode {
    /// The shared handle on this state. # C: O(1)
    pub fn shared(&self) -> Option<Arc<OvlInode>> { self.me.upgrade() }
    /// Recover the VFS inode owning this state. # C: O(1)
    pub fn inode(&self) -> Option<InodeRef> { self.self_inode.lock().as_ref()?.upgrade() }
    /// A snapshot of the object list. # C: O(layers)
    pub fn entry(&self) -> OvlEntry { self.entry.lock().clone() }
    /// Replace it after a copy-up. # C: O(1)
    pub fn set_entry(&self, e: OvlEntry) { *self.entry.lock() = e; }
    /// The real object reads go to. # C: O(1)
    pub fn real(&self) -> Option<InodeRef> { self.entry.lock().real() }
    /// The real object holding the DATA, which for a metadata-only object is
    /// not the same one. # C: O(1)
    pub fn realdata(&self) -> Option<InodeRef> { self.entry.lock().realdata() }
}

/// The overlay state behind an inode. # C: O(1)
pub fn ovl_of(inode: &vfs::Inode) -> Option<&OvlInode> { inode.private::<OvlInode>() }

/// Non-persistent inode numbers, for an object no layer can supply one for.
/// They start above anything a layer is likely to mint so a collision is
/// visible rather than plausible.
static NEXT_INO: AtomicU64 = AtomicU64::new(1 << 48);

/// The inode number an overlay object reports.
///
/// A directory always reports the writable layer's, so `..` and the entry a
/// merged read produces agree. Everything else reports the number of the
/// object its data comes from, tagged with the layer when the mount remaps
/// them — that is what stops two files on two layers from looking like one.
/// # C: O(1)
pub fn report_ino(stack: &LayerStack, entry: &OvlEntry) -> u64 {
    let Some(real) = entry.real() else { return NEXT_INO.fetch_add(1, Ordering::Relaxed) };
    if real.file_type() == FileType::Directory { return real.ino(); }
    if entry.upper.is_some() {
        // A copied-up object keeps the number of the lower object it came
        // from, so a program holding it across a write does not see it change.
        if let Some(l) = entry.lower.first() {
            return xino::remap(l.inode.ino(), stack.xino.bits(), l.layer.fsid);
        }
        return real.ino();
    }
    match entry.lower.first() {
        Some(l) => xino::remap(l.inode.ino(), stack.xino.bits(), l.layer.fsid),
        None => real.ino(),
    }
}

/// Select the real inode key Linux uses for overlay inode hashing. A lower
/// inode remains the key when copy-up must preserve its identity; an
/// unindexed lower hardlink that will be broken on copy-up is intentionally
/// left uncached. A pure upper object uses its upper inode directly.
/// # C: O(1)
fn cache_key(stack: &LayerStack, entry: &OvlEntry) -> Option<usize> {
    let real = entry.real()?;
    let Some(lower) = entry.lower.first() else {
        return entry.upper.as_ref().map(|i| Arc::as_ptr(i) as usize);
    };
    let is_dir = real.file_type() == FileType::Directory;
    let by_lower = if stack.upper.is_none() { true }
        else if stack.indexdir.is_some() { true }
        else if !is_dir && real.nlink() > 1 { false }
        else { true };
    if by_lower { Some(Arc::as_ptr(&lower.inode) as usize) }
    else { entry.upper.as_ref().map(|i| Arc::as_ptr(i) as usize) }
}

/// Build the overlay inode for `entry`.
///
/// Its mode, size, owner and timestamps are the real object's, so the merge is
/// invisible to `stat` except where it deliberately is not — the inode number
/// and, when the layers differ, the device.
/// # C: O(1)
pub fn make_inode(stack: &Arc<LayerStack>, entry: OvlEntry, parent: Option<Arc<OvlInode>>,
                  name: &str) -> InodeRef {
    let key = cache_key(stack, &entry);
    if let Some(key) = key {
        let mut cache = stack.inode_cache.lock();
        if let Some(existing) = cache.get(&key).and_then(|w| w.upgrade()) { return existing; }
        cache.remove(&key);
        let inode = build_inode(stack, entry, parent, name);
        cache.insert(key, Arc::downgrade(&inode));
        return inode;
    }
    build_inode(stack, entry, parent, name)
}

/// Build one uncached overlay inode after the cache owner has selected its
/// canonical identity. # C: O(1)
fn build_inode(stack: &Arc<LayerStack>, entry: OvlEntry, parent: Option<Arc<OvlInode>>,
               name: &str) -> InodeRef {
    let real = entry.real();
    let st = real.as_ref().map(|r| r.getattr(&Idmap::identity()));
    let mode = st.as_ref().map(|s| s.mode).unwrap_or(S_IFDIR as u32 | 0o755);
    let ino = report_ino(stack, &entry);
    // The size of a metadata-only object is the upper object's, which the
    // copy-up set from the lower one; the data itself is still below.
    let size = st.as_ref().map(|s| s.size).unwrap_or(0);
    let ovl = Arc::new_cyclic(|me| OvlInode {
        stack: stack.clone(),
        entry: Spinlock::new(entry),
        parent,
        me: me.clone(),
        self_inode: Spinlock::new(None),
        name: name.to_string(),
    });
    let ops: Arc<dyn InodeOps> = Arc::new(super::ops::OvlOps);
    let fops: Arc<dyn FileOps> = Arc::new(super::ops::OvlOps);
    let mut b = InodeBuilder::new(ino, mode, ops, fops).private(ovl.clone()).size(size);
    if let Some(s) = &st {
        b = b.owner(s.uid, s.gid).times(s.atime, s.mtime, s.ctime).nlink(s.nlink).rdev(s.rdev);
    }
    if let Some(r) = &real {
        if let Some(l) = r.i_link() { b = b.link(l.to_vec().into_boxed_slice()); }
    }
    let inode = b.build();
    *ovl.self_inode.lock() = Some(Arc::downgrade(&inode));
    inode
}

/// Refresh an overlay inode's metadata from the real object, after something
/// changed which one that is. # C: O(1)
pub fn refresh(inode: &vfs::Inode) {
    let Some(ovl) = ovl_of(inode) else { return };
    let Some(real) = ovl.real() else { return };
    let st = real.getattr(&Idmap::identity());
    inode.set_size(st.size);
    let _ = inode.set_perm((st.mode & 0o7777) as u16);
    let _ = inode.set_owner(st.uid, st.gid);
}
