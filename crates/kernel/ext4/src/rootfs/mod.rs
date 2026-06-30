// P6-07 → Stage 3: ext4 root mount + de-singletonised per-mount state.
//
// The ROOT filesystem (`Ext4RootfsFs`, a unit struct kmain registers at
// "/") resolves through a single published root `RootfsState`. Stage 3
// adds `Ext4Mount` (in `ops.rs`) — a self-contained FileSystem instance
// that carries its OWN `RootfsState` (mount + page cache + orphan set),
// so /home or a tools volume can each be its own ext4 mount without
// aliasing the root's device, cache, or orphan tracking. The free-fn API
// (`read_file`, `lookup_path`, …) and `Ext4RootfsFs` stay bound to the
// root, so existing callers (smoke/elf.rs, kmain) need no edits during
// the transition.

mod state;
mod inode;
mod ops;
mod framecache;

pub use state::RootfsState;
pub use inode::{EXT4_INO_MARK, EXT4_INO_MASK,
    ext4_wrap_ino, is_ext4_ino, ext4_unwrap_ino};
pub use ops::Ext4Mount;
pub use framecache::flush_all_dirty;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

#[cfg(target_os = "oxide-kernel")]
use block::BlockDevice;
use block::types::InodeId;

/// Published root `RootfsState` (leaked `&'static`, filled by
/// `init`/`set_test_mount`). The free-fn API + `Ext4RootfsFs` resolve
/// through this. Non-root mounts use their own `Arc<RootfsState>` via
/// `Ext4Mount` and never touch this pointer.
static ROOT: AtomicPtr<Arc<RootfsState>> = AtomicPtr::new(core::ptr::null_mut());

/// Resolve the published root state, or None if not yet mounted.
/// # C: O(1)
fn root() -> Option<&'static Arc<RootfsState>> {
    let p = ROOT.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: ROOT is published once via init()/set_test_mount() with a leaked Arc<RootfsState>; the pointee is stable for the kernel lifetime and only ever read here.
    Some(unsafe { &*p })
}

/// Publish `st` as the root state (idempotent — first writer wins).
/// Atomic `compare_exchange`: a losing writer drops its just-leaked box
/// rather than racing the `store`, so ROOT is published exactly once.
fn publish_root(st: Arc<RootfsState>) {
    let leaked: *mut Arc<RootfsState> = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(st));
    if ROOT
        .compare_exchange(core::ptr::null_mut(), leaked, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // Lost the race / already published — reclaim the unused box.
        // SAFETY: leaked came from Box::into_raw above and was never stored; we hold the sole pointer, so reconstituting the Box to drop it is the matching deallocation.
        drop(unsafe { alloc::boxed::Box::from_raw(leaked) });
    }
}

/// Mount `dev` as the ext4 ROOT filesystem + publish it for the free-fn
/// API. Idempotent (first ROOT publisher wins). Returns the opened
/// `RootfsState` so the caller can also build the VFS FileSystem object.
/// `Err` if the ext4 superblock fails to open.
///
/// # SAFETY: caller is the boot path post-allocator-up; no other CPU
/// has yet seen ROOT.
/// # C: O(N_groups + 1024) one-shot
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn init_from_dev(dev: Arc<dyn BlockDevice>) -> Result<(), block::types::BlockError> {
    if root().is_some() { return Ok(()); }
    let st = RootfsState::open(dev)?;
    publish_root(st);
    vfs::file::set_close_hook(close_hook_free_orphan);
    Ok(())
}

/// Test-only: publish a `Mount` (fixture image) as the ROOT mount, so
/// hosted resolution tests drive the real ext4 Inode impls without a
/// QEMU boot. Idempotent. Non-root fixture mounts use `Ext4Mount::open`.
/// # C: O(1)
pub fn set_test_mount(mount: crate::Mount) {
    if root().is_some() { return; }
    publish_root(RootfsState::new(Arc::new(mount)));
}

/// Close-hook: free an ext4 O_TMPFILE inode once its last fd drops AND
/// its on-disk nlink is 0. Routes to the OWNING mount via the closed
/// inode's own `Arc<RootfsState>` (recovered from `i_private` by
/// `ext4_state_of`) — NEVER `root()`. Small on-disk inos (11,12,13…)
/// collide across every ext4 image, so freeing against the root would
/// silently corrupt the root fs when a non-root mount's fd closes. The
/// marker only proves "some ext4 inode"; the wrapper's `st` field
/// disambiguates which mount owns it.
#[cfg(target_os = "oxide-kernel")]
fn close_hook_free_orphan(ino_ref: &vfs::InodeRef, _was_writable: bool) {
    if !is_ext4_ino(ino_ref.ino()) { return; }
    // Recover (owning mount state, ext4 ino) from the inode's i_private.
    let (st, ino): (Arc<RootfsState>, u32) = match inode::ext4_state_of(ino_ref) {
        Some(v) => v,
        None => return,
    };
    if !st.orphan_contains(ino) { return; }
    if Arc::strong_count(ino_ref) != 1 { return; }
    if let Ok(inode) = st.mount.read_inode(ino) {
        if inode.links_count == 0 {
            let _ = st.mount.free_orphan_inode(ino);
            st.orphan_remove(ino);
            st.page_cache.invalidate(InodeId(ino as u64));
        }
    }
}

/// (hits, misses) for the root mount's page cache.
/// # C: O(1)
pub fn cache_stats() -> (u64, u64) { root().map(|s| s.cache_stats()).unwrap_or((0, 0)) }

/// True iff the root ext4 mount is up.
/// # C: O(1)
pub fn mounted() -> bool { root().is_some() }

// ── Free-fn API: thin forwards to the ROOT state. Unchanged surface so
//    smoke/elf.rs, syscalls, etc. need no edits during the transition. ──

/// # C: O(path components × dir size)
pub fn lookup_path(path: &[u8]) -> Option<u32> { root()?.lookup_path(path) }
/// # C: O(N entries)
pub fn read_dir<F: FnMut(&[u8], u8)>(path: &[u8], f: F) -> Option<()> { root()?.read_dir(path, f) }
/// # C: O(file size)
pub fn read_file(path: &[u8]) -> Option<Vec<u8>> { root()?.read_file(path) }
/// # C: O(N_extents) + O(1) block I/O
pub fn write_file(path: &[u8], data: &[u8]) -> Option<()> { root()?.write_file(path, data) }
/// # C: O(path components)
pub fn lookup_inode_any(path: &[u8]) -> Option<vfs::InodeRef> { root()?.lookup_inode_any(path) }
/// # C: O(N_entries in dir)
pub fn lookup_child_ino(dir_ino: u32, name: &str) -> Option<u32> { root()?.lookup_child_ino(dir_ino, name) }
/// # C: O(1) inode read
pub fn wrap_any_ino(ino: u32) -> Option<vfs::InodeRef> { root()?.wrap_any_ino(ino) }
/// # C: O(path components × dir size)
pub fn stat_path(path: &[u8]) -> Option<(u32, vfs::FileType, u64)> { root()?.stat_path(path) }
/// # C: O(file size) on first call, O(log N) on cache hit
pub fn lookup_inode(path: &[u8]) -> Option<vfs::InodeRef> { root()?.lookup_inode(path) }
/// # C: O(N parent entries)
pub fn create_at(path: &[u8], mode_perm: u16) -> Option<vfs::InodeRef> { root()?.create_at(path, mode_perm) }
/// # C: O(1) inode alloc + 1 I/O
pub fn create_anonymous_at(dir_path: &[u8], mode_perm: u16) -> Option<vfs::InodeRef> {
    root()?.create_anonymous_at(dir_path, mode_perm)
}

/// # C: O(N_extents) block-free + 1 inode-free
pub fn free_orphan_inode(ino: u32) -> Result<(), vfs::VfsError> {
    root().ok_or(vfs::VfsError::Eio)?.free_orphan_inode(ino)
}
/// # C: O(N parent entries)
pub fn link_inode_at(ino: u32, link_path: &[u8]) -> Result<(), vfs::VfsError> {
    root().ok_or(vfs::VfsError::Eio)?.link_inode_at(ino, link_path)
}
/// # C: O(N parent entries) + (free blocks if last link)
pub fn unlink_at(path: &[u8]) -> Result<(), vfs::VfsError> {
    root().ok_or(vfs::VfsError::Eio)?.unlink_at(path)
}
/// # C: O(N parent entries)
pub fn symlink_at(target: &[u8], link_path: &[u8]) -> Result<(), vfs::VfsError> {
    root().ok_or(vfs::VfsError::Eio)?.symlink_at(target, link_path)
}
/// # C: O(N parent entries)
pub fn mknod_at(path: &[u8], mode: u16, rdev: u32) -> Result<(), vfs::VfsError> {
    root().ok_or(vfs::VfsError::Eio)?.mknod_at(path, mode, rdev)
}
/// # C: O(N parent entries)
pub fn mkdir_at(path: &[u8], mode_perm: u16) -> Result<(), vfs::VfsError> {
    root().ok_or(vfs::VfsError::Eio)?.mkdir_at(path, mode_perm)
}
/// # C: O(N parent entries)
pub fn rmdir_at(path: &[u8]) -> Result<(), vfs::VfsError> {
    root().ok_or(vfs::VfsError::Eio)?.rmdir_at(path)
}
/// # C: O(N parent entries)
pub fn link_at(target_path: &[u8], link_path: &[u8]) -> Result<(), vfs::VfsError> {
    root().ok_or(vfs::VfsError::Eio)?.link_at(target_path, link_path)
}
/// # C: O(1)
pub fn rename_at(from: &[u8], to: &[u8]) -> Result<(), vfs::VfsError> {
    root().ok_or(vfs::VfsError::Eio)?.rename_at(from, to)
}

/// FileSystem trait impl for the ROOT ext4 mount. Unit struct so kmain's
/// `Arc::new(Ext4RootfsFs)` and `Ext4RootfsFs.root()` keep compiling
/// unchanged; methods forward to the published root state.
pub struct Ext4RootfsFs;

impl vfs::fs::FileSystem for Ext4RootfsFs {
    fn name(&self) -> &str { "ext4" }
    /// EXT4_SUPER_MAGIC (linux/magic.h).
    fn magic(&self) -> u64 { crate::EXT4_SUPER_MAGIC as u64 }
    /// ext4 is block-device backed (Linux `FS_REQUIRES_DEV`). # C: O(1)
    fn fs_flags(&self) -> vfs::fs::FsFlags { vfs::fs::FsFlags::FS_REQUIRES_DEV }
    /// On-disk `s_blocksize` of the published root mount. # C: O(1)
    fn block_size(&self) -> u32 { root().map(|st| st.mount.sb.block_size).unwrap_or(4096) }
    /// Install live ext4 statfs accounting (root mount's state) as `s_op`.
    /// # C: O(1)
    fn super_ops(&self) -> Option<Arc<dyn vfs::SuperOps>> {
        root().map(|st| Arc::new(ops::Ext4SuperOps::new(st.clone())) as Arc<dyn vfs::SuperOps>)
    }
    /// ext4 root is always inode 2 (`docs/16§2`).
    fn root(&self) -> Option<vfs::InodeRef> { wrap_any_ino(2) }
    /// Back-stamp the SB into the published ROOT state so root-fs inodes'
    /// `i_sb()` resolves and `fsid()` reports `sb.s_dev`. # C: O(1)
    fn set_sb(&self, sb: alloc::sync::Weak<vfs::SuperBlock>) {
        if let Some(st) = root() { st.set_sb(sb); }
    }
    fn create(&self, path: &str, mode: u32) -> vfs::fs::KResult<vfs::InodeRef> {
        create_at(path.as_bytes(), mode as u16).ok_or(vfs::VfsError::Enoent)
    }
    fn create_anonymous(&self, dir: &str, mode: u32) -> vfs::fs::KResult<vfs::InodeRef> {
        create_anonymous_at(dir.as_bytes(), mode as u16).ok_or(vfs::VfsError::Enospc)
    }
    fn unlink(&self, path: &str) -> vfs::fs::KResult<()> { unlink_at(path.as_bytes()) }
    fn link(&self, target: &str, link: &str) -> vfs::fs::KResult<()> {
        link_at(target.as_bytes(), link.as_bytes())
    }
    fn link_inode(&self, inode: vfs::InodeRef, link: &str) -> vfs::fs::KResult<()> {
        let ino = inode::ext4_file_ino(&inode).ok_or(vfs::VfsError::Exdev)?;
        link_inode_at(ino, link.as_bytes())
    }
    fn rename(&self, from: &str, to: &str) -> vfs::fs::KResult<()> {
        rename_at(from.as_bytes(), to.as_bytes())
    }
}

/// Singleton accessor for the root FS.
/// # C: O(1)
pub fn instance() -> &'static dyn vfs::fs::FileSystem { &Ext4RootfsFs }
