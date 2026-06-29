// `struct Inode` per `16§2` — the CONCRETE in-core inode (Linux `struct
// inode`). Replaces the old ~53-method god-trait `Inode`: an inode is now
// shared STATE (the fields below) plus two behaviour vtables —
//   * `i_op`  ([`crate::inode_ops::InodeOps`]) = `inode_operations`
//             (lookup/create/mkdir/…/getattr/setattr/permission), and
//   * `i_fop` ([`crate::file_ops::FileOps`])   = `file_operations`
//             (read/write/iterate/poll/on_open/…).
// Backend-specific per-inode state lives behind `i_private: Arc<dyn Any>` (the
// old `as_any` downcast hook), so one shared `Arc<dyn InodeOps>` /
// `Arc<dyn FileOps>` serves every inode of a filesystem.
//
// The inherent methods below mirror the OLD trait method NAMES so call sites
// barely move: `ino()`/`file_type()`/`size()`/`perm()`/`lookup()`/`read()`/…
// resolve against the fields or delegate to `i_op`/`i_fop`.
//
// Lifecycle state that the trait-object model kept icache-side (Linux
// `i_state`/`__i_nlink`/`i_count`) now lives IN the struct (`i_state`,
// `i_nlink`, `i_count`), so `superblock.rs`'s icache is a pure `Weak<Inode>`
// map and `iget`/`iput` drive the refcount here.

extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::file_ops::FileOps;
use crate::inode_ops::InodeOps;
use crate::mapping::AddressSpaceOps;
use crate::poll_subs::PollSubscribers;
use crate::superblock::SuperBlock;
use crate::types::{FileType, Ino, KResult, Umode, VfsError, S_IFMT};

/// `struct inode` reference (Linux `struct inode *`). CONCRETE — one type for
/// every filesystem; behaviour comes from `i_op`/`i_fop`/`i_private`.
pub type InodeRef = Arc<Inode>;

/// `struct inode` (`16§2`). One per in-core inode; shared by every dentry alias
/// (hardlinks) and every open `File` on it.
pub struct Inode {
    /// `i_ino` — the inode number (Linux `inode->i_ino`).
    i_ino: Ino,
    /// `i_mode` — the full `umode_t`: `S_IFMT` type bits OR'd with the low-12
    /// perm/setid/sticky bits. `file_type()`/`perm()` derive from it.
    i_mode: AtomicU32,
    /// `i_size` — logical file size in bytes.
    i_size: AtomicU64,
    /// `i_blocks` — 512-byte blocks occupied (sparse-aware backends maintain it;
    /// `0` lets `generic_fillattr` estimate from `i_size`).
    i_blocks: AtomicU64,
    /// `__i_nlink` — hard-link count.
    i_nlink: AtomicU32,
    /// `i_uid` / `i_gid` — owner ids (fs-domain; the mount idmap maps them out).
    i_uid: AtomicU32,
    i_gid: AtomicU32,
    /// `i_flags` — the VFS `S_*` flag set (`S_IMMUTABLE`/`S_APPEND`/…), distinct
    /// from the `S_IF*`/perm bits in `i_mode`.
    i_flags: AtomicU32,
    /// `i_rdev` — packed `dev_t` for a char/block node (`0` otherwise).
    i_rdev: u32,
    /// `i_generation` — generation stamp (`name_to_handle_at`/NFS FID).
    i_generation: u32,
    /// `i_atime`/`i_mtime`/`i_ctime` (ns since epoch) + `i_btime` (birth; `0` =
    /// none).
    i_atime: AtomicU64,
    i_mtime: AtomicU64,
    i_ctime: AtomicU64,
    i_btime: u64,
    /// `i_state` — `I_NEW`/`I_DIRTY*`/`I_WILL_FREE`/`I_FREEING`/`I_CLEAR`.
    i_state: AtomicU32,
    /// `i_count` — the iget/iput reference count (Linux `inode->i_count`). A
    /// build-miss starts at 1; `igrab` bumps, `iput` drops; `0` → evict.
    i_count: AtomicU32,
    /// `i_version` — the NFS/IMA change cookie (raw word incl. the QUERIED flag).
    i_version: AtomicU64,
    /// `i_fsid` — the `st_dev` identity override; `0` = derive from `i_sb`.
    i_fsid: AtomicU64,
    /// `i_sb` — owning superblock backref (non-owning, Linux `d_sb`).
    i_sb: Weak<SuperBlock>,
    /// `i_mapping` — the per-inode `address_space` page cache, if any.
    i_mapping: Option<Arc<dyn AddressSpaceOps>>,
    /// `i_op` — the `inode_operations` vtable.
    i_op: Arc<dyn InodeOps>,
    /// `i_fop` — the `file_operations` vtable.
    i_fop: Arc<dyn FileOps>,
    /// Backend-private state (Linux `i_private` / the old `as_any` target).
    i_private: Arc<dyn Any + Send + Sync>,
    /// F181 per-inode epoll subscriber list for targeted wakes (`None` = global
    /// broadcast).
    poll_subs: Option<PollSubscribers>,
    /// memfd file-sealing word (`Some` only for a sealable memfd).
    seals: Option<AtomicU32>,
    /// `i_link` — inline fast-symlink body (Linux `inode->i_link`); `None` = no
    /// inline body, so `get_link` falls through to `i_op->readlink`.
    i_link: Option<Box<[u8]>>,
}

impl Inode {
    // ---- identity / metadata accessors (mirror the old trait names) --------

    /// `inode->i_ino`. # C: O(1)
    pub fn ino(&self) -> Ino { self.i_ino }

    /// `i_mode` umode_t view (`S_IFMT` | perm). # C: O(1)
    pub fn i_mode(&self) -> Umode { (self.i_mode.load(Ordering::Relaxed) & 0xFFFF) as Umode }

    /// File-type tag, derived from `i_mode & S_IFMT`. # C: O(1)
    pub fn file_type(&self) -> FileType { FileType::from_ifmt(self.i_mode()) }

    /// Permission bits (low 12 of `i_mode`). `Some` always — the concrete inode
    /// owns its mode (the old `None`-means-pseudo-fallback is obsolete). Kept
    /// `Option` so `generic_fillattr`/`generic_permission` call sites are
    /// unchanged. # C: O(1)
    pub fn perm(&self) -> Option<u16> { Some(self.i_mode() & 0o7777) }

    /// `i_size`. # C: O(1)
    pub fn size(&self) -> u64 { self.i_size.load(Ordering::Relaxed) }

    /// `__i_nlink`. # C: O(1)
    pub fn nlink(&self) -> u32 { self.i_nlink.load(Ordering::Relaxed) }

    /// `i_uid`. # C: O(1)
    pub fn uid(&self) -> Option<u32> { Some(self.i_uid.load(Ordering::Relaxed)) }

    /// `i_gid`. # C: O(1)
    pub fn gid(&self) -> Option<u32> { Some(self.i_gid.load(Ordering::Relaxed)) }

    /// `i_atime` (ns). # C: O(1)
    pub fn atime(&self) -> Option<u64> { Some(self.i_atime.load(Ordering::Relaxed)) }
    /// `i_mtime` (ns). # C: O(1)
    pub fn mtime(&self) -> Option<u64> { Some(self.i_mtime.load(Ordering::Relaxed)) }
    /// `i_ctime` (ns). # C: O(1)
    pub fn ctime(&self) -> Option<u64> { Some(self.i_ctime.load(Ordering::Relaxed)) }
    /// `i_btime` — `None` when unset (`0`), so `STATX_BTIME` stays clear. # C: O(1)
    pub fn btime(&self) -> Option<u64> { if self.i_btime != 0 { Some(self.i_btime) } else { None } }

    /// `i_flags` (`S_*`). # C: O(1)
    pub fn i_flags(&self) -> u32 { self.i_flags.load(Ordering::Relaxed) }

    /// `i_rdev` packed `dev_t`. # C: O(1)
    pub fn rdev(&self) -> u32 { self.i_rdev }

    /// `i_generation`. # C: O(1)
    pub fn i_generation(&self) -> u32 { self.i_generation }

    /// `i_sb` — owning superblock (if still live). # C: O(1)
    pub fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.i_sb.upgrade() }

    /// Superblock/mount identity (`st_dev`). `i_fsid` override, else `i_sb`'s
    /// `s_dev`, else 0. # C: O(1)
    pub fn fsid(&self) -> u64 {
        let f = self.i_fsid.load(Ordering::Relaxed);
        if f != 0 { f } else { self.i_sb().map(|s| s.s_dev).unwrap_or(0) }
    }

    /// Filesystem magic for `fstatfs` on a pathless/anon inode (`s_magic` of the
    /// owning SB, else 0). # C: O(1)
    pub fn statfs_magic(&self) -> u64 { self.i_sb().map(|s| s.s_magic).unwrap_or(0) }

    /// Preferred I/O block size (`s_blocksize`, else 4096). # C: O(1)
    pub fn blksize(&self) -> u32 { self.i_sb().map(|s| s.s_blocksize).unwrap_or(4096) }

    /// `i_mapping` — the per-inode page cache, if any. # C: O(1)
    pub fn i_mapping(&self) -> Option<&dyn AddressSpaceOps> { self.i_mapping.as_deref() }

    /// `i_private` — the backend-private state `Arc` (Linux `i_private`). # C: O(1)
    pub fn i_private(&self) -> &Arc<dyn Any + Send + Sync> { &self.i_private }

    /// Downcast `i_private` to a concrete backend state type (the old `as_any`
    /// recovery, e.g. POSIX-MQ pulling `MqQueue` out of an `MqInode`). # C: O(1)
    pub fn private<T: Any + Send + Sync>(&self) -> Option<&T> { self.i_private.downcast_ref::<T>() }

    /// F181 per-inode epoll subscribers (`None` = global broadcast). # C: O(1)
    pub fn poll_subscribers(&self) -> Option<&PollSubscribers> { self.poll_subs.as_ref() }

    /// memfd seal word (`Some` only for a sealable memfd). # C: O(1)
    pub fn fcntl_seals(&self) -> Option<&AtomicU32> { self.seals.as_ref() }

    /// `i_version` raw word — always present on the concrete inode. # C: O(1)
    pub fn i_version_raw(&self) -> Option<&AtomicU64> { Some(&self.i_version) }

    /// `i_link` — inline fast-symlink body. # C: O(1)
    pub fn i_link(&self) -> Option<&[u8]> { self.i_link.as_deref() }

    /// The `i_op` vtable. # C: O(1)
    pub fn i_op(&self) -> &Arc<dyn InodeOps> { &self.i_op }
    /// The `i_fop` vtable. # C: O(1)
    pub fn i_fop(&self) -> &Arc<dyn FileOps> { &self.i_fop }

    // ---- metadata mutators (write the concrete fields) ---------------------

    /// Set `i_size` (Linux `i_size_write`). # C: O(1)
    pub fn set_size(&self, size: u64) { self.i_size.store(size, Ordering::Relaxed); }
    /// Set `i_blocks`. # C: O(1)
    pub fn set_blocks(&self, blocks: u64) { self.i_blocks.store(blocks, Ordering::Relaxed); }
    /// `i_blocks` (512-byte units; `0` = estimate from size). # C: O(1)
    pub fn blocks(&self) -> u64 { self.i_blocks.load(Ordering::Relaxed) }
    /// Set `i_flags` (`S_*`). # C: O(1)
    pub fn set_i_flags(&self, flags: u32) { self.i_flags.store(flags, Ordering::Relaxed); }

    /// `chmod` field write — replace the perm bits, preserving `S_IFMT`. # C: O(1)
    pub fn set_perm(&self, perm: u16) -> KResult<()> {
        let ifmt = self.i_mode.load(Ordering::Relaxed) & (S_IFMT as u32);
        self.i_mode.store(ifmt | (perm as u32 & 0o7777), Ordering::Relaxed);
        Ok(())
    }

    /// `chown` field write. # C: O(1)
    pub fn set_owner(&self, uid: u32, gid: u32) -> KResult<()> {
        self.i_uid.store(uid, Ordering::Relaxed);
        self.i_gid.store(gid, Ordering::Relaxed);
        Ok(())
    }

    /// utimes field write. `None` = leave alone (UTIME_OMIT). `ctime` is always
    /// stamped. # C: O(1)
    pub fn set_times(&self, atime: Option<u64>, mtime: Option<u64>, ctime: u64) -> KResult<()> {
        if let Some(a) = atime { self.i_atime.store(a, Ordering::Relaxed); }
        if let Some(m) = mtime { self.i_mtime.store(m, Ordering::Relaxed); }
        self.i_ctime.store(ctime, Ordering::Relaxed);
        Ok(())
    }

    // ---- refcount + lifecycle state (Linux i_count / i_state / __i_nlink) ---

    /// `igrab` — take one extra `i_count` reference. # C: O(1)
    pub fn igrab(&self) { self.i_count.fetch_add(1, Ordering::AcqRel); }
    /// `i_count` snapshot. # C: O(1)
    pub fn i_count(&self) -> u32 { self.i_count.load(Ordering::Acquire) }
    /// Drop one `i_count`; returns the PRIOR value (1 ⇒ caller drops the last
    /// reference and must evict). # C: O(1)
    pub fn i_count_dec(&self) -> u32 { self.i_count.fetch_sub(1, Ordering::AcqRel) }

    /// `i_state` snapshot. # C: O(1)
    pub fn i_state(&self) -> u32 { self.i_state.load(Ordering::Acquire) }
    /// Set/clear `i_state` bits. # C: O(1)
    pub fn set_state(&self, set: u32, clear: u32) {
        let mut cur = self.i_state.load(Ordering::Acquire);
        loop {
            let new = (cur & !clear) | set;
            match self.i_state.compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break, Err(v) => cur = v,
            }
        }
    }
    /// True iff being evicted (`I_FREEING|I_WILL_FREE`). # C: O(1)
    pub fn is_freeing(&self) -> bool { self.i_state() & (I_FREEING | I_WILL_FREE) != 0 }

    /// `set_nlink`. # C: O(1)
    pub fn set_nlink(&self, n: u32) { self.i_nlink.store(n, Ordering::Relaxed); }
    /// `inc_nlink` (saturating). # C: O(1)
    pub fn inc_nlink(&self) { let _ = self.i_nlink.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| Some(n.saturating_add(1))); }
    /// `drop_nlink` (saturating at 0). # C: O(1)
    pub fn drop_nlink(&self) { let _ = self.i_nlink.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| Some(n.saturating_sub(1))); }

    // ---- i_op delegators (namespace + metadata) ----------------------------

    /// `i_op->lookup`. # C: backend-dependent
    pub fn lookup(&self, name: &str) -> KResult<InodeRef> { self.i_op.lookup(self, name) }
    /// `i_op->create`. # C: backend-dependent
    pub fn create_child(&self, name: &str, mode: u32) -> KResult<InodeRef> { self.i_op.create(self, name, mode) }
    /// `i_op->mkdir`. # C: backend-dependent
    pub fn mkdir(&self, name: &str, mode: u32) -> KResult<InodeRef> { self.i_op.mkdir(self, name, mode) }
    /// `i_op->rmdir`. # C: backend-dependent
    pub fn rmdir(&self, name: &str) -> KResult<()> { self.i_op.rmdir(self, name) }
    /// `i_op->unlink`. # C: backend-dependent
    pub fn unlink_child(&self, name: &str) -> KResult<()> { self.i_op.unlink(self, name) }
    /// `i_op->symlink`. # C: backend-dependent
    pub fn symlink_child(&self, name: &str, target: &[u8]) -> KResult<()> { self.i_op.symlink(self, name, target) }
    /// `i_op->mknod`. # C: backend-dependent
    pub fn mknod_child(&self, name: &str, mode: u16, rdev: u32) -> KResult<()> { self.i_op.mknod(self, name, mode, rdev) }
    /// `i_op->link`. # C: backend-dependent
    pub fn link_child(&self, target: &InodeRef, name: &str) -> KResult<()> { self.i_op.link(self, target, name) }
    /// `i_op->rename`. # C: backend-dependent
    pub fn rename_child(&self, old: &str, new_dir: &Inode, new: &str, flags: u32) -> KResult<()> {
        self.i_op.rename(self, old, new_dir, new, flags)
    }

    /// `i_op->readlink` (the storage primitive). # C: O(target_len)
    pub fn readlink(&self) -> KResult<Vec<u8>> { self.i_op.readlink(self) }

    /// `i_op->get_link` (Linux) — the inline `i_link` fast path FIRST, else the
    /// per-inode `readlink`. # C: O(target_len)
    pub fn get_link(&self) -> KResult<Vec<u8>> {
        if let Some(l) = self.i_link() { return Ok(l.to_vec()); }
        self.readlink()
    }

    /// `i_op->truncate`. # C: backend-dependent
    pub fn truncate(&self, len: u64) -> KResult<()> { self.i_op.truncate(self, len) }
    /// `i_op->fallocate`. # C: backend-dependent
    pub fn fallocate(&self, off: u64, len: u64, keep_size: bool, zero_range: bool) -> KResult<()> {
        self.i_op.fallocate(self, off, len, keep_size, zero_range)
    }
    /// `i_op->fiemap`. # C: O(extents)
    pub fn fiemap(&self, start: u64, len: u64, emit: &mut dyn FnMut(FiemapExtent) -> bool) -> KResult<()> {
        self.i_op.fiemap(self, start, len, emit)
    }
    /// `bmap`. # C: O(1) amortized
    pub fn bmap(&self, block: u64) -> KResult<u64> { self.i_op.bmap(self, block) }
    /// `i_op->fileattr_get`. # C: O(1)
    pub fn fileattr_get(&self) -> KResult<FileAttr> { self.i_op.fileattr_get(self) }
    /// `i_op->fileattr_set`. # C: O(1)
    pub fn fileattr_set(&self, fa: &FileAttr) -> KResult<()> { self.i_op.fileattr_set(self, fa) }

    /// `i_op->permission`. # C: O(ngroups)
    pub fn permission(&self, mask: u32, cred: &crate::namei::Cred) -> KResult<()> {
        self.i_op.permission(self, mask, cred)
    }
    /// `i_op->getattr`. # C: O(1)
    pub fn getattr(&self, idmap: &crate::idmap::Idmap, overlay: Option<crate::inode_times::InodeTimes>)
        -> crate::getattr::Kstat { self.i_op.getattr(self, idmap, overlay) }
    /// `i_op->setattr`. # C: O(1)
    pub fn setattr(&self, idmap: &crate::idmap::Idmap, ia: &crate::setattr::Iattr) -> KResult<()> {
        self.i_op.setattr(self, idmap, ia)
    }

    // ---- i_fop delegators (data path) --------------------------------------

    /// `f_op->read`. # C: backend-dependent
    pub fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> { self.i_fop.read(self, off, buf) }
    /// `f_op->write`. # C: backend-dependent
    pub fn write(&self, off: u64, buf: &[u8]) -> KResult<usize> { self.i_fop.write(self, off, buf) }
    /// Non-blocking read. # C: backend-dependent
    pub fn read_nonblock(&self, off: u64, buf: &mut [u8]) -> KResult<usize> { self.i_fop.read_nonblock(self, off, buf) }
    /// Non-blocking write. # C: backend-dependent
    pub fn write_nonblock(&self, off: u64, buf: &[u8]) -> KResult<usize> { self.i_fop.write_nonblock(self, off, buf) }
    /// `f_op->iterate`/readdir. # C: backend-dependent
    pub fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        self.i_fop.iterate(self, off, f)
    }
    /// `f_op->poll`. # C: O(1)
    pub fn poll(&self) -> u32 { self.i_fop.poll(self) }
    /// Position-aware poll. # C: O(1)
    pub fn poll_file(&self, pos: u64) -> u32 { self.i_fop.poll_file(self, pos) }
    /// `MAP_SHARED` cache frame. # C: O(log N_pages)
    pub fn mmap_shared_frame(&self, off: u64) -> Option<u64> { self.i_fop.mmap_shared_frame(self, off) }
    /// `f_op->open` hook. # C: O(1)
    pub fn on_open(&self) -> KResult<()> { self.i_fop.on_open(self) }
    /// `f_op->release` hook. # C: O(1)
    pub fn on_release(&self) { self.i_fop.on_release(self) }
    /// `f_op->flush` hook. # C: O(1)
    pub fn on_flush(&self) { self.i_fop.on_flush(self) }
    /// `show_fdinfo` extra lines. # C: O(1)
    pub fn fdinfo_extra(&self, out: &mut Vec<u8>) { self.i_fop.fdinfo_extra(self, out) }
}

/// Builder for [`Inode`] — the one constructor every `make_*_inode` /
/// `iget`-build closure funnels through. Set the type/mode + ops, chain the
/// optional fields, then `.build()` into an `Arc<Inode>`.
pub struct InodeBuilder {
    ino: Ino,
    mode: u32,
    i_op: Arc<dyn InodeOps>,
    i_fop: Arc<dyn FileOps>,
    sb: Weak<SuperBlock>,
    size: u64,
    blocks: u64,
    nlink: Option<u32>,
    uid: u32,
    gid: u32,
    flags: u32,
    rdev: u32,
    generation: u32,
    fsid: u64,
    atime: u64,
    mtime: u64,
    ctime: u64,
    btime: u64,
    version: u64,
    mapping: Option<Arc<dyn AddressSpaceOps>>,
    private: Arc<dyn Any + Send + Sync>,
    poll_subs: Option<PollSubscribers>,
    seals: Option<u32>,
    link: Option<Box<[u8]>>,
}

impl InodeBuilder {
    /// Start a build with the inode number, full `umode_t`, and the two vtables.
    /// # C: O(1)
    pub fn new(ino: Ino, mode: u32, i_op: Arc<dyn InodeOps>, i_fop: Arc<dyn FileOps>) -> Self {
        InodeBuilder {
            ino, mode, i_op, i_fop, sb: Weak::new(),
            size: 0, blocks: 0, nlink: None, uid: 0, gid: 0, flags: 0, rdev: 0,
            generation: 0, fsid: 0, atime: 0, mtime: 0, ctime: 0, btime: 0, version: 0,
            mapping: None, private: Arc::new(()), poll_subs: None, seals: None, link: None,
        }
    }
    /// Set `i_sb`. # C: O(1)
    pub fn sb(mut self, sb: Weak<SuperBlock>) -> Self { self.sb = sb; self }
    /// Set `i_size`. # C: O(1)
    pub fn size(mut self, n: u64) -> Self { self.size = n; self }
    /// Set `i_blocks`. # C: O(1)
    pub fn blocks(mut self, n: u64) -> Self { self.blocks = n; self }
    /// Set `__i_nlink` (default: 2 for a directory, else 1). # C: O(1)
    pub fn nlink(mut self, n: u32) -> Self { self.nlink = Some(n); self }
    /// Set `i_uid`/`i_gid`. # C: O(1)
    pub fn owner(mut self, uid: u32, gid: u32) -> Self { self.uid = uid; self.gid = gid; self }
    /// Set `i_flags` (`S_*`). # C: O(1)
    pub fn i_flags(mut self, f: u32) -> Self { self.flags = f; self }
    /// Set `i_rdev`. # C: O(1)
    pub fn rdev(mut self, d: u32) -> Self { self.rdev = d; self }
    /// Set `i_generation`. # C: O(1)
    pub fn generation(mut self, g: u32) -> Self { self.generation = g; self }
    /// Set the `st_dev` override (`i_fsid`). # C: O(1)
    pub fn fsid(mut self, f: u64) -> Self { self.fsid = f; self }
    /// Set atime/mtime/ctime (ns). # C: O(1)
    pub fn times(mut self, a: u64, m: u64, c: u64) -> Self { self.atime = a; self.mtime = m; self.ctime = c; self }
    /// Set the birth time (`STATX_BTIME`). # C: O(1)
    pub fn btime(mut self, b: u64) -> Self { self.btime = b; self }
    /// Seed the raw `i_version` word. # C: O(1)
    pub fn version(mut self, v: u64) -> Self { self.version = v; self }
    /// Attach the per-inode `address_space`. # C: O(1)
    pub fn mapping(mut self, m: Arc<dyn AddressSpaceOps>) -> Self { self.mapping = Some(m); self }
    /// Attach backend-private state (`i_private`). # C: O(1)
    pub fn private(mut self, p: Arc<dyn Any + Send + Sync>) -> Self { self.private = p; self }
    /// Attach a per-inode epoll subscriber list. # C: O(1)
    pub fn poll_subs(mut self, p: PollSubscribers) -> Self { self.poll_subs = Some(p); self }
    /// Enable memfd sealing with an initial seal word. # C: O(1)
    pub fn seals(mut self, initial: u32) -> Self { self.seals = Some(initial); self }
    /// Set the inline fast-symlink body (`i_link`). # C: O(1)
    pub fn link(mut self, body: Box<[u8]>) -> Self { self.link = Some(body); self }

    /// Finish: produce the `Arc<Inode>` with `i_count == 1` and `I_NEW` clear.
    /// # C: O(1)
    pub fn build(self) -> Arc<Inode> {
        let nlink = self.nlink.unwrap_or_else(|| default_nlink(self.mode));
        Arc::new(Inode {
            i_ino: self.ino,
            i_mode: AtomicU32::new(self.mode),
            i_size: AtomicU64::new(self.size),
            i_blocks: AtomicU64::new(self.blocks),
            i_nlink: AtomicU32::new(nlink),
            i_uid: AtomicU32::new(self.uid),
            i_gid: AtomicU32::new(self.gid),
            i_flags: AtomicU32::new(self.flags),
            i_rdev: self.rdev,
            i_generation: self.generation,
            i_atime: AtomicU64::new(self.atime),
            i_mtime: AtomicU64::new(self.mtime),
            i_ctime: AtomicU64::new(self.ctime),
            i_btime: self.btime,
            i_state: AtomicU32::new(0),
            i_count: AtomicU32::new(1),
            i_version: AtomicU64::new(self.version),
            i_fsid: AtomicU64::new(self.fsid),
            i_sb: self.sb,
            i_mapping: self.mapping,
            i_op: self.i_op,
            i_fop: self.i_fop,
            i_private: self.private,
            poll_subs: self.poll_subs,
            seals: self.seals.map(AtomicU32::new),
            i_link: self.link,
        })
    }
}

/// Default `__i_nlink` for a fresh inode given its `umode_t`: an empty directory
/// has `.`+parent (2), any other type 1 (Linux baseline). # C: O(1)
fn default_nlink(mode: u32) -> u32 {
    if (mode as u16 & S_IFMT) == crate::types::S_IFDIR { 2 } else { 1 }
}

/// One physical extent reported by `Inode::fiemap` (Linux `struct
/// fiemap_extent`). Byte offsets/lengths, not blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FiemapExtent {
    /// `fe_logical` — byte offset within the file.
    pub logical: u64,
    /// `fe_physical` — byte offset on the device.
    pub physical: u64,
    /// `fe_length` — byte length.
    pub length: u64,
    /// `fe_flags` — `FIEMAP_EXTENT_*`.
    pub flags: u32,
}

/// Inode attribute view shared by `fileattr_get`/`fileattr_set` (Linux `struct
/// fileattr`). Carries both the legacy `FS_*_FL` word and the `xflags`/projid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FileAttr {
    /// `FS_IOC_GETFLAGS` `FS_*_FL` word.
    pub flags: u32,
    /// `FS_IOC_FSGETXATTR` `fsx_xflags`.
    pub fsx_xflags: u32,
    /// `FS_IOC_FSGETXATTR` `fsx_projid`.
    pub fsx_projid: u32,
}

impl FileAttr {
    /// Translate the VFS `i_flags` (`S_*`) word into the `FS_*_FL` view. # C: O(1)
    pub fn from_i_flags(i_flags: u32) -> Self {
        let mut flags = 0;
        if i_flags & S_IMMUTABLE != 0 { flags |= FS_IMMUTABLE_FL; }
        if i_flags & S_APPEND    != 0 { flags |= FS_APPEND_FL; }
        if i_flags & S_NOATIME   != 0 { flags |= FS_NOATIME_FL; }
        if i_flags & S_SYNC      != 0 { flags |= FS_SYNC_FL; }
        FileAttr { flags, fsx_xflags: 0, fsx_projid: 0 }
    }
}

/// `FIEMAP_EXTENT_*` flags (Linux `include/uapi/linux/fiemap.h`).
pub const FIEMAP_EXTENT_LAST:           u32 = 0x0001;
pub const FIEMAP_EXTENT_UNKNOWN:        u32 = 0x0002;
pub const FIEMAP_EXTENT_DELALLOC:       u32 = 0x0004;
pub const FIEMAP_EXTENT_ENCODED:        u32 = 0x0008;
pub const FIEMAP_EXTENT_DATA_ENCRYPTED: u32 = 0x0080;
pub const FIEMAP_EXTENT_NOT_ALIGNED:    u32 = 0x0100;
pub const FIEMAP_EXTENT_DATA_INLINE:    u32 = 0x0200;
pub const FIEMAP_EXTENT_UNWRITTEN:      u32 = 0x0800;
pub const FIEMAP_EXTENT_MERGED:         u32 = 0x1000;
pub const FIEMAP_EXTENT_SHARED:         u32 = 0x2000;

/// `FS_*_FL` inode flags (Linux `include/uapi/linux/fs.h`).
pub const FS_SECRM_FL:     u32 = 0x0000_0001;
pub const FS_UNRM_FL:      u32 = 0x0000_0002;
pub const FS_COMPR_FL:     u32 = 0x0000_0004;
pub const FS_SYNC_FL:      u32 = 0x0000_0008;
pub const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
pub const FS_APPEND_FL:    u32 = 0x0000_0020;
pub const FS_NODUMP_FL:    u32 = 0x0000_0040;
pub const FS_NOATIME_FL:   u32 = 0x0000_0080;

/// `get_next_ino` (Linux `fs/inode.c`) — process-wide anon-inode allocator;
/// monotone `u32`, never `0`. # C: O(1)
pub fn get_next_ino() -> u32 {
    use core::sync::atomic::AtomicU32;
    static LAST_INO: AtomicU32 = AtomicU32::new(0);
    loop {
        let next = LAST_INO.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        if next != 0 { return next; }
    }
}

/// `IS_IMMUTABLE` — the inode carries `S_IMMUTABLE`. # C: O(1)
pub fn is_immutable(inode: &Inode) -> bool { inode.i_flags() & S_IMMUTABLE != 0 }
/// `IS_APPEND` — the inode carries `S_APPEND`. # C: O(1)
pub fn is_append(inode: &Inode) -> bool { inode.i_flags() & S_APPEND != 0 }
/// `IS_NOATIME` — the inode carries `S_NOATIME`. # C: O(1)
pub fn is_noatime(inode: &Inode) -> bool { inode.i_flags() & S_NOATIME != 0 }
/// `IS_SYNC` (inode portion) — the inode carries `S_SYNC`. # C: O(1)
pub fn is_sync(inode: &Inode) -> bool { inode.i_flags() & S_SYNC != 0 }

/// `i_version` lazy-counter bit layout (Linux `include/linux/iversion.h`).
pub const I_VERSION_QUERIED_SHIFT: u32 = 1;
pub const I_VERSION_QUERIED:       u64 = 1 << (I_VERSION_QUERIED_SHIFT - 1);
pub const I_VERSION_INCREMENT:     u64 = 1 << I_VERSION_QUERIED_SHIFT;

/// `inode_peek_iversion_raw` (Linux). # C: O(1)
pub fn inode_peek_iversion_raw(inode: &Inode) -> u64 {
    match inode.i_version_raw() { Some(v) => v.load(Ordering::Relaxed), None => 0 }
}

/// `inode_set_iversion_raw` (Linux). # C: O(1)
pub fn inode_set_iversion_raw(inode: &Inode, val: u64) {
    if let Some(v) = inode.i_version_raw() { v.store(val, Ordering::Relaxed); }
}

/// `inode_maybe_inc_iversion` (Linux) — lazy NFS-friendly bump. # C: O(1) amortized
pub fn inode_maybe_inc_iversion(inode: &Inode, force: bool) -> bool {
    let store = match inode.i_version_raw() { Some(v) => v, None => return false };
    let mut cur = store.load(Ordering::Relaxed);
    loop {
        if !force && (cur & I_VERSION_QUERIED) == 0 { return false; }
        let new = (cur & !I_VERSION_QUERIED) + I_VERSION_INCREMENT;
        match store.compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return true, Err(actual) => cur = actual,
        }
    }
}

/// `inode_inc_iversion` (Linux). # C: O(1) amortized
pub fn inode_inc_iversion(inode: &Inode) { inode_maybe_inc_iversion(inode, true); }

/// `inode_query_iversion` (Linux) — read + latch the QUERIED flag. # C: O(1) amortized
pub fn inode_query_iversion(inode: &Inode) -> u64 {
    let store = match inode.i_version_raw() { Some(v) => v, None => return 0 };
    let mut cur = store.load(Ordering::Relaxed);
    loop {
        if (cur & I_VERSION_QUERIED) != 0 { break; }
        let new = cur | I_VERSION_QUERIED;
        match store.compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => break, Err(actual) => cur = actual,
        }
    }
    cur >> I_VERSION_QUERIED_SHIFT
}

/// `inode_owner_or_capable` (Linux `fs/inode.c`) — owner-or-`CAP_FOWNER`,
/// idmap-aware. # C: O(extents)
pub fn inode_owner_or_capable(idmap: &crate::idmap::Idmap, inode: &Inode, cred: &crate::namei::Cred) -> bool {
    let vfsuid = idmap.map_out_uid(inode.uid().unwrap_or(0));
    if vfsuid == cred.uid { return true; }
    cred.cap_fowner && vfsuid != crate::idmap::INVALID_ID
}

/// `inode_init_owner` (Linux `fs/inode.c`) — owner ids + finalized mode for a
/// NEWLY created inode under directory `dir` (SGID inheritance + strip rules).
/// Returns `(i_uid, i_gid, i_mode)`. # C: O(ngroups)
pub fn inode_init_owner(dir: &Inode, mode: crate::types::Umode, cred: &crate::namei::Cred)
    -> (u32, u32, crate::types::Umode) {
    let uid = cred.uid;
    let mut m = mode;
    let gid = if dir.i_mode() & crate::namei::S_ISGID != 0 {
        let dgid = dir.gid().unwrap_or(0);
        if m & crate::types::S_IFMT == crate::types::S_IFDIR {
            m |= crate::namei::S_ISGID;
        } else if m & (crate::namei::S_ISGID | crate::namei::S_IXGRP)
            == crate::namei::S_ISGID | crate::namei::S_IXGRP
            && !cred.in_group(dgid) && !cred.cap_fsetid {
            m &= !crate::namei::S_ISGID;
        }
        dgid
    } else { cred.gid };
    (uid, gid, m)
}

/// errno for a default (no-data-op) `read`/`write` keyed on `S_IFMT`: directory
/// → `Eisdir` (Linux `generic_read_dir`), else `Einval` (Linux `vfs_read`/
/// `vfs_write` with no op). # C: O(1)
pub(crate) fn no_data_op_errno(ft: FileType) -> VfsError {
    match ft { FileType::Directory => VfsError::Eisdir, _ => VfsError::Einval }
}

/// `i_state` bits (Linux `include/linux/fs.h`). Now stored in `Inode::i_state`.
pub const I_DIRTY_SYNC:     u32 = 1 << 0;
pub const I_DIRTY_DATASYNC: u32 = 1 << 1;
pub const I_DIRTY_PAGES:    u32 = 1 << 2;
pub const I_NEW:            u32 = 1 << 3;
pub const I_WILL_FREE:      u32 = 1 << 4;
pub const I_FREEING:        u32 = 1 << 5;
pub const I_CLEAR:          u32 = 1 << 6;
/// `I_DIRTY` aggregate.
pub const I_DIRTY: u32 = I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES;

/// `i_flags` `S_*` bits (Linux `include/linux/fs.h`) — the VFS inode flag set.
pub const S_SYNC:      u32 = 1 << 0;
pub const S_NOATIME:   u32 = 1 << 1;
pub const S_APPEND:    u32 = 1 << 2;
pub const S_IMMUTABLE: u32 = 1 << 3;
pub const S_DEAD:      u32 = 1 << 4;
pub const S_DIRSYNC:   u32 = 1 << 6;
pub const S_DAX:       u32 = 1 << 13;
pub const S_ENCRYPTED: u32 = 1 << 14;
pub const S_CASEFOLD:  u32 = 1 << 15;
pub const S_VERITY:    u32 = 1 << 16;

/// `poll(2)` event bitmasks. Numeric reps match Linux exactly.
pub const POLL_IN:    u32 = 0x0001;
pub const POLL_OUT:   u32 = 0x0004;
pub const POLL_HUP:   u32 = 0x0010;
pub const POLL_ERR:   u32 = 0x0008;
pub const POLL_PRI:   u32 = 0x0002;
pub const POLL_RDHUP: u32 = 0x2000;
