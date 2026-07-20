extern crate alloc;

use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::file_ops::FileOps;
use crate::inode_ops::InodeOps;
use crate::mapping::AddressSpaceOps;
use crate::poll_subs::PollSubscribers;
use crate::superblock::SuperBlock;
use crate::types::{FileType, KResult, Umode, S_IFMT};

use super::flags::{I_FREEING, I_WILL_FREE};
use super::model::{Inode, SealCarrier};

/// oxide-internal `i_flags` bit: a shared-across-namespaces public device node
/// whose owner/mode is held at its universal-access as-created value (see
/// [`Inode::mark_public_device`]). High bit to avoid the Linux `S_*` runtime
/// flags in the low range.
const I_PUBLIC_DEV: u32 = 1 << 28;

impl Inode {
    /// Canonical inode-owned advisory-lock context (`inode->i_flctx`). # C: O(1)
    pub fn file_lock_context(&self) -> &super::file_lock::FileLockContext { &self.i_flctx }

    /// `inode->i_ino`. # C: O(1)
    pub fn ino(&self) -> crate::types::Ino { self.i_ino }
    /// `i_mode` umode_t view (`S_IFMT` | perm). # C: O(1)
    pub fn i_mode(&self) -> Umode { (self.i_mode.load(Ordering::Relaxed) & 0xFFFF) as Umode }
    /// File-type tag, derived from `i_mode & S_IFMT`. # C: O(1)
    pub fn file_type(&self) -> FileType { FileType::from_ifmt(self.i_mode()) }
    /// Permission bits. # C: O(1)
    pub fn perm(&self) -> Option<u16> { Some(self.i_mode() & 0o7777) }
    /// `i_size`. # C: O(1)
    pub fn size(&self) -> u64 { self.i_size.load(Ordering::Relaxed) }
    /// `__i_nlink`. # C: O(1)
    pub fn nlink(&self) -> u32 { self.i_nlink.load(Ordering::Relaxed) }
    /// `i_uid`. # C: O(1)
    pub fn uid(&self) -> Option<u32> { Some(self.i_uid.load(Ordering::Relaxed)) }
    /// `i_gid`. # C: O(1)
    pub fn gid(&self) -> Option<u32> { Some(self.i_gid.load(Ordering::Relaxed)) }
    /// `i_projid`. # C: O(1)
    pub fn projid(&self) -> u32 { self.i_projid.load(Ordering::Relaxed) }
    /// `i_atime` (ns). # C: O(1)
    pub fn atime(&self) -> Option<u64> { Some(self.i_atime.load(Ordering::Relaxed)) }
    /// `i_mtime` (ns). # C: O(1)
    pub fn mtime(&self) -> Option<u64> { Some(self.i_mtime.load(Ordering::Relaxed)) }
    /// `i_ctime` (ns). # C: O(1)
    pub fn ctime(&self) -> Option<u64> { Some(self.i_ctime.load(Ordering::Relaxed)) }
    /// `i_btime`. # C: O(1)
    pub fn btime(&self) -> Option<u64> { if self.i_btime != 0 { Some(self.i_btime) } else { None } }
    /// `i_flags` (`S_*`). # C: O(1)
    pub fn i_flags(&self) -> u32 { self.i_flags.load(Ordering::Relaxed) }
    /// Mark this inode a kernel-provided PUBLIC device node (/dev/null, /dev/zero,
    /// /dev/full, /dev/random, /dev/urandom). oxide backs each of these with ONE
    /// shared inode across every mount namespace (Linux gives each private `/dev`
    /// its own copy). systemd resets device-node ownership per session/service via
    /// `fchownat(fd,"",AT_EMPTY_PATH)`; on the shared node the LAST chown would
    /// strip world-access and lock out every other process (the greeter, whose uid
    /// != the last chowner, then fails glib's "open /dev/null to remap fd" with
    /// EACCES). `notify_change` keeps these nodes at their as-created world-rw
    /// mode + root owner — the universal-access invariant they always hold on
    /// Linux. # C: O(1)
    pub fn mark_public_device(&self) { self.i_flags.fetch_or(I_PUBLIC_DEV, Ordering::Relaxed); }
    /// True iff [`mark_public_device`] was set. # C: O(1)
    pub fn is_public_device(&self) -> bool { self.i_flags.load(Ordering::Relaxed) & I_PUBLIC_DEV != 0 }
    /// `i_rdev` packed `dev_t`. # C: O(1)
    pub fn rdev(&self) -> u32 { self.i_rdev }
    /// `i_generation`. # C: O(1)
    pub fn i_generation(&self) -> u32 { self.i_generation }
    /// `i_sb` — owning superblock (if still live). # C: O(1)
    pub fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.i_sb.upgrade() }
    /// Superblock/mount identity (`st_dev`). # C: O(1)
    pub fn fsid(&self) -> u64 {
        let f = self.i_fsid.load(Ordering::Relaxed);
        if f != 0 { f } else { self.i_sb().map(|s| s.s_dev).unwrap_or(0) }
    }
    /// Set the `i_fsid` override (`st_dev`). # C: O(1)
    pub fn set_fsid(&self, f: u64) { self.i_fsid.store(f, Ordering::Release); }
    /// Filesystem magic for `fstatfs`. # C: O(1)
    pub fn statfs_magic(&self) -> u64 { self.i_sb().map(|s| s.s_magic).unwrap_or(0) }
    /// Preferred I/O block size. # C: O(1)
    pub fn blksize(&self) -> u32 { self.i_sb().map(|s| s.s_blocksize).unwrap_or(4096) }
    /// `i_mapping` — the per-inode page cache. # C: O(1)
    pub fn i_mapping(&self) -> Option<&dyn AddressSpaceOps> { self.i_mapping.as_deref() }
    /// Canonical file reverse-map owner (`address_space->i_mmap`). # C: O(1)
    pub fn file_rmap(&self) -> Arc<vmm::FileRmap> { Arc::clone(&self.i_file_rmap) }
    /// `i_private` — backend-private state. # C: O(1)
    pub fn i_private(&self) -> &Arc<dyn Any + Send + Sync> { &self.i_private }
    /// Downcast `i_private` to a concrete backend state type. # C: O(1)
    pub fn private<T: Any + Send + Sync>(&self) -> Option<&T> { self.i_private.downcast_ref::<T>() }
    /// Per-inode epoll subscribers. # C: O(1)
    pub fn poll_subscribers(&self) -> Option<&PollSubscribers> { self.poll_subs.as_deref() }
    /// Clone the `Arc` backing the per-inode epoll subscriber set — a backend
    /// (FUSE `/dev/fuse`) whose channel state must notify the SAME subscriber set
    /// the poller registered on adopts this into its shared connection object.
    /// # C: O(1)
    pub fn poll_subscribers_arc(&self) -> Option<Arc<PollSubscribers>> { self.poll_subs.clone() }
    /// memfd seal-store carrier. # C: O(1)
    pub fn as_seal_carrier(&self) -> Option<&dyn SealCarrier> { self.seal_carrier.as_deref() }
    /// memfd seal word. # C: O(1)
    pub fn fcntl_seals(&self) -> Option<&AtomicU32> { self.as_seal_carrier().map(|c| c.seal_word()) }
    /// `i_version` raw word. # C: O(1)
    pub fn i_version_raw(&self) -> Option<&AtomicU64> { Some(&self.i_version) }
    /// `i_link` — inline fast-symlink body. # C: O(1)
    pub fn i_link(&self) -> Option<&[u8]> { self.i_link.as_deref() }
    /// `i_xattrs` — the inode's own xattr store. # C: O(1)
    pub fn simple_xattrs(&self) -> Option<&crate::xattr::SimpleXattrs> { self.i_xattrs.as_ref() }
    /// The `i_op` vtable. # C: O(1)
    pub fn i_op(&self) -> &Arc<dyn InodeOps> { &self.i_op }
    /// The `i_fop` vtable. # C: O(1)
    pub fn i_fop(&self) -> &Arc<dyn FileOps> { &self.i_fop }

    /// Set `i_size`. # C: O(1)
    pub fn set_size(&self, size: u64) { self.i_size.store(size, Ordering::Relaxed); }
    /// Monotonic `i_size` extend. # C: O(1)
    pub fn i_size_fetch_max(&self, size: u64) { self.i_size.fetch_max(size, Ordering::AcqRel); }
    /// Set `i_blocks`. # C: O(1)
    pub fn set_blocks(&self, blocks: u64) { self.i_blocks.store(blocks, Ordering::Relaxed); }
    /// `i_blocks`. # C: O(1)
    pub fn blocks(&self) -> u64 { self.i_blocks.load(Ordering::Relaxed) }
    /// Set `i_flags`. # C: O(1)
    pub fn set_i_flags(&self, flags: u32) { self.i_flags.store(flags, Ordering::Relaxed); }
    /// Replace permission bits, preserving `S_IFMT`. # C: O(1)
    pub fn set_perm(&self, perm: u16) -> KResult<()> {
        let ifmt = self.i_mode.load(Ordering::Relaxed) & (S_IFMT as u32);
        self.i_mode.store(ifmt | (perm as u32 & 0o7777), Ordering::Relaxed);
        Ok(())
    }
    /// `chown` field write. Writes the in-core `i_uid`/`i_gid`, then — for a
    /// synthesized inode that installed an [`OwnerPersist`](super::model::OwnerPersist)
    /// hook (cgroupfs) — writes the owner THROUGH to the backing store so it
    /// survives the inode being re-created on the next lookup (systemd cgroup
    /// delegation). No hook installed → the write-through is skipped, so every
    /// native-storage inode's chown is unchanged. # C: O(1) + backend
    pub fn set_owner(&self, uid: u32, gid: u32) -> KResult<()> {
        self.i_uid.store(uid, Ordering::Relaxed);
        self.i_gid.store(gid, Ordering::Relaxed);
        if let Some(h) = &self.owner_persist { h.persist_owner(uid, gid); }
        Ok(())
    }
    /// Project-id field write. # C: O(1)
    pub fn set_projid(&self, projid: u32) { self.i_projid.store(projid, Ordering::Relaxed); }
    /// utimes field write. # C: O(1)
    pub fn set_times(&self, atime: Option<u64>, mtime: Option<u64>, ctime: u64) -> KResult<()> {
        if let Some(a) = atime { self.i_atime.store(a, Ordering::Relaxed); }
        if let Some(m) = mtime { self.i_mtime.store(m, Ordering::Relaxed); }
        self.i_ctime.store(ctime, Ordering::Relaxed);
        Ok(())
    }

    /// `igrab`. # C: O(1)
    pub fn igrab(&self) { self.i_count.fetch_add(1, Ordering::AcqRel); }
    /// `i_count` snapshot. # C: O(1)
    pub fn i_count(&self) -> u32 { self.i_count.load(Ordering::Acquire) }
    /// Drop one `i_count`; returns the prior value. # C: O(1)
    pub fn i_count_dec(&self) -> u32 { self.i_count.fetch_sub(1, Ordering::AcqRel) }
    /// `i_state` snapshot. # C: O(1)
    pub fn i_state(&self) -> u32 { self.i_state.load(Ordering::Acquire) }
    /// Set/clear `i_state` bits. # C: O(1)
    pub fn set_state(&self, set: u32, clear: u32) {
        let mut cur = self.i_state.load(Ordering::Acquire);
        loop {
            let new = (cur & !clear) | set;
            match self.i_state.compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(v) => cur = v,
            }
        }
    }
    /// True iff being evicted. # C: O(1)
    pub fn is_freeing(&self) -> bool { self.i_state() & (I_FREEING | I_WILL_FREE) != 0 }
    /// `set_nlink`. # C: O(1)
    pub fn set_nlink(&self, n: u32) { self.i_nlink.store(n, Ordering::Relaxed); }
    /// `inc_nlink` (saturating). # C: O(1)
    pub fn inc_nlink(&self) {
        let _ = self.i_nlink.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| Some(n.saturating_add(1)));
    }
    /// `drop_nlink` (saturating at 0). # C: O(1)
    pub fn drop_nlink(&self) {
        let _ = self.i_nlink.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| Some(n.saturating_sub(1)));
    }
    /// Atomically remove one hard-link name and report whether it was the last. # C: O(1)
    pub fn drop_link(&self) -> bool {
        let prev = self.i_nlink.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| Some(n.saturating_sub(1)));
        matches!(prev, Ok(n) if n <= 1)
    }
}
