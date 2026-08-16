//! `statfs` and the option tail.

use alloc::string::String;
use alloc::sync::Arc;

use vfs::superblock::{SbStatFs, SuperOps};
use vfs::KResult;

use crate::limits::NAME_MAX;
use crate::uapi::F2FS_SUPER_MAGIC;

use super::F2fs;

/// The superblock operations of one mounted volume.
pub struct F2fsSuperOps {
    pub(crate) fs: Arc<F2fs>,
}

impl SuperOps for F2fsSuperOps {
    /// The counts come from the checkpoint the mount already read, which is
    /// the same number this filesystem's own writer maintains. Two counts are
    /// reported because a volume can exhaust either: blocks, or node slots.
    fn statfs(&self) -> KResult<SbStatFs> {
        let v = self.fs.volume.lock();
        let s = v.space();
        let sb = v.super_block();
        // The identifier is the volume's own uuid, folded to the width the
        // interface reports, so two mounts of the same medium agree.
        let fsid = u64::from_le_bytes(sb.uuid[..8].try_into().unwrap_or([0u8; 8]));
        Ok(SbStatFs {
            f_type: F2FS_SUPER_MAGIC,
            f_bsize: s.block_bytes,
            f_blocks: s.total,
            f_bfree: s.free,
            f_bavail: s.avail,
            f_files: s.files,
            f_ffree: s.ffree,
            f_fsid: fsid,
            f_flags: 0,
            f_namelen: NAME_MAX,
            f_frsize: 0,
        })
    }

    /// The same counts, narrowed to what the named object is actually allowed.
    ///
    /// A file under a project-inheriting tree is confined to that project's
    /// limits, not the volume's. Reporting the volume's counts inside such a
    /// tree says there is room where there is none, and the write that follows
    /// fails with the space apparently still free — which is the one thing a
    /// caller cannot recover from, because it contradicts what it was just
    /// told. An unlimited project, an inode outside any project, or a volume
    /// not enforcing project quota all fall back to the volume's own answer.
    /// # C: O(1 block + quota file lookup)
    fn statfs_at(&self, inode: &vfs::InodeRef) -> KResult<SbStatFs> {
        let mut st = self.statfs()?;
        let mut v = self.fs.volume.lock();
        if !crate::quota::types::enforced(&v.quota_setup()[crate::quota::uapi::PRJQUOTA]) {
            return Ok(st);
        }
        let Ok(ino) = v.read_inode(inode.ino() as u32) else { return Ok(st) };
        if ino.flags & crate::flags::F2FS_PROJINHERIT_FL == 0 { return Ok(st); }
        let Ok(d) = v.quota_record(crate::quota::uapi::PRJQUOTA, ino.projid) else { return Ok(st) };
        // The record counts bytes; this interface counts blocks. The limit and
        // the usage are each rounded to whole blocks BEFORE they are
        // subtracted: rounding the difference instead loses a block whenever
        // either is not a whole number of them, and a limit is stored in units
        // a block is not a multiple of.
        //
        // A limit smaller than one block narrows nothing at all. Reporting
        // zero blocks and zero free would tell the caller the filesystem is
        // full, when the volume's own answer is both truthful and useful; the
        // write is refused by the quota itself, which is where that belongs.
        let bsize = u64::from(st.f_bsize.max(1));
        let limit = crate::quota::limit::effective_limit(d.bhardlimit, d.bsoftlimit)
            .map_or(0, |l| l / bsize);
        if limit > 0 {
            let used = crate::quota::limit::total_space(&d) / bsize;
            let left = limit.saturating_sub(used);
            st.f_blocks = st.f_blocks.min(limit);
            // Free and available narrow together: the reserve an ordinary
            // caller may not touch is the VOLUME's, and it does not buy room
            // inside a project that is already at its limit.
            st.f_bfree = st.f_bfree.min(left);
            st.f_bavail = st.f_bavail.min(left);
        }
        if let Some(limit) = crate::quota::limit::effective_limit(d.ihardlimit, d.isoftlimit) {
            let left = crate::quota::limit::inodes_remaining(&d).unwrap_or(0);
            st.f_files = st.f_files.min(limit);
            st.f_ffree = st.f_ffree.min(left);
        }
        Ok(st)
    }

    fn show_options(&self) -> String { crate::opts::show(self.fs.volume.lock().options()) }

    /// Write a checkpoint.
    ///
    /// Until one is written the medium still describes the state this mount
    /// started from: every out-of-place write is invisible, because nothing
    /// points at the new blocks. A read-only mount has nothing to push and
    /// reports success rather than failing every `sync(2)` on the machine.
    fn sync_fs(&self, _wait: bool) -> KResult<()> { self.fs.checkpoint() }

    /// Unmount. This is the last chance to write a checkpoint, and skipping it
    /// throws away everything the mount did since the previous one — the
    /// medium would still describe the state it was mounted in.
    ///
    /// The result cannot be reported: unmount has no error path by this point.
    /// A failure is logged rather than swallowed silently, because the volume
    /// is then genuinely behind and a check is due.
    fn put_super(&self) {
        if self.fs.checkpoint().is_err() {
            klog::warn::warn_on(true, "f2fs: could not write a checkpoint at unmount; run fsck");
        }
        // The reporting directories describe a volume that no longer exists.
        crate::fsattr::run_teardown(&crate::fsattr::dev_id(self.fs.source()));
    }

    /// Freezing must leave the medium consistent, which for this filesystem
    /// means a checkpoint: a frozen volume that still needs one is a volume
    /// whose snapshot is missing the work it was told to flush.
    fn freeze_fs(&self) -> KResult<()> { self.fs.checkpoint() }

    /// Going read-only is a state change a reader must see, so it is written
    /// out; coming back read-write needs nothing, because the mount already
    /// holds the state.
    fn remount_fs(&self, sb_flags: u64, _data: &str) -> KResult<()> {
        if sb_flags & vfs::superblock::SB_RDONLY != 0 { return self.fs.checkpoint(); }
        Ok(())
    }
}
