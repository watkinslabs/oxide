use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use block::types::InodeId;
use vfs::file_ops::{FileIoctlCmd, FileIoctlReply, FileOps, HoleOrData};
use vfs::inode::InodeBuilder;
use vfs::inode_ops::{InodeOps, mk_mode};
use vfs::mapping::AddressSpaceOps;
use vfs::{FileType, Inode, InodeRef, KResult, VfsError};

use super::data::{Ext4FileData, remove_inode_xattr, set_inode_xattr};
use super::ids::ext4_wrap_ino;
use super::super::state::RootfsState;

/// `ext4_sync_file` (Linux `fs/ext4/fsync.c`) — the shared body of the
/// `f_op->fsync` slot that ext4 installs on BOTH its regular-file and its
/// directory operations. Commits the journal transaction carrying this inode
/// and flushes the OWNING mount's device.
///
/// Deliberately NOT `super_operations->sync_fs`: that is the whole-mount pass
/// behind `sync(2)`/`syncfs(2)`, which additionally writes back every dirty
/// page on the filesystem. Routing `fsync` through it makes every call cost a
/// full `syncfs` — the regression this exists to close. Resolving the mount
/// from the inode's own `i_private` (rather than the rootfs-only helper) is
/// also what makes a file on a NON-root ext4 mount genuinely durable.
/// # C: O(journal tx)
pub(crate) fn ext4_sync_file(inode: &Inode) -> KResult<()> {
    let Some((st, _ino)) = super::data::ext4_state_of(inode) else {
        return Ok(()); // not an ext4-backed inode: nothing of ours to commit
    };
    st.mount.commit_batch().map_err(vfs_error_from_mount)?;
    st.mount.dev.flush().map_err(|_| VfsError::Eio)?;
    Ok(())
}

pub(crate) fn vfs_error_from_mount(e: crate::MountError) -> vfs::VfsError {
    match e {
        // A directory with no free dirent slot whose block growth path isn't
        // wired is an out-of-space condition, not an I/O error (Linux ext4 grows
        // the dir; where we can't, ENOSPC is the honest errno — blanket EIO here
        // hid the real cause of the boot's `mkdir /run/udev`/`/var/log/journal`).
        crate::MountError::NoSpace | crate::MountError::DirFull => vfs::VfsError::Enospc,
        crate::MountError::NotDir => vfs::VfsError::Enotdir,
        crate::MountError::Inode(crate::InodeError::BadLen) => vfs::VfsError::Einval,
        crate::MountError::NotFound => vfs::VfsError::Eopnotsupp,
        crate::MountError::DepthUnsupported | crate::MountError::ExtentTreeFull
            | crate::MountError::NotExtents => vfs::VfsError::Eopnotsupp,
        crate::MountError::CorruptExtentTree => vfs::VfsError::Eio,
        crate::MountError::BadChecksum => vfs::VfsError::Eio,
        crate::MountError::UnsupportedFeature => vfs::VfsError::Einval,
        crate::MountError::Quota(e) => e,
        _ => vfs::VfsError::Eio,
    }
}

/// `inode_operations` for a regular ext4 file: metadata + truncate /
/// fallocate. Namespace ops (lookup/...) stay the trait default. Shared
/// (ZST) across every file inode. # C: O(1)
pub(crate) struct Ext4RegInodeOps;

/// `bmap` reports zero for an unmapped logical filesystem block.
const BMAP_HOLE: u64 = 0;

impl InodeOps for Ext4RegInodeOps {
    /// `ext4_bmap`: translate one logical ext4 block through the authoritative
    /// extent tree.  Swapfile activation uses this same mapping to reject
    /// holes and unwritten extents before it can expose persistent swap I/O.
    /// # C: O(number of extents)
    fn bmap(&self, inode: &Inode, block: u64) -> KResult<u64> {
        let d = inode.private::<Ext4FileData>().ok_or(VfsError::Eio)?;
        let runs = d.st.mount.extent_map(d.ino).map_err(vfs_error_from_mount)?;
        for (logical, physical, len, unwritten) in runs {
            let run_start = logical as u64;
            let run_len = len as u64;
            let run_end = run_start.checked_add(run_len).ok_or(VfsError::Eio)?;
            if block < run_start || block >= run_end { continue; }
            if unwritten { return Ok(BMAP_HOLE); }
            return physical.checked_add(block - run_start).ok_or(VfsError::Eio);
        }
        Ok(BMAP_HOLE)
    }

    fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> {
        let d = inode.private::<Ext4FileData>().ok_or(VfsError::Eio)?;
        let _mutation = d.begin_swap_mutation()?;
        d.st.mount.truncate_inode(d.ino, len).map_err(vfs_error_from_mount)?;
        d.st.page_cache.invalidate(InodeId(d.ino as u64));
        d.frames.invalidate_range(len & !(4095u64), u64::MAX);
        #[cfg(feature = "ext4-frame-cache")]
        d.frames.set_size(len);
        d.refresh_size();
        inode.set_size(d.size_hint.load(Ordering::Acquire));
        d.refresh_inode_usage(inode);
        Ok(())
    }

    fn fallocate(&self, inode: &Inode, off: u64, len: u64, keep_size: bool, zero_range: bool, punch: bool)
        -> KResult<()>
    {
        let d = inode.private::<Ext4FileData>().ok_or(VfsError::Eio)?;
        let _mutation = d.begin_swap_mutation()?;
        if punch {
            // FALLOC_FL_PUNCH_HOLE: deallocate the range → holes (read zeros),
            // size unchanged. Linux requires KEEP_SIZE with PUNCH_HOLE.
            d.st.mount.punch_hole_inode(d.ino, off, len).map_err(vfs_error_from_mount)?;
        } else if zero_range {
            let old = d.size_hint.load(Ordering::Acquire);
            let end = off.checked_add(len).ok_or(VfsError::Einval)?;
            let bs = d.st.mount.sb.block_size.max(1) as usize;
            let zeros = alloc::vec![0u8; bs];
            let mut pos = off;
            while pos < end {
                let n = core::cmp::min((end - pos) as usize, zeros.len());
                d.st.mount.write_at(d.ino, pos, &zeros[..n]).map_err(vfs_error_from_mount)?;
                pos += n as u64;
            }
            if keep_size && end > old {
                d.st.mount.set_inode_size(d.ino, old).map_err(vfs_error_from_mount)?;
            }
        } else {
            d.st.mount.fallocate_inode(d.ino, off, len, keep_size).map_err(vfs_error_from_mount)?;
        }
        d.st.page_cache.invalidate(InodeId(d.ino as u64));
        if let Some(end) = off.checked_add(len) { d.frames.invalidate_range(off & !(4095u64), end); }
        d.refresh_size();
        inode.set_size(d.size_hint.load(Ordering::Acquire));
        d.refresh_inode_usage(inode);
        #[cfg(feature = "ext4-frame-cache")]
        d.frames.set_size(d.size_hint.load(Ordering::Acquire));
        // ext4_fallocate stamps mtime + ctime (Linux) — the allocation mutates
        // the file even under keep_size, so the change/modify times advance.
        let raw = vfs::inode_times::realtime_now_ns();
        if raw != 0 {
            let now = vfs::inode_times::current_time(inode, raw);
            self.update_time(inode, now, vfs::S_MTIME | vfs::S_CTIME)?;
        }
        Ok(())
    }

    fn getattr(&self, inode: &Inode, idmap: &vfs::idmap::Idmap)
        -> vfs::getattr::Kstat
    {
        let mut k = vfs::getattr::generic_fillattr(inode, idmap);
        if let Some(d) = inode.private::<Ext4FileData>() {
            if let Ok(i) = d.st.mount.read_inode(d.ino) { k.blocks = i.i_blocks; }
        }
        k
    }

    fn setattr(&self, inode: &Inode, idmap: &vfs::idmap::Idmap, ia: &vfs::Iattr) -> KResult<()> {
        super::meta::ext4_setattr(inode, idmap, ia)
    }

    /// `ext4_update_time` — the `file_update_time` / `->update_time` backend:
    /// apply the requested times to the in-core inode, then write them THROUGH
    /// to the on-disk slot (journaled) so a write(2)-stamped mtime/ctime is
    /// durable across eviction and remount. Mirrors `ext4_setattr`'s writeback.
    /// # C: O(1) + one journaled inode write
    fn update_time(&self, inode: &Inode, now: u64, flags: u32) -> KResult<()> {
        vfs::generic_update_time(inode, now, flags)?;
        if let Some(d) = inode.private::<Ext4FileData>() {
            d.st.mount.persist_inode_meta(
                d.ino, inode.i_mode(),
                inode.uid().unwrap_or(0), inode.gid().unwrap_or(0),
                inode.atime().unwrap_or(0), inode.mtime().unwrap_or(0), inode.ctime().unwrap_or(0),
            ).map_err(vfs_error_from_mount)?;
        }
        Ok(())
    }

    /// `FS_IOC_GETFLAGS` / `FS_IOC_SETFLAGS` (chattr/lsattr) — read/write the
    /// on-disk `i_flags`. # C: O(1) [+ 1 journaled write on set]
    fn fileattr_get(&self, inode: &Inode) -> KResult<vfs::FileAttr> {
        super::meta::ext4_fileattr_get(inode)
    }
    fn fileattr_set(&self, inode: &Inode, fa: &vfs::FileAttr) -> KResult<()> {
        super::meta::ext4_fileattr_set(inode, fa)
    }

    /// `ext4_fiemap` (`FS_IOC_FIEMAP`, filefrag/backup/dedup tools): report the
    /// file's physical extents intersecting `[start, start+len)` as byte-unit
    /// `FiemapExtent`s. Reuses the leaf-extent walk; an unwritten (fallocated)
    /// extent is flagged `FIEMAP_EXTENT_UNWRITTEN`, and the final extent of the
    /// file carries `FIEMAP_EXTENT_LAST` (Linux `EXT4_FIEMAP` semantics). `emit`
    /// returning false (user array full) stops the walk. # C: O(N_extents)
    fn fiemap(&self, inode: &Inode, start: u64, len: u64,
              emit: &mut dyn FnMut(vfs::FiemapExtent) -> bool) -> KResult<()> {
        let d = inode.private::<Ext4FileData>().ok_or(VfsError::Eio)?;
        let bs = d.st.mount.sb.block_size.max(1) as u64;
        let runs = d.st.mount.extent_map(d.ino).map_err(vfs_error_from_mount)?;
        let range_end = start.saturating_add(len);
        let last_idx = runs.len().wrapping_sub(1);
        for (idx, &(rlog, rphys, rlen, unwritten)) in runs.iter().enumerate() {
            let logical = rlog as u64 * bs;
            let length  = rlen as u64 * bs;
            let ext_end = logical.saturating_add(length);
            // Report any extent whose byte span intersects the requested range;
            // extents are reported whole (Linux does not split at the boundary).
            if ext_end <= start || logical >= range_end { continue; }
            let mut flags = 0u32;
            if unwritten { flags |= vfs::inode::FIEMAP_EXTENT_UNWRITTEN; }
            if idx == last_idx { flags |= vfs::inode::FIEMAP_EXTENT_LAST; }
            if !emit(vfs::FiemapExtent { logical, physical: rphys * bs, length, flags }) {
                break;
            }
        }
        Ok(())
    }

    fn setxattr(&self, inode: &Inode, name: &str, value: Vec<u8>, create: bool, replace: bool)
        -> Result<(), vfs::XattrError>
    {
        set_inode_xattr(inode, name, value, create, replace)
    }

    fn removexattr(&self, inode: &Inode, name: &str) -> Result<(), vfs::XattrError> {
        remove_inode_xattr(inode, name)
    }
}

/// `file_operations` for a regular ext4 file: read/write through the
/// owning mount's device + page cache. Shared (ZST). # C: O(1)
pub(crate) struct Ext4RegFileOps;

impl FileOps for Ext4RegFileOps {
    /// `ext4_sync_file` (Linux `fs/ext4/fsync.c`) — the `f_op->fsync` slot.
    /// Commits the journal transaction carrying THIS inode and flushes the
    /// owning mount's device, so the file's data and the metadata reaching it
    /// are on disk when `fsync(2)` returns.
    ///
    /// Deliberately NOT `super_operations->sync_fs`: that is the whole-mount
    /// pass behind `sync(2)`/`syncfs(2)` and additionally writes back every
    /// dirty page on the filesystem. Routing `fsync` through it makes each call
    /// cost a full `syncfs` — the regression this override exists to close.
    /// Resolving the mount from the inode's own `i_private` (not the rootfs
    /// helper) keeps a file on a NON-root ext4 mount genuinely durable.
    /// # C: O(journal tx)
    fn fsync(&self, file: &vfs::File, _datasync: bool) -> KResult<()> {
        ext4_sync_file(file.inode())
    }

    fn unlocked_ioctl(
        &self,
        file: &vfs::File,
        idmap: &vfs::idmap::Idmap,
        cred: &vfs::Cred,
        cmd: FileIoctlCmd,
    ) -> KResult<FileIoctlReply> {
        match cmd {
            FileIoctlCmd::GetVersion =>
                Ok(FileIoctlReply::U32(super::meta::ext4_getversion(file.inode())?)),
            FileIoctlCmd::SetVersionPrepare => {
                super::meta::ext4_setversion_prepare(file.inode(), idmap, cred)?;
                Ok(FileIoctlReply::Done)
            }
            FileIoctlCmd::SetVersion(gen) => {
                super::meta::ext4_setversion(file.inode(), gen)?;
                Ok(FileIoctlReply::Done)
            }
            FileIoctlCmd::GetFsLabel =>
                Ok(FileIoctlReply::Label(super::meta::ext4_getfslabel(file.inode())?)),
            FileIoctlCmd::SetFsLabelPrepare(cap) => {
                super::meta::ext4_setfslabel_prepare(cap)?;
                Ok(FileIoctlReply::Done)
            }
            FileIoctlCmd::SetFsLabel(label) => {
                super::meta::ext4_setfslabel(file.inode(), label)?;
                Ok(FileIoctlReply::Done)
            }
            FileIoctlCmd::FitTrimPrepare(cap) => {
                super::meta::ext4_fitrim_prepare(cap)?;
                Ok(FileIoctlReply::Done)
            }
            FileIoctlCmd::FitTrim { start, len, minlen } => {
                super::meta::ext4_fitrim(start, len, minlen)?;
                Ok(FileIoctlReply::Done)
            }
        }
    }

    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<Ext4FileData>().ok_or(VfsError::Eio)?;
        #[cfg(feature = "ext4-frame-cache")]
        { return d.frames.read_framed(off, buf); }
        #[cfg(not(feature = "ext4-frame-cache"))]
        { d.st.read_cached(d.ino, off, buf).map_err(|_| VfsError::Eio) }
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let d = inode.private::<Ext4FileData>().ok_or(VfsError::Eio)?;
        let _mutation = d.begin_swap_mutation()?;
        // Linux buffered write: land the bytes in the page cache (dirty) and
        // return; disk I/O is deferred to writeback (fsync/msync/sync/drop).
        // Without the frame cache there is nowhere to buffer, so fall back to
        // the synchronous write-through path.
        #[cfg(feature = "ext4-frame-cache")]
        { d.frames.write_buffered(off, buf)?; }
        #[cfg(not(feature = "ext4-frame-cache"))]
        {
            d.st.mount.write_at(d.ino, off, buf).map_err(vfs_error_from_mount)?;
            d.st.page_cache.invalidate(InodeId(d.ino as u64));
        }
        let end = off.saturating_add(buf.len() as u64);
        d.size_hint.fetch_max(end, Ordering::AcqRel);
        inode.i_size_fetch_max(end);
        if let Ok(i) = d.st.mount.read_inode(d.ino) { inode.set_blocks(i.i_blocks as u64); }
        Ok(buf.len())
    }

    fn seek_hole_data(&self, inode: &Inode, offset: u64, which: HoleOrData) -> KResult<u64> {
        let d = inode.private::<Ext4FileData>().ok_or(VfsError::Eio)?;
        let i = d.st.mount.read_inode(d.ino).map_err(|_| VfsError::Eio)?;
        let size = i.size;
        if offset >= size { return Err(VfsError::Enxio); }
        let bs = d.st.mount.sb.block_size.max(1) as u64;
        let runs = d.st.mount.collect_leaf_extents(&i.i_block).map_err(|_| VfsError::Eio)?;
        seek_in_runs(&runs, bs, size, offset, which)
    }
}

/// Pure SEEK_HOLE/SEEK_DATA boundary resolver over a file's data runs.
/// `runs` are `(first_logical_block, len_blocks)` ASCENDING by start block,
/// non-overlapping; gaps between runs (and the region after the last run, up
/// to `size`) are holes. `bs` = block size, `size` = i_size (bytes), `offset`
/// = scan-start byte (caller guarantees `offset < size`). Mirrors Linux
/// `ext4_seek_data`/`ext4_seek_hole` semantics. # C: O(N_runs)
fn seek_in_runs(runs: &[(u32, u32)], bs: u64, size: u64, offset: u64, which: HoleOrData)
    -> KResult<u64>
{
    let b = offset / bs;
    let contains = |blk: u64| runs.iter().any(|&(s, l)| blk >= s as u64 && blk < s as u64 + l as u64);
    match which {
        HoleOrData::Data => {
            if contains(b) { return Ok(offset); }
            for &(s, _l) in runs {
                if (s as u64) > b {
                    let byte = (s as u64) * bs;
                    return if byte < size { Ok(byte) } else { Err(VfsError::Enxio) };
                }
            }
            Err(VfsError::Enxio)
        }
        HoleOrData::Hole => {
            if !contains(b) { return Ok(offset); }
            let mut chain_end: Option<u64> = None;
            for &(s, l) in runs {
                let start = s as u64;
                let end = start + l as u64;
                match chain_end {
                    None => { if b >= start && b < end { chain_end = Some(end); } }
                    Some(ce) => {
                        if start == ce { chain_end = Some(end); }
                        else if start > ce { break; }
                    }
                }
            }
            let hole_byte = chain_end.map(|e| e * bs).unwrap_or(offset);
            Ok(hole_byte.min(size))
        }
    }
}

/// ext4 file `address_space` (`i_mapping`): reads route through the owning
/// mount's shared `page_cache` (keyed by inode id), so all mappers/readers
/// of one inode hit the SAME cached pages. # C: O(1)
pub(crate) struct Ext4FileMapping { pub(crate) data: Arc<Ext4FileData> }

impl AddressSpaceOps for Ext4FileMapping {
    fn shared_frame(&self, off: u64) -> KResult<Option<vfs::SharedFrame>> {
        #[cfg(feature = "ext4-frame-cache")]
        { return self.data.frames.shared_frame(off); }
        #[cfg(not(feature = "ext4-frame-cache"))]
        { let _ = off; Ok(None) }
    }

    fn read_at(&self, off: u64, dst: &mut [u8]) -> KResult<usize> {
        #[cfg(feature = "ext4-frame-cache")]
        { return self.data.frames.read_framed(off, dst); }
        #[cfg(not(feature = "ext4-frame-cache"))]
        { self.data.st.read_cached(self.data.ino, off, dst).map_err(|_| VfsError::Eio) }
    }

    fn writeback(&self) -> Result<(), ()> { self.data.frames.writeback() }

    fn writeback_range(&self, start: u64, end: u64) -> Result<(), ()> {
        self.data.frames.writeback_range(start, end)
    }

    fn mincore_page(&self, off: u64) -> bool { self.data.frames.mincore_page(off) }

    fn invalidate_range(&self, start: u64, end: u64) -> usize {
        self.data.frames.invalidate_range(start, end)
    }

    fn size(&self) -> u64 { self.data.size_hint.load(Ordering::Acquire) }
}

/// Build a regular-file `vfs::Inode` for ext4 inode `ino`. `mode`/`size`/
/// `nlink`/`times` are the captured on-disk metadata (read by the caller before
/// the `iget` build closure). `times` = `(atime, mtime, ctime, crtime)` ns
/// (crtime `0` → no STATX_BTIME). # C: O(1)
pub(crate) fn build_file_inode(st: Arc<RootfsState>, ino: u32, mode: u16, size: u64, nlink: u32,
    uid: u32, gid: u32, projid: u32, times: (u64, u64, u64, u64))
    -> InodeRef
{
    let frames = super::super::framecache::Ext4FrameStore::new(st.clone(), ino, size);
    let data = Arc::new(Ext4FileData { st, ino, size_hint: AtomicU64::new(size), frames,
        swap_active: Arc::new(core::sync::atomic::AtomicBool::new(false)),
        swap_mutations: Arc::new(AtomicU64::new(0)) });
    let mapping: Arc<dyn AddressSpaceOps> = Arc::new(Ext4FileMapping { data: data.clone() });
    let weak_sb = data.st.sb.lock().clone();
    let xattrs = vfs::SimpleXattrs::new();
    data.st.mount.load_xattrs(ino, &xattrs);
    let blocks = data.st.mount.read_inode(ino).map(|i| i.i_blocks as u64).unwrap_or(0);
    InodeBuilder::new(ext4_wrap_ino(ino), mk_mode(FileType::Regular, mode & 0o7777),
                      Arc::new(Ext4RegInodeOps), Arc::new(Ext4RegFileOps))
        .sb(weak_sb)
        .size(size)
        .blocks(blocks)
        .nlink(nlink)
        .owner(uid, gid)
        .projid(projid)
        .times(times.0, times.1, times.2)
        .btime(times.3)
        .mapping(mapping)
        .xattrs(xattrs)
        .private(data)
        .build()
}

#[cfg(test)]
mod tests {
    use super::{HoleOrData, seek_in_runs};
    use vfs::VfsError;

    const BS: u64 = 4096;

    #[test]
    fn full_file_data_and_hole() {
        let runs = [(0u32, 10u32)];
        let size = 40000u64;
        assert_eq!(seek_in_runs(&runs, BS, size, 0, HoleOrData::Data), Ok(0));
        assert_eq!(seek_in_runs(&runs, BS, size, 5000, HoleOrData::Data), Ok(5000));
        assert_eq!(seek_in_runs(&runs, BS, size, 0, HoleOrData::Hole), Ok(size));
    }

    #[test]
    fn sparse_middle_hole() {
        let runs = [(0u32, 1u32), (5u32, 3u32)];
        let size = 8 * BS;
        assert_eq!(seek_in_runs(&runs, BS, size, 100, HoleOrData::Hole), Ok(BS));
        assert_eq!(seek_in_runs(&runs, BS, size, 2 * BS, HoleOrData::Data), Ok(5 * BS));
        let off = 2 * BS + 17;
        assert_eq!(seek_in_runs(&runs, BS, size, off, HoleOrData::Hole), Ok(off));
        assert_eq!(seek_in_runs(&runs, BS, size, 6 * BS, HoleOrData::Hole), Ok(size));
    }

    #[test]
    fn leading_hole() {
        let runs = [(3u32, 2u32)];
        let size = 6 * BS;
        assert_eq!(seek_in_runs(&runs, BS, size, 0, HoleOrData::Data), Ok(3 * BS));
        assert_eq!(seek_in_runs(&runs, BS, size, 0, HoleOrData::Hole), Ok(0));
    }

    #[test]
    fn adjacent_runs_merge() {
        let runs = [(0u32, 2u32), (2u32, 1u32), (10u32, 1u32)];
        let size = 11 * BS;
        assert_eq!(seek_in_runs(&runs, BS, size, BS, HoleOrData::Hole), Ok(3 * BS));
        assert_eq!(seek_in_runs(&runs, BS, size, 5 * BS, HoleOrData::Data), Ok(10 * BS));
    }

    #[test]
    fn no_more_data_enxio() {
        let runs = [(0u32, 1u32)];
        let size = 8 * BS;
        assert_eq!(seek_in_runs(&runs, BS, size, 4 * BS, HoleOrData::Data), Err(VfsError::Enxio));
    }

    #[test]
    fn no_extents_all_hole() {
        let runs: [(u32, u32); 0] = [];
        let size = 3 * BS;
        assert_eq!(seek_in_runs(&runs, BS, size, 0, HoleOrData::Hole), Ok(0));
        assert_eq!(seek_in_runs(&runs, BS, size, BS, HoleOrData::Data), Err(VfsError::Enxio));
    }
}
