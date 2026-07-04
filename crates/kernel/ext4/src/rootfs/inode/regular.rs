use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use block::types::InodeId;
use vfs::file_ops::{FileOps, HoleOrData};
use vfs::inode::InodeBuilder;
use vfs::inode_ops::{InodeOps, mk_mode};
use vfs::mapping::AddressSpaceOps;
use vfs::{FileType, Inode, InodeRef, KResult, VfsError};

use super::data::{Ext4FileData, persist_inode_xattrs};
use super::ids::ext4_wrap_ino;
use super::super::state::RootfsState;

fn vfs_error_from_mount(e: crate::MountError) -> vfs::VfsError {
    match e {
        crate::MountError::NoSpace => vfs::VfsError::Enospc,
        crate::MountError::Inode(crate::InodeError::BadLen) => vfs::VfsError::Einval,
        crate::MountError::NotFound => vfs::VfsError::Eopnotsupp,
        crate::MountError::DepthUnsupported | crate::MountError::ExtentTreeFull => vfs::VfsError::Eopnotsupp,
        _ => vfs::VfsError::Eio,
    }
}

/// `inode_operations` for a regular ext4 file: metadata + truncate /
/// fallocate. Namespace ops (lookup/...) stay the trait default. Shared
/// (ZST) across every file inode. # C: O(1)
pub(crate) struct Ext4RegInodeOps;

impl InodeOps for Ext4RegInodeOps {
    fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> {
        let d = inode.private::<Ext4FileData>().ok_or(VfsError::Eio)?;
        d.st.mount.truncate_inode(d.ino, len).map_err(|_| VfsError::Eio)?;
        d.st.page_cache.invalidate(InodeId(d.ino as u64));
        d.frames.invalidate_range(len & !(4095u64), u64::MAX);
        d.refresh_size();
        inode.set_size(d.size_hint.load(Ordering::Acquire));
        Ok(())
    }

    fn fallocate(&self, inode: &Inode, off: u64, len: u64, keep_size: bool, zero_range: bool)
        -> KResult<()>
    {
        let d = inode.private::<Ext4FileData>().ok_or(VfsError::Eio)?;
        if zero_range {
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
        Ok(())
    }

    fn getattr(&self, inode: &Inode, idmap: &vfs::idmap::Idmap, overlay: Option<vfs::inode_times::InodeTimes>)
        -> vfs::getattr::Kstat
    {
        let mut k = vfs::getattr::generic_fillattr(inode, idmap, overlay);
        if let Some(d) = inode.private::<Ext4FileData>() {
            if let Ok(i) = d.st.mount.read_inode(d.ino) { k.blocks = i.i_blocks; }
        }
        k
    }

    fn setxattr(&self, inode: &Inode, name: &str, value: Vec<u8>, create: bool, replace: bool)
        -> Result<(), vfs::XattrError>
    {
        let store = inode.simple_xattrs().ok_or(vfs::XattrError::NotSup)?;
        store.set(name, value, create, replace)?;
        persist_inode_xattrs(inode);
        Ok(())
    }

    fn removexattr(&self, inode: &Inode, name: &str) -> Result<(), vfs::XattrError> {
        let store = inode.simple_xattrs().ok_or(vfs::XattrError::NotSup)?;
        store.remove(name)?;
        persist_inode_xattrs(inode);
        Ok(())
    }
}

/// `file_operations` for a regular ext4 file: read/write through the
/// owning mount's device + page cache. Shared (ZST). # C: O(1)
pub(crate) struct Ext4RegFileOps;

impl FileOps for Ext4RegFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<Ext4FileData>().ok_or(VfsError::Eio)?;
        #[cfg(feature = "ext4-frame-cache")]
        { return d.frames.read_framed(off, buf).map_err(|_| VfsError::Eio); }
        #[cfg(not(feature = "ext4-frame-cache"))]
        { d.st.read_cached(d.ino, off, buf).map_err(|_| VfsError::Eio) }
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let d = inode.private::<Ext4FileData>().ok_or(VfsError::Eio)?;
        d.st.mount.write_at(d.ino, off, buf).map_err(|_| VfsError::Eio)?;
        d.st.page_cache.invalidate(InodeId(d.ino as u64));
        #[cfg(feature = "ext4-frame-cache")]
        d.frames.update_resident(off, buf);
        let end = off.saturating_add(buf.len() as u64);
        d.size_hint.fetch_max(end, Ordering::AcqRel);
        inode.i_size_fetch_max(end);
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
    fn shared_frame(&self, off: u64) -> Option<u64> {
        #[cfg(feature = "ext4-frame-cache")]
        { return self.data.frames.shared_frame(off); }
        #[cfg(not(feature = "ext4-frame-cache"))]
        { let _ = off; None }
    }

    fn read_at(&self, off: u64, dst: &mut [u8]) -> Result<usize, ()> {
        #[cfg(feature = "ext4-frame-cache")]
        { return self.data.frames.read_framed(off, dst); }
        #[cfg(not(feature = "ext4-frame-cache"))]
        { self.data.st.read_cached(self.data.ino, off, dst) }
    }

    fn writeback(&self) -> Result<(), ()> { self.data.frames.writeback() }

    fn writeback_range(&self, start: u64, end: u64) -> Result<(), ()> {
        self.data.frames.writeback_range(start, end)
    }

    fn invalidate_range(&self, start: u64, end: u64) -> usize {
        self.data.frames.invalidate_range(start, end)
    }

    fn size(&self) -> u64 { self.data.size_hint.load(Ordering::Acquire) }
}

/// Build a regular-file `vfs::Inode` for ext4 inode `ino`. `mode`/`size`/
/// `nlink` are the captured on-disk metadata (read by the caller before the
/// `iget` build closure). # C: O(1)
pub(crate) fn build_file_inode(st: Arc<RootfsState>, ino: u32, mode: u16, size: u64, nlink: u32, uid: u32, gid: u32)
    -> InodeRef
{
    let frames = super::super::framecache::Ext4FrameStore::new(st.clone(), ino);
    let data = Arc::new(Ext4FileData { st, ino, size_hint: AtomicU64::new(size), frames });
    let mapping: Arc<dyn AddressSpaceOps> = Arc::new(Ext4FileMapping { data: data.clone() });
    let weak_sb = data.st.sb.lock().clone();
    let xattrs = vfs::SimpleXattrs::new();
    data.st.mount.load_xattrs(ino, &xattrs);
    InodeBuilder::new(ext4_wrap_ino(ino), mk_mode(FileType::Regular, mode & 0o7777),
                      Arc::new(Ext4RegInodeOps), Arc::new(Ext4RegFileOps))
        .sb(weak_sb)
        .size(size)
        .nlink(nlink)
        .owner(uid, gid)
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
