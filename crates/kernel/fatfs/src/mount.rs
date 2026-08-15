//! Mounting a FAT volume: the VFS-facing filesystem, its inodes and their
//! operations.
//!
//! Everything below this file is pure and already tested against images in
//! memory. This is the adapter, and the decisions it owns are the ones the
//! layers below cannot make: what an inode NUMBER is on a filesystem that has
//! none, and which VFS type and mode each entry presents as.
//!
//! Both of those live in `ident`, ungated and tested, because this module
//! reaches the block layer and would otherwise be untestable.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;

use syscall::errno::Errno;

use vfs::{mk_mode, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef,
          KResult, VfsError};

use crate::dirent::ShortEntry;
use crate::ident::{self, DirLocation};
use crate::volume::{DirEntry, SectorSource, Volume};

/// Linux's magic for a FAT superblock.
pub const MSDOS_SUPER_MAGIC: u64 = 0x4d44;

/// Permissions every entry presents with.
///
/// FAT stores no owner and no permission bits — only a read-only flag — so a
/// mount presents one mode for everything, which is what the reference does
/// with its `umask`/`fmask`/`dmask` options defaulted. A read-only entry drops
/// the write bits rather than being reported writable and failing later.
const DIR_MODE: u16 = 0o755;
const FILE_MODE: u16 = 0o644;
const FILE_MODE_RO: u16 = 0o444;

/// Reads a volume's sectors through a registered block device.
pub struct BlockSource {
    dev: Arc<dyn block::BlockDevice>,
    /// Sector size the VOLUME uses, which need not be the device's.
    sector_size: u32,
    /// Whether this mount may write at all.
    writable: bool,
}

impl BlockSource {
    /// # C: O(1)
    pub fn new(dev: Arc<dyn block::BlockDevice>) -> Self {
        Self { dev, sector_size: 512, writable: false }
    }

    /// Allow writes through this source. # C: O(1)
    pub fn writable(mut self, writable: bool) -> Self { self.writable = writable; self }

    /// Re-aim at the volume's own sector size once the boot sector has named
    /// it. # C: O(1)
    pub fn with_sector_size(mut self, sector_size: u32) -> Self {
        self.sector_size = sector_size;
        self
    }
}

impl BlockSource {
    /// Byte offset and device-block span one volume-sector request covers.
    /// # C: O(1)
    fn span(&self, sector: u64, len: usize) -> Result<(u64, usize, u32), Errno> {
        let dev_block = u64::from(self.dev.block_size().max(1));
        let byte_off = sector.checked_mul(u64::from(self.sector_size)).ok_or(Errno::Eio)?;
        let first = byte_off / dev_block;
        let skew = usize::try_from(byte_off % dev_block).map_err(|_| Errno::Eio)?;
        let span = skew + len;
        let blocks = u32::try_from(span.div_ceil(dev_block as usize)).map_err(|_| Errno::Eio)?;
        Ok((first, skew, blocks))
    }
}

impl SectorSource for BlockSource {
    fn read_sectors(&self, sector: u64, buf: &mut [u8]) -> Result<(), Errno> {
        let dev_block = u64::from(self.dev.block_size().max(1));
        let byte_off = sector.checked_mul(u64::from(self.sector_size)).ok_or(Errno::Eio)?;
        // The volume's sectors and the device's blocks need not be the same
        // size, so the request is expressed in the DEVICE's unit and the
        // wanted bytes are taken out of what comes back.
        let first = byte_off / dev_block;
        let skew = usize::try_from(byte_off % dev_block).map_err(|_| Errno::Eio)?;
        let span = skew + buf.len();
        let blocks = u32::try_from(span.div_ceil(dev_block as usize)).map_err(|_| Errno::Eio)?;
        let mut req = block::BlockRequest::new_read(first, blocks, self.dev.block_size());
        self.dev.submit_sync(&mut req).map_err(|_| Errno::Eio)?;
        if req.buffer.len() < span { return Err(Errno::Eio); }
        buf.copy_from_slice(&req.buffer[skew..span]);
        Ok(())
    }

    /// Write through the device.
    ///
    /// A request that does not start and end on a device-block boundary is a
    /// read-modify-write: the blocks either side hold bytes this write must
    /// not disturb, and a device writes whole blocks or nothing.
    fn write_sectors(&self, sector: u64, buf: &[u8]) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let (first, skew, blocks) = self.span(sector, buf.len())?;
        let span = skew + buf.len();
        let whole = blocks as usize * self.dev.block_size().max(1) as usize;
        let mut payload = if skew == 0 && span == whole {
            alloc::vec![0u8; whole]
        } else {
            let mut req = block::BlockRequest::new_read(first, blocks, self.dev.block_size());
            self.dev.submit_sync(&mut req).map_err(|_| Errno::Eio)?;
            if req.buffer.len() < whole { return Err(Errno::Eio); }
            req.buffer
        };
        payload[skew..span].copy_from_slice(buf);
        let mut req = block::BlockRequest::new_write(first, blocks, payload);
        self.dev.submit_sync(&mut req).map_err(|_| Errno::Eio)?;
        Ok(())
    }

    fn writable(&self) -> bool { self.writable }
}

/// A mounted FAT filesystem.
pub struct FatFs {
    /// One lock: a write mutates the in-memory table every read consults.
    volume: sync::Spinlock<Volume<BlockSource>, sync::TaskList>,
    source: String,
}

impl FatFs {
    /// Mount the volume on `dev`.
    ///
    /// The boot sector is read at 512 bytes first because that is the only
    /// size every volume's first sector is guaranteed to fill; a volume
    /// declaring a larger one is re-read at its own size by the volume layer.
    /// # C: O(table bytes)
    pub fn open(dev: Arc<dyn block::BlockDevice>, source: &str) -> KResult<Arc<Self>> {
        Self::open_with_access(dev, source, false)
    }

    /// Mount, asking for write access.
    ///
    /// A volume its last owner left dirty mounts read-WRITE and warns that a
    /// check is due, which is what the reference does. Refusing would leave a
    /// user unable to save anything to a stick that was pulled once; the
    /// warning is what tells them to run a check.
    /// # C: O(table bytes)
    pub fn open_with_access(dev: Arc<dyn block::BlockDevice>, source: &str, write: bool)
        -> KResult<Arc<Self>> {
        let volume = Volume::mount(BlockSource::new(dev).writable(write)).map_err(errno_to_vfs)?;
        if volume.was_dirty() {
            klog::warn::warn_on(true,
                "vfat: volume was not properly unmounted; some data may be corrupt, run fsck");
        }
        // Marking is a no-op on a volume already dirty: the flag it carries is
        // its last owner's, and this mount has not repaired anything.
        if volume.writable() { volume.set_dirty(true).map_err(errno_to_vfs)?; }
        Ok(Arc::new(Self { volume: sync::Spinlock::new(volume), source: source.to_string() }))
    }

    /// Whether this mount ended up writable. # C: O(1)
    pub fn is_writable(&self) -> bool { self.volume.lock().writable() }

    /// Whether the volume was found dirty. # C: O(1)
    pub fn was_dirty(&self) -> bool { self.volume.lock().was_dirty() }

    /// Clear the dirty flag — unmount. # C: O(1 sector)
    pub fn mark_clean(&self) -> KResult<()> {
        let v = self.volume.lock();
        if !v.writable() { return Ok(()); }
        v.set_dirty(false).map_err(errno_to_vfs)
    }
}

fn errno_to_vfs(err: Errno) -> VfsError {
    match err {
        Errno::Einval => VfsError::Einval,
        Errno::Enoent => VfsError::Enoent,
        Errno::Eisdir => VfsError::Eisdir,
        Errno::Enomem => VfsError::Enomem,
        _ => VfsError::Eio,
    }
}

impl vfs::fs::FileSystem for FatFs {
    fn name(&self) -> &str { "vfat" }
    fn magic(&self) -> u64 { MSDOS_SUPER_MAGIC }
    fn fs_flags(&self) -> vfs::fs::FsFlags { vfs::fs::FsFlags::FS_REQUIRES_DEV }
    fn block_size(&self) -> u32 { self.volume.lock().geometry().sector_size }
    // The root inode is handed to the superblock by the mount constructor
    // rather than produced here: building it needs the `Arc` that owns this
    // filesystem, and this method only has a borrow.
    fn show_options(&self) -> String { String::new() }
}

/// What an inode of this filesystem is: the entry it came from, and where in
/// the tree it sits. A directory carries the cluster its contents start at;
/// the root carries none when the volume keeps it in a fixed region.
struct FatNode {
    fs: Arc<FatFs>,
    entry: Option<ShortEntry>,
    location: DirLocation,
    /// The directory this entry was found in, and where its record sits in
    /// it. Carried so a write updates the record where it came from rather
    /// than searching for a name it already resolved.
    parent: Option<u32>,
    slot: u64,
}

impl FatFs {
    /// The root inode. # C: O(1)
    pub fn root_inode(self: &Arc<Self>) -> InodeRef {
        let location = {
            let v = self.volume.lock();
            if v.geometry().has_fixed_root() { DirLocation::FixedRoot }
            else { DirLocation::Cluster(v.geometry().root_cluster) }
        };
        node_inode(Arc::clone(self), None, location, None, 0)
    }
}

/// Build the inode for one entry. # C: O(1)
fn node_inode(fs: Arc<FatFs>, entry: Option<ShortEntry>, location: DirLocation,
              parent: Option<u32>, slot: u64) -> InodeRef {
    let ino = ident::inode_number(&location, entry.as_ref());
    let (ftype, mode) = match &entry {
        None => (FileType::Directory, DIR_MODE),
        Some(e) if e.is_dir() => (FileType::Directory, DIR_MODE),
        Some(e) if e.attr & crate::dirent::ATTR_RO != 0 => (FileType::Regular, FILE_MODE_RO),
        Some(_) => (FileType::Regular, FILE_MODE),
    };
    let size = entry.as_ref().map_or(0, |e| u64::from(e.size));
    let inode_ops: Arc<dyn InodeOps> = Arc::new(FatOps);
    let file_ops: Arc<dyn FileOps> = Arc::new(FatOps);
    InodeBuilder::new(ino, mk_mode(ftype, mode), inode_ops, file_ops)
        .size(size)
        .private(Arc::new(FatNode { fs, entry, location, parent, slot }))
        .build()
}

struct FatOps;

impl FatOps {
    /// The directory contents an inode names, or `ENOTDIR`. # C: O(dir bytes)
    fn entries(node: &FatNode) -> KResult<alloc::vec::Vec<DirEntry>> {
        let cluster = match node.location {
            DirLocation::FixedRoot => None,
            DirLocation::Cluster(c) => Some(c),
            DirLocation::Entry { .. } => return Err(VfsError::Enotdir),
        };
        node.fs.volume.lock().read_dir(cluster).map_err(errno_to_vfs)
    }
}

impl InodeOps for FatOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let node = inode.private::<FatNode>().ok_or(VfsError::Einval)?;
        let hit = FatOps::entries(node)?.into_iter()
            .find(|e| e.name.eq_ignore_ascii_case(name))
            .ok_or(VfsError::Enoent)?;
        let location = ident::location_of(&hit.entry, &node.location);
        let parent = match node.location {
            DirLocation::FixedRoot => None,
            DirLocation::Cluster(c) => Some(c),
            DirLocation::Entry { .. } => return Err(VfsError::Enotdir),
        };
        Ok(node_inode(Arc::clone(&node.fs), Some(hit.entry), location, parent, hit.slot))
    }
}

impl FileOps for FatOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let node = inode.private::<FatNode>().ok_or(VfsError::Einval)?;
        let entry = node.entry.as_ref().ok_or(VfsError::Eisdir)?;
        node.fs.volume.lock().read_file(entry, off, buf).map_err(errno_to_vfs)
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let node = inode.private::<FatNode>().ok_or(VfsError::Einval)?;
        let entry = node.entry.as_ref().ok_or(VfsError::Eisdir)?;
        // The name is not re-resolved: the record's own slot came with the
        // inode, so the write lands on the record this inode IS.
        let hit = DirEntry { name: String::new(), entry: *entry, slot: node.slot };
        let mut volume = node.fs.volume.lock();
        let size = volume.write_file(node.parent, &hit, off, buf).map_err(errno_to_vfs)?;
        inode.set_size(size);
        Ok(buf.len())
    }

    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let node = inode.private::<FatNode>().ok_or(VfsError::Einval)?;
        let entries = FatOps::entries(node)?;
        // `.` and `..` are ordinary entries on a FAT subdirectory but absent
        // from the root, so they are emitted here rather than trusted from the
        // medium — a root listing must still carry them.
        let self_ino = inode.ino();
        if ctx.pos == 0 && !ctx.emit(".", self_ino, FileType::Directory, 1) { return Ok(()); }
        if ctx.pos == 1 && !ctx.emit("..", self_ino, FileType::Directory, 2) { return Ok(()); }
        for (i, entry) in entries.iter().enumerate() {
            let slot = i as u64 + 2;
            if ctx.pos > slot { continue; }
            // The medium's own dot entries would duplicate the two above.
            if entry.name == "." || entry.name == ".." { continue; }
            let location = ident::location_of(&entry.entry, &node.location);
            let ino = ident::inode_number(&location, Some(&entry.entry));
            let ftype = if entry.is_dir() { FileType::Directory } else { FileType::Regular };
            if !ctx.emit(&entry.name, ino, ftype, slot + 1) { break; }
        }
        Ok(())
    }
}

/// Read the whole of `path` from a mounted volume. Exists for the boot-time
/// caller that wants one file without a mount point. # C: O(file bytes)
pub fn read_path(fs: &FatFs, path: &str) -> KResult<alloc::vec::Vec<u8>> {
    let v = fs.volume.lock();
    let hit = v.lookup(path).map_err(errno_to_vfs)?;
    if hit.is_dir() { return Err(VfsError::Eisdir); }
    let mut out = vec![0u8; usize::try_from(hit.entry.size).map_err(|_| VfsError::Einval)?];
    let got = v.read_file(&hit.entry, 0, &mut out).map_err(errno_to_vfs)?;
    out.truncate(got);
    Ok(out)
}

/// The device this filesystem was mounted from. # C: O(1)
pub fn source_of(fs: &FatFs) -> &str { &fs.source }

#[cfg(test)]
#[path = "mount/tests.rs"]
mod tests;
