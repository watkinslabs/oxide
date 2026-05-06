// `Mount` ties superblock + group-descriptor-table + inode +
// directory + extent parsers together against a `BlockDevice`
// per `17§2`. Provides:
//
//   - Mount::open(dev): read superblock + GDT once, cache.
//   - Mount::read_inode(ino): locate + fetch + parse one inode.
//   - Mount::read_inline_extents(inode, callback): walk leaves.
//   - Mount::read_file_block(inode, file_blk): map logical to
//     physical block via extents; read.
//   - Mount::lookup_in_dir(dir_inode, name): scan directory's
//     first data block for the named entry.
//   - Mount::lookup_path("/foo/bar"): root-relative walk.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockRequest};

use crate::dir;
use crate::gdt::{self, GdtError, GroupDesc};
use crate::inode::{self, Extent, ExtentHeader, Inode, InodeError};
use crate::superblock::{Superblock, SuperblockError, SUPERBLOCK_OFFSET, SUPERBLOCK_LEN};

/// Errors at the Mount layer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MountError {
    BlockIo,
    Superblock(SuperblockError),
    Gdt(GdtError),
    Inode(InodeError),
    Dir(dir::DirError),
    /// Path component not found.
    NotFound,
    /// Path component was not a directory.
    NotDir,
    /// Directory had a non-extent layout (legacy ext2 indirect blocks).
    NotExtents,
    /// File extent tree depth > 0; v1 supports only inline extents.
    DepthUnsupported,
}

impl From<SuperblockError> for MountError { fn from(e: SuperblockError) -> Self { MountError::Superblock(e) } }
impl From<GdtError>        for MountError { fn from(e: GdtError)        -> Self { MountError::Gdt(e) } }
impl From<InodeError>      for MountError { fn from(e: InodeError)      -> Self { MountError::Inode(e) } }
impl From<dir::DirError>   for MountError { fn from(e: dir::DirError)   -> Self { MountError::Dir(e) } }

/// Mounted ext4 filesystem.
pub struct Mount {
    dev: Arc<dyn BlockDevice>,
    pub sb: Superblock,
    /// Cached GDT bytes (read once at mount).
    gdt_buf: Vec<u8>,
}

impl Mount {
    /// Open the filesystem on `dev`. Reads + parses the
    /// superblock + group descriptor table.
    /// # C: O(N_groups * desc_size + 1024)
    pub fn open(dev: Arc<dyn BlockDevice>) -> Result<Self, MountError> {
        let sb_bytes = read_byte_range(&*dev, SUPERBLOCK_OFFSET, SUPERBLOCK_LEN)?;
        let sb = Superblock::parse(&sb_bytes)?;
        let groups = sb.group_count() as usize;
        let dsize = gdt::desc_size_for(&sb) as usize;
        // GDT lives at the block after the superblock. With 1 KiB
        // blocks the SB is at block 1 and the GDT starts at block 2.
        // With ≥ 4 KiB blocks the SB shares block 0 (offset 1024)
        // and the GDT starts at block 1.
        let gdt_byte_offset: u64 = if sb.block_size == 1024 {
            // block 2 → offset 2048
            (sb.block_size as u64) * 2
        } else {
            sb.block_size as u64
        };
        let gdt_len = groups * dsize;
        let gdt_buf = read_byte_range(&*dev, gdt_byte_offset, gdt_len)?;
        Ok(Self { dev, sb, gdt_buf })
    }

    /// Look up the `n`-th group descriptor.
    /// # C: O(1)
    pub fn group_desc(&self, n: u32) -> Result<GroupDesc, MountError> {
        Ok(gdt::parse_descriptor(&self.gdt_buf, n, &self.sb)?)
    }

    /// Read inode `ino` (1-indexed) from disk.
    /// # C: O(1) I/O + O(1) parse
    pub fn read_inode(&self, ino: u32) -> Result<Inode, MountError> {
        let (group, idx) = gdt::locate_inode(&self.sb, ino)?;
        let gd = self.group_desc(group)?;
        let off_in_table = (idx as u64) * (self.sb.inode_size as u64);
        let byte_off = gd.inode_table * (self.sb.block_size as u64) + off_in_table;
        let buf = read_byte_range(&*self.dev, byte_off, self.sb.inode_size as usize)?;
        Ok(Inode::parse(&buf, &self.sb)?)
    }

    /// Read the data of `inode`'s `file_blk`-th logical block.
    /// Returns one block of `sb.block_size` bytes. Only inline
    /// extent trees are supported (depth==0); deeper trees
    /// surface as `MountError::DepthUnsupported`.
    /// # C: O(N_extents)
    pub fn read_file_block(&self, inode: &Inode, file_blk: u32) -> Result<Vec<u8>, MountError> {
        let hdr = inode::parse_extent_header(&inode.i_block)?;
        if hdr.depth != 0 { return Err(MountError::DepthUnsupported); }
        for i in 0..hdr.entries {
            let e = inode::parse_inline_extent(&inode.i_block, &hdr, i)
                .ok_or(MountError::NotFound)?;
            if file_blk >= e.block && file_blk < e.block + e.len as u32 {
                let phys = e.start_lba() + (file_blk - e.block) as u64;
                let byte_off = phys * (self.sb.block_size as u64);
                return read_byte_range(&*self.dev, byte_off, self.sb.block_size as usize);
            }
        }
        // Sparse / hole — caller probably reading past EOF.
        Err(MountError::NotFound)
    }

    /// Write `data` (one filesystem block) back to `file_blk`'s
    /// physical extent. **In-place only** — does not allocate
    /// new extents, does not grow the file, does not journal.
    /// `data.len()` must equal `sb.block_size`. Phase 7b minimum;
    /// allocation + journaling (JBD2) ride alongside the full
    /// `docs/17` RW path.
    /// # C: O(N_extents) extent walk + O(1) block I/O
    pub fn write_file_block(
        &self,
        inode:    &Inode,
        file_blk: u32,
        data:     &[u8],
    ) -> Result<(), MountError> {
        if data.len() != self.sb.block_size as usize {
            return Err(MountError::Inode(InodeError::BadLen));
        }
        let hdr = inode::parse_extent_header(&inode.i_block)?;
        if hdr.depth != 0 { return Err(MountError::DepthUnsupported); }
        for i in 0..hdr.entries {
            let e = inode::parse_inline_extent(&inode.i_block, &hdr, i)
                .ok_or(MountError::NotFound)?;
            if file_blk >= e.block && file_blk < e.block + e.len as u32 {
                let phys = e.start_lba() + (file_blk - e.block) as u64;
                let byte_off = phys * (self.sb.block_size as u64);
                return write_byte_range(&*self.dev, byte_off, data);
            }
        }
        Err(MountError::NotFound)
    }

    /// Look `name` up in the directory whose first data block
    /// holds the entries. Only the first block is consulted —
    /// large dirs split across multiple blocks land in P6-06+.
    /// # C: O(N_entries)
    pub fn lookup_in_dir(&self, dir_inode: &Inode, name: &[u8]) -> Result<u32, MountError> {
        if !dir_inode.is_dir() { return Err(MountError::NotDir); }
        let blk = self.read_file_block(dir_inode, 0)?;
        match dir::lookup(&blk, name)? {
            Some(e) => Ok(e.inode),
            None    => Err(MountError::NotFound),
        }
    }

    /// Walk an absolute path from the root inode (always 2 in ext4).
    /// Returns the final inode number.
    /// # C: O(path components × dir size)
    pub fn lookup_path(&self, path: &[u8]) -> Result<u32, MountError> {
        let mut cur_ino = 2u32;
        if path.is_empty() || path[0] != b'/' { return Err(MountError::NotFound); }
        let mut i = 1usize;
        while i < path.len() {
            // Skip leading slashes.
            while i < path.len() && path[i] == b'/' { i += 1; }
            if i >= path.len() { break; }
            let start = i;
            while i < path.len() && path[i] != b'/' { i += 1; }
            let comp = &path[start..i];
            let dir_node = self.read_inode(cur_ino)?;
            cur_ino = self.lookup_in_dir(&dir_node, comp)?;
        }
        Ok(cur_ino)
    }
}

/// Write `data` (must equal one filesystem block) back to `dev`
/// at byte offset `byte_off`. The block-device contract is
/// sector-granular; we issue a whole-block Write request that
/// covers `data.len()` bytes (which must already be aligned to
/// the device sector size — caller is `write_file_block` which
/// only emits filesystem-block-sized writes).
/// # C: O(1) device I/O
fn write_byte_range(dev: &dyn BlockDevice, byte_off: u64, data: &[u8]) -> Result<(), MountError> {
    let bs = dev.block_size() as u64;
    if (byte_off % bs) != 0 || (data.len() as u64 % bs) != 0 {
        return Err(MountError::BlockIo);
    }
    let start_block = byte_off / bs;
    let n_blocks = (data.len() as u64 / bs) as u32;
    let mut req = block::BlockRequest::new_write(start_block, n_blocks, data.to_vec());
    dev.submit_sync(&mut req).map_err(|_| MountError::BlockIo)?;
    Ok(())
}

/// Read `len` bytes from `dev` starting at byte `byte_off`.
/// Translates to whole-block reads under the hood.
fn read_byte_range(dev: &dyn BlockDevice, byte_off: u64, len: usize) -> Result<Vec<u8>, MountError> {
    let bs = dev.block_size() as u64;
    let first_blk = byte_off / bs;
    let last_byte = byte_off + len as u64;
    let last_blk_excl = (last_byte + bs - 1) / bs;
    let n_blocks = (last_blk_excl - first_blk) as u32;
    let mut req = BlockRequest::new_read(first_blk, n_blocks, dev.block_size());
    dev.submit_sync(&mut req).map_err(|_| MountError::BlockIo)?;
    let inner_off = (byte_off - first_blk * bs) as usize;
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&req.buffer[inner_off .. inner_off + len]);
    Ok(out)
}
