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
use sync::{Guard, Spinlock, Superblock as SuperblockLockClass};

use crate::dir;
use crate::gdt::{self, GdtError, GroupDesc};
use crate::inode::{self, Inode, InodeError};
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
    /// No free block/inode found in any group.
    NoSpace,
    /// Caller passed a physical block outside any group.
    BadBlock,
    /// Caller asked to free a block whose bit was already clear.
    DoubleFree,
    /// Inline extent table is full and growth into an external
    /// node is not yet supported (v1 cap = 4 inline leaves).
    ExtentTreeFull,
    /// Directory block has no free slot for a new entry and
    /// dir-block growth is not yet wired (P7b-03 minimum).
    DirFull,
}

impl From<SuperblockError> for MountError { fn from(e: SuperblockError) -> Self { MountError::Superblock(e) } }
impl From<GdtError>        for MountError { fn from(e: GdtError)        -> Self { MountError::Gdt(e) } }
impl From<InodeError>      for MountError { fn from(e: InodeError)      -> Self { MountError::Inode(e) } }
impl From<dir::DirError>   for MountError { fn from(e: dir::DirError)   -> Self { MountError::Dir(e) } }

/// Mutable cached state — locked under `state` for any RW path.
pub struct MountState {
    /// Cached GDT bytes (mirrors disk; updated on every counter
    /// edit + flushed back to the device).
    pub(crate) gdt_buf: Vec<u8>,
    /// Live free-blocks counter; mirrors `s_free_blocks_count`.
    pub(crate) sb_free_blocks: u64,
    /// Live free-inodes counter; mirrors `s_free_inodes_count`.
    pub(crate) sb_free_inodes: u32,
}

pub type MountStateGuard<'a> = Guard<'a, MountState, SuperblockLockClass>;

/// Mounted ext4 filesystem.
pub struct Mount {
    pub(crate) dev: Arc<dyn BlockDevice>,
    pub sb: Superblock,
    pub(crate) state: Spinlock<MountState, SuperblockLockClass>,
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
        let state = MountState {
            gdt_buf,
            sb_free_blocks: sb.free_blocks_count,
            sb_free_inodes: sb.free_inodes_count,
        };
        Ok(Self { dev, sb, state: Spinlock::new(state) })
    }

    /// Byte offset of the GDT on disk. Block 2 for 1 KiB-block
    /// images (block 0 = boot, block 1 = sb), block 1 otherwise
    /// (block 0 contains pad + sb at offset 1024).
    /// # C: O(1)
    pub fn gdt_byte_offset(&self) -> u64 {
        if self.sb.block_size == 1024 {
            (self.sb.block_size as u64) * 2
        } else {
            self.sb.block_size as u64
        }
    }

    /// Look up the `n`-th group descriptor.
    /// # C: O(1)
    pub fn group_desc(&self, n: u32) -> Result<GroupDesc, MountError> {
        let g = self.state.lock();
        Ok(gdt::parse_descriptor(&g.gdt_buf, n, &self.sb)?)
    }

    /// Live free-blocks counter (mirrors `s_free_blocks_count`).
    /// # C: O(1)
    pub fn state_free_blocks(&self) -> u64 { self.state.lock().sb_free_blocks }

    /// Live free-inodes counter.
    /// # C: O(1)
    pub fn state_free_inodes(&self) -> u32 { self.state.lock().sb_free_inodes }

    /// Read inode `ino` (1-indexed) from disk.
    /// # C: O(1) I/O + O(1) parse
    pub fn read_inode(&self, ino: u32) -> Result<Inode, MountError> {
        let (group, idx) = gdt::locate_inode(&self.sb, ino)?;
        let gd = {
            let g = self.state.lock();
            gdt::parse_descriptor(&g.gdt_buf, group, &self.sb)?
        };
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

    /// Add a `name → child_ino` entry to directory `dir_ino`.
    /// Reads dir's first data block, splices a new dir_entry_2,
    /// writes the block back. `DirFull` if no slack.
    /// # C: O(N entries) walk + 2 block I/Os
    pub fn dir_link(&self, dir_ino: u32, name: &[u8], child_ino: u32, file_type: u8)
        -> Result<(), MountError>
    {
        let dir_node = self.read_inode(dir_ino)?;
        if !dir_node.is_dir() { return Err(MountError::NotDir); }
        let mut blk = self.read_file_block(&dir_node, 0)?;
        match dir::insert(&mut blk, child_ino, file_type, name) {
            Err(dir::DirError::Full) => return Err(MountError::DirFull),
            Err(e) => return Err(MountError::Dir(e)),
            Ok(()) => {}
        }
        // Write block 0 back through the existing in-place extent
        // write path (which does the extent walk + bs-aligned write).
        self.write_file_block(&dir_node, 0, &blk)
    }

    /// Remove `name` from directory `dir_ino`. Returns the inode
    /// number of the unlinked target (caller decrements its
    /// link count + frees blocks/inode when nlink reaches 0).
    /// # C: O(N entries) walk + 2 block I/Os
    pub fn dir_unlink(&self, dir_ino: u32, name: &[u8]) -> Result<u32, MountError> {
        let dir_node = self.read_inode(dir_ino)?;
        if !dir_node.is_dir() { return Err(MountError::NotDir); }
        let mut blk = self.read_file_block(&dir_node, 0)?;
        let removed = match dir::remove(&mut blk, name) {
            Err(dir::DirError::NotFound) => return Err(MountError::NotFound),
            Err(e) => return Err(MountError::Dir(e)),
            Ok(n) => n,
        };
        self.write_file_block(&dir_node, 0, &blk)?;
        Ok(removed)
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

/// Write `data` to `dev` at byte offset `byte_off`. Read-modify-
/// writes the leading + trailing partial blocks so unaligned
/// (sub-sector) writes are honored — `data` need not be a multiple
/// of the device sector size.
/// # C: O(data.len() / sector_size + 2 RMW reads)
pub(crate) fn write_byte_range(dev: &dyn BlockDevice, byte_off: u64, data: &[u8])
    -> Result<(), MountError>
{
    let bs = dev.block_size() as u64;
    let first_blk = byte_off / bs;
    let last_byte = byte_off + data.len() as u64;
    let last_blk_excl = (last_byte + bs - 1) / bs;
    let n_blocks = (last_blk_excl - first_blk) as u32;
    let mut full = BlockRequest::new_read(first_blk, n_blocks, dev.block_size());
    dev.submit_sync(&mut full).map_err(|_| MountError::BlockIo)?;
    let inner_off = (byte_off - first_blk * bs) as usize;
    full.buffer[inner_off .. inner_off + data.len()].copy_from_slice(data);
    let mut wreq = BlockRequest::new_write(first_blk, n_blocks, full.buffer);
    dev.submit_sync(&mut wreq).map_err(|_| MountError::BlockIo)?;
    Ok(())
}

/// Read `len` bytes from `dev` starting at byte `byte_off`.
/// Translates to whole-block reads under the hood.
pub(crate) fn read_byte_range(dev: &dyn BlockDevice, byte_off: u64, len: usize)
    -> Result<Vec<u8>, MountError>
{
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

/// Crate-public alias so submodules (`balloc`, `extent_rw`, …) can
/// call the read helper without re-implementing block-window math.
#[inline] pub(crate) fn read_byte_range_pub(dev: &dyn BlockDevice, byte_off: u64, len: usize)
    -> Result<Vec<u8>, MountError>
{ read_byte_range(dev, byte_off, len) }
