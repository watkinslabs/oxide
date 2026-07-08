use alloc::vec::Vec;

use crate::gdt;
use crate::inode::{self, Inode, InodeError};

use super::{Mount, MountError};
use super::io::{read_byte_range, write_byte_range};

impl Mount {
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
        let buf = self.read_meta_byte_range(byte_off, self.sb.inode_size as usize)?;
        Ok(Inode::parse(&buf, &self.sb)?)
    }

    /// Read the data of `inode`'s `file_blk`-th logical block.
    /// Walks the extent tree top-down: at depth=0 finds a leaf
    /// extent and returns its data; at depth>0 finds the child
    /// extent_idx whose subtree covers `file_blk`, reads the
    /// child block (extent_header + records), recurses.
    /// v1 supports up to depth=2 (one level of interior nodes
    /// + leaves); deeper trees surface DepthUnsupported.
    /// # C: O(depth × log N) — small constant in practice
    pub fn read_file_block(&self, inode: &Inode, file_blk: u32) -> Result<Vec<u8>, MountError> {
        let phys = self.resolve_pblock(&inode.i_block, file_blk)?;
        let byte_off = phys * (self.sb.block_size as u64);
        read_byte_range(&*self.dev, byte_off, self.sb.block_size as usize)
    }

    /// Map a file-logical block → physical LBA by descending the extent
    /// tree from the inode `i_block` through ANY number of interior levels
    /// (depth 0..=5 per the ext4 spec — Linux `ext4_ext_binsearch`/
    /// `ext4_find_extent`). Replaces the old depth-0/1/2 hand-unroll that
    /// returned `DepthUnsupported` past depth 2.
    /// # C: O(depth) block I/Os + O(entries) per level
    pub(crate) fn resolve_pblock(&self, i_block: &[u8; inode::I_BLOCK_LEN], file_blk: u32)
        -> Result<u64, MountError>
    {
        let hdr = inode::parse_extent_header(i_block)?;
        if hdr.depth == 0 {
            return self.leaf_pblock_inline(i_block, &hdr, file_blk);
        }
        let bs = self.sb.block_size as usize;
        let mut child_lba = self.find_child_for(i_block, &hdr, file_blk)?;
        loop {
            let buf = read_byte_range(&*self.dev, child_lba * (bs as u64), bs)?;
            let chdr = inode::parse_extent_header_slice(&buf)?;
            if chdr.depth == 0 {
                return self.leaf_pblock_slice(&buf, &chdr, file_blk);
            }
            child_lba = self.find_child_for_slice(&buf, &chdr, file_blk)?;
        }
    }

    /// Leaf (depth-0) lookup against the inline i_block → physical LBA.
    fn leaf_pblock_inline(&self, i_block: &[u8; inode::I_BLOCK_LEN],
                          hdr: &inode::ExtentHeader, file_blk: u32) -> Result<u64, MountError> {
        for i in 0..hdr.entries {
            let e = inode::parse_inline_extent(i_block, hdr, i).ok_or(MountError::BlockIo)?;
            if file_blk >= e.block && file_blk < e.block + e.real_len() {
                if e.is_unwritten() { return Err(MountError::NotFound); }
                return Ok(e.start_lba() + (file_blk - e.block) as u64);
            }
        }
        Err(MountError::NotFound)
    }

    /// Leaf (depth-0) lookup against a child block slice → physical LBA.
    fn leaf_pblock_slice(&self, buf: &[u8], hdr: &inode::ExtentHeader, file_blk: u32)
        -> Result<u64, MountError>
    {
        for i in 0..hdr.entries {
            let e = inode::parse_inline_extent_slice(buf, hdr, i).ok_or(MountError::BlockIo)?;
            if file_blk >= e.block && file_blk < e.block + e.real_len() {
                if e.is_unwritten() { return Err(MountError::NotFound); }
                return Ok(e.start_lba() + (file_blk - e.block) as u64);
            }
        }
        Err(MountError::NotFound)
    }

    /// Inline-i_block idx walk (depth>0).
    fn find_child_for(&self, i_block: &[u8; inode::I_BLOCK_LEN],
                      hdr: &inode::ExtentHeader, file_blk: u32)
        -> Result<u64, MountError>
    {
        let mut best: Option<inode::ExtentIdx> = None;
        for i in 0..hdr.entries {
            let idx = inode::parse_extent_idx(i_block, hdr, i)
                .ok_or(MountError::NotFound)?;
            if idx.block <= file_blk {
                match best {
                    Some(b) if b.block >= idx.block => {}
                    _ => best = Some(idx),
                }
            }
        }
        best.map(|b| b.leaf_lba()).ok_or(MountError::NotFound)
    }

    fn find_child_for_slice(&self, buf: &[u8], hdr: &inode::ExtentHeader, file_blk: u32)
        -> Result<u64, MountError>
    {
        let mut best: Option<inode::ExtentIdx> = None;
        for i in 0..hdr.entries {
            let idx = inode::parse_extent_idx_slice(buf, hdr, i)
                .ok_or(MountError::NotFound)?;
            if idx.block <= file_blk {
                match best {
                    Some(b) if b.block >= idx.block => {}
                    _ => best = Some(idx),
                }
            }
        }
        best.map(|b| b.leaf_lba()).ok_or(MountError::NotFound)
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
        let phys = self.resolve_pblock(&inode.i_block, file_blk)?;
        let byte_off = phys * (self.sb.block_size as u64);
        write_byte_range(&*self.dev, byte_off, data)
    }

    /// Shadow-aware companion to `read_file_block`: walks the
    /// extent tree to find the physical LBA, then reads it via
    /// the shadow buffer if a scope holds a copy.
    /// # C: O(N_extents) walk + 1 block I/O (or shadow hit)
    pub fn read_file_block_meta(&self, inode: &Inode, file_blk: u32)
        -> Result<Vec<u8>, MountError>
    {
        let phys = self.resolve_pblock(&inode.i_block, file_blk)?;
        self.read_metadata_block(phys)
    }

    /// Like `write_file_block` but routes through `metadata_write`
    /// — the block being written is part of a metadata-fs structure
    /// (e.g. a directory's data block) and must be journaled when
    /// a journal scope is open.
    /// # C: O(N_extents) walk + 1 block I/O (or staging)
    pub fn write_file_block_meta(
        &self,
        inode:    &Inode,
        file_blk: u32,
        data:     &[u8],
    ) -> Result<(), MountError> {
        if data.len() != self.sb.block_size as usize {
            return Err(MountError::Inode(InodeError::BadLen));
        }
        let phys = self.resolve_pblock(&inode.i_block, file_blk)?;
        let byte_off = phys * (self.sb.block_size as u64);
        self.metadata_write(byte_off, data)
    }

    /// Convert the UNWRITTEN extent covering logical block `file_blk` to a
    /// written (initialized) extent, in place. Linux `fallocate` leaves
    /// preallocated ranges as "unwritten" extents (`len` top bit set / `len >
    /// 32768`) whose backing blocks may hold arbitrary on-disk bytes but which
    /// READ as zeros; a write into such a range must make the not-yet-written
    /// blocks read as their true zero value AND flip the extent to initialized
    /// so the write persists and is visible on read. Our own fallocate is eager
    /// (never produces unwritten extents), but a PREBUILT rootfs image
    /// (mkfs/fallocate on real Linux) carries them — notably systemd-journald's
    /// preallocated `system.journal`, whose mmap writeback failed with
    /// `NotFound` (`leaf_pblock_*` rejects unwritten) before this path,
    /// re-dirtying the page forever and silently losing every log line.
    ///
    /// Strategy: zero the WHOLE extent's blocks on disk (so blocks the caller
    /// does not overwrite still read as zeros — the unwritten-read contract),
    /// then clear the unwritten flag in the extent record and persist it (inode
    /// i_block for depth 0, the covering leaf block for depth>0). No split
    /// needed; matches our eager-fallocate model. No-op when `file_blk` already
    /// maps to a written extent or a hole. MUST run inside a `run_journaled`
    /// scope (write_at does): the flag-clear stages in the shadow and commits
    /// atomically; block zeroing is direct data I/O sequenced before the commit.
    /// # C: O(real_len) zero I/O + O(depth) walk + O(1) metadata persist
    pub(crate) fn convert_unwritten_at(&self, ino: u32, file_blk: u32) -> Result<(), MountError> {
        let (mut ibytes, _off) = self.read_inode_bytes(ino)?;
        let mut i_block = [0u8; inode::I_BLOCK_LEN];
        i_block.copy_from_slice(&ibytes[0x28..0x28 + inode::I_BLOCK_LEN]);
        let hdr = inode::parse_extent_header(&i_block)?;
        if hdr.depth == 0 {
            for i in 0..hdr.entries {
                let e = inode::parse_inline_extent(&i_block, &hdr, i).ok_or(MountError::BlockIo)?;
                if file_blk >= e.block && file_blk < e.block + e.real_len() {
                    if !e.is_unwritten() { return Ok(()); }
                    self.zero_extent_blocks(e.start_lba(), e.real_len())?;
                    let mut ew = e;
                    ew.len = e.real_len() as u16;                 // clear the unwritten flag
                    inode::write_inline_extent(&mut i_block, i, &ew);
                    ibytes[0x28..0x28 + inode::I_BLOCK_LEN].copy_from_slice(&i_block);
                    return self.write_inode_bytes(ino, &ibytes);
                }
            }
            return Ok(());                                        // hole
        }
        let bs = self.sb.block_size as u64;
        let mut child_lba = self.find_child_for(&i_block, &hdr, file_blk)?;
        loop {
            let mut buf = self.read_metadata_block(child_lba)?;
            let chdr = inode::parse_extent_header_slice(&buf)?;
            if chdr.depth == 0 {
                for i in 0..chdr.entries {
                    let e = inode::parse_inline_extent_slice(&buf, &chdr, i).ok_or(MountError::BlockIo)?;
                    if file_blk >= e.block && file_blk < e.block + e.real_len() {
                        if !e.is_unwritten() { return Ok(()); }
                        self.zero_extent_blocks(e.start_lba(), e.real_len())?;
                        let mut ew = e;
                        ew.len = e.real_len() as u16;
                        inode::write_inline_extent_slice(&mut buf, i, &ew);
                        return self.metadata_write(child_lba * bs, &buf);
                    }
                }
                return Ok(());
            }
            child_lba = self.find_child_for_slice(&buf, &chdr, file_blk)?;
        }
    }

    /// Zero `len` filesystem blocks starting at physical LBA `start_lba` (direct
    /// data write, not journaled) — the not-yet-written blocks of an
    /// unwritten extent being initialized. # C: O(len) block I/O
    fn zero_extent_blocks(&self, start_lba: u64, len: u32) -> Result<(), MountError> {
        let bs = self.sb.block_size as usize;
        let zero = alloc::vec![0u8; bs];
        for i in 0..len as u64 {
            write_byte_range(&*self.dev, (start_lba + i) * (bs as u64), &zero)?;
        }
        Ok(())
    }

    /// Read `(i_flags, i_generation)` for `ino` from its raw slot.
    /// `i_flags` drives the htree (`EXT4_INDEX_FL`) branch; the
    /// generation keys the dir-block metadata_csum.
    /// # C: O(1) I/O
    pub fn inode_flags_gen(&self, ino: u32) -> Result<(u32, u32), MountError> {
        let (raw, _) = self.read_inode_bytes(ino)?;
        let flags = u32::from_le_bytes([raw[0x20], raw[0x21], raw[0x22], raw[0x23]]);
        let gen   = u32::from_le_bytes([raw[0x64], raw[0x65], raw[0x66], raw[0x67]]);
        Ok((flags, gen))
    }
}
