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
use crate::jbd2::StagedBlock;

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
    /// In-memory shadow buffer used during a `run_journaled`
    /// scope: keyed by target fs LBA, value = the new contents
    /// of that fs-block. `metadata_write` populates this; reads
    /// (`read_byte_range_pub`) consult it before going to disk
    /// so that staged-but-uncommitted bytes are visible to
    /// subsequent ops within the same scope. Drained at scope
    /// close + committed as one JBD2 transaction.
    pub(crate) shadow: Option<alloc::collections::BTreeMap<u64, Vec<u8>>>,
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
            shadow: None,
        };
        let m = Self { dev, sb, state: Spinlock::new(state) };
        // Run JBD2 replay before allowing any writes. No-op for
        // images without a journal or with a clean log.
        let _ = m.recover_journal();
        Ok(m)
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

    /// Metadata write: RMWs the affected fs block(s). Inside a
    /// `run_journaled` scope, stages the resulting full-block
    /// payloads in the in-memory shadow buffer (later reads from
    /// the same LBA see the new bytes); the scope close commits
    /// all shadow blocks as one JBD2 transaction. Outside any
    /// scope, commits immediately as its own transaction.
    /// # C: O(N affected fs blocks) RMW + (in-scope: O(1) stage / out-of-scope: 1 journal txn)
    pub fn metadata_write(&self, byte_off: u64, data: &[u8]) -> Result<(), MountError> {
        let bs = self.sb.block_size as u64;
        let first_blk = byte_off / bs;
        let last_byte = byte_off + data.len() as u64;
        let last_blk_excl = (last_byte + bs - 1) / bs;
        let n_blocks = (last_blk_excl - first_blk) as u32;
        let inner_off = (byte_off - first_blk * bs) as usize;
        // Build the post-RMW full-block buffer. For each affected
        // block, prefer the shadow's existing copy; otherwise read
        // from disk.
        let mut full_buf: Vec<u8> = Vec::with_capacity((n_blocks as usize) * bs as usize);
        for i in 0..n_blocks as u64 {
            let lba = first_blk + i;
            let block_bytes = self.read_metadata_block(lba)?;
            full_buf.extend_from_slice(&block_bytes);
        }
        full_buf[inner_off .. inner_off + data.len()].copy_from_slice(data);
        // Decide: stage in shadow, or commit immediately.
        let in_scope = self.state.lock().shadow.is_some();
        if in_scope {
            let mut s = self.state.lock();
            let shadow = s.shadow.as_mut().unwrap();
            for i in 0..n_blocks as u64 {
                let lba = first_blk + i;
                let lo = (i * bs) as usize;
                let hi = lo + bs as usize;
                shadow.insert(lba, full_buf[lo..hi].to_vec());
            }
            Ok(())
        } else {
            let mut staged = Vec::with_capacity(n_blocks as usize);
            for i in 0..n_blocks as u64 {
                let lba = first_blk + i;
                let lo = (i * bs) as usize;
                let hi = lo + bs as usize;
                staged.push(StagedBlock {
                    target_lba: lba,
                    data:       full_buf[lo..hi].to_vec(),
                });
            }
            let _ = self.commit_metadata(staged)?;
            Ok(())
        }
    }

    /// Read one fs-block from either the shadow buffer (if a
    /// scope holds a copy) or the underlying device.
    /// # C: O(1) shadow lookup or O(1) device I/O
    pub(crate) fn read_metadata_block(&self, lba: u64) -> Result<Vec<u8>, MountError> {
        if let Some(buf) = {
            let s = self.state.lock();
            s.shadow.as_ref().and_then(|m| m.get(&lba).cloned())
        } {
            return Ok(buf);
        }
        let bs = self.sb.block_size as u64;
        read_byte_range(&*self.dev, lba * bs, self.sb.block_size as usize)
    }

    /// Open a shadow scope: every `metadata_write` inside `f`
    /// populates `state.shadow` with the new fs-block bytes;
    /// shadow-aware reads (`read_metadata_block`, `read_meta_byte_range`)
    /// see the staged bytes immediately, so multiple sub-ops
    /// (e.g. two `alloc_block` calls) within one fs op observe
    /// each other's writes. At scope close, the shadow drains
    /// into `commit_metadata` as one JBD2 transaction. On
    /// `Err`, the shadow is dropped (no commit, no target writes).
    ///
    /// Re-entrant: nested calls participate in the outermost
    /// shadow without opening a new one.
    /// # C: O(N shadow blocks) commit + 2 journal I/Os + N target I/Os
    pub fn run_journaled<R, F>(&self, f: F) -> Result<R, MountError>
    where F: FnOnce(&Self) -> Result<R, MountError>
    {
        let already_open = self.state.lock().shadow.is_some();
        if already_open { return f(self); }
        self.state.lock().shadow = Some(alloc::collections::BTreeMap::new());
        let r = f(self);
        let shadow = self.state.lock().shadow.take().unwrap_or_default();
        match r {
            Ok(v) => {
                if !shadow.is_empty() {
                    let staged: Vec<StagedBlock> = shadow.into_iter()
                        .map(|(target_lba, data)| StagedBlock { target_lba, data })
                        .collect();
                    let _ = self.commit_metadata(staged)?;
                }
                Ok(v)
            }
            Err(e) => Err(e),
        }
    }

    /// No-op alias kept for legacy call sites. The shadow
    /// scope mid-flushes implicitly through `metadata_write`
    /// populating state.shadow which subsequent reads consult.
    /// # C: O(1)
    pub fn flush_pending_tx(&self) -> Result<(), MountError> { Ok(()) }

    /// Read `len` bytes starting at `byte_off`, splicing in
    /// shadow-buffered fs-block bytes where present. Use this
    /// in metadata read paths inside a `run_journaled` scope so
    /// staged-but-uncommitted writes are visible.
    /// # C: O(N affected fs blocks)
    pub fn read_meta_byte_range(&self, byte_off: u64, len: usize) -> Result<Vec<u8>, MountError> {
        let bs = self.sb.block_size as u64;
        let first_blk = byte_off / bs;
        let last_byte = byte_off + len as u64;
        let last_blk_excl = (last_byte + bs - 1) / bs;
        let n_blocks = (last_blk_excl - first_blk) as u32;
        let inner_off = (byte_off - first_blk * bs) as usize;
        let mut full = Vec::with_capacity((n_blocks as usize) * bs as usize);
        for i in 0..n_blocks as u64 {
            full.extend_from_slice(&self.read_metadata_block(first_blk + i)?);
        }
        Ok(full[inner_off .. inner_off + len].to_vec())
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
        let hdr = inode::parse_extent_header(&inode.i_block)?;
        if hdr.depth == 0 {
            return self.read_file_block_from_leaves(&inode.i_block, &hdr, file_blk);
        }
        if hdr.depth > 2 { return Err(MountError::DepthUnsupported); }
        // depth > 0: walk inline idx records, descend into the
        // child block whose `block` covers `file_blk`. Inline
        // idx records share i_block with their header.
        let child_lba = self.find_child_for(&inode.i_block, &hdr, file_blk)?;
        // Child block: [ExtentHeader | records]. Read it.
        let bs = self.sb.block_size as usize;
        let child = read_byte_range(&*self.dev, child_lba * (bs as u64), bs)?;
        let chdr = inode::parse_extent_header_slice(&child)?;
        if chdr.depth == 0 {
            self.read_file_block_from_leaves_slice(&child, &chdr, file_blk)
        } else {
            // depth=2: one more level. Recurse via finding
            // child_lba inside this child's idx records.
            let next_child_lba = self.find_child_for_slice(&child, &chdr, file_blk)?;
            let leaf = read_byte_range(&*self.dev, next_child_lba * (bs as u64), bs)?;
            let lhdr = inode::parse_extent_header_slice(&leaf)?;
            if lhdr.depth != 0 { return Err(MountError::DepthUnsupported); }
            self.read_file_block_from_leaves_slice(&leaf, &lhdr, file_blk)
        }
    }

    /// Inline-i_block leaf walk (depth==0).
    fn read_file_block_from_leaves(&self, i_block: &[u8; inode::I_BLOCK_LEN],
                                    hdr: &inode::ExtentHeader, file_blk: u32)
        -> Result<Vec<u8>, MountError>
    {
        for i in 0..hdr.entries {
            let e = inode::parse_inline_extent(i_block, hdr, i)
                .ok_or(MountError::NotFound)?;
            if file_blk >= e.block && file_blk < e.block + e.len as u32 {
                let phys = e.start_lba() + (file_blk - e.block) as u64;
                let byte_off = phys * (self.sb.block_size as u64);
                return read_byte_range(&*self.dev, byte_off, self.sb.block_size as usize);
            }
        }
        Err(MountError::NotFound)
    }

    /// Slice variant of leaf walk for child blocks (which are
    /// fs-block-sized, not 60 bytes).
    fn read_file_block_from_leaves_slice(&self, buf: &[u8],
                                          hdr: &inode::ExtentHeader, file_blk: u32)
        -> Result<Vec<u8>, MountError>
    {
        for i in 0..hdr.entries {
            let e = inode::parse_inline_extent_slice(buf, hdr, i)
                .ok_or(MountError::NotFound)?;
            if file_blk >= e.block && file_blk < e.block + e.len as u32 {
                let phys = e.start_lba() + (file_blk - e.block) as u64;
                let byte_off = phys * (self.sb.block_size as u64);
                return read_byte_range(&*self.dev, byte_off, self.sb.block_size as usize);
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

    /// Shadow-aware companion to `read_file_block`: walks the
    /// extent tree to find the physical LBA, then reads it via
    /// the shadow buffer if a scope holds a copy.
    /// # C: O(N_extents) walk + 1 block I/O (or shadow hit)
    pub fn read_file_block_meta(&self, inode: &Inode, file_blk: u32)
        -> Result<Vec<u8>, MountError>
    {
        let hdr = inode::parse_extent_header(&inode.i_block)?;
        if hdr.depth != 0 { return Err(MountError::DepthUnsupported); }
        for i in 0..hdr.entries {
            let e = inode::parse_inline_extent(&inode.i_block, &hdr, i)
                .ok_or(MountError::NotFound)?;
            if file_blk >= e.block && file_blk < e.block + e.len as u32 {
                let phys = e.start_lba() + (file_blk - e.block) as u64;
                return self.read_metadata_block(phys);
            }
        }
        Err(MountError::NotFound)
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
        let hdr = inode::parse_extent_header(&inode.i_block)?;
        if hdr.depth != 0 { return Err(MountError::DepthUnsupported); }
        for i in 0..hdr.entries {
            let e = inode::parse_inline_extent(&inode.i_block, &hdr, i)
                .ok_or(MountError::NotFound)?;
            if file_blk >= e.block && file_blk < e.block + e.len as u32 {
                let phys = e.start_lba() + (file_blk - e.block) as u64;
                let byte_off = phys * (self.sb.block_size as u64);
                return self.metadata_write(byte_off, data);
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
        let mut blk = self.read_file_block_meta(&dir_node, 0)?;
        match dir::insert(&mut blk, child_ino, file_type, name) {
            Err(dir::DirError::Full) => return Err(MountError::DirFull),
            Err(e) => return Err(MountError::Dir(e)),
            Ok(()) => {}
        }
        self.run_journaled(|m| m.write_file_block_meta(&dir_node, 0, &blk))
    }

    /// Remove `name` from directory `dir_ino`. Returns the inode
    /// number of the unlinked target (caller decrements its
    /// link count + frees blocks/inode when nlink reaches 0).
    /// # C: O(N entries) walk + 2 block I/Os
    pub fn dir_unlink(&self, dir_ino: u32, name: &[u8]) -> Result<u32, MountError> {
        let dir_node = self.read_inode(dir_ino)?;
        if !dir_node.is_dir() { return Err(MountError::NotDir); }
        let mut blk = self.read_file_block_meta(&dir_node, 0)?;
        let removed = match dir::remove(&mut blk, name) {
            Err(dir::DirError::NotFound) => return Err(MountError::NotFound),
            Err(e) => return Err(MountError::Dir(e)),
            Ok(n) => n,
        };
        self.run_journaled(|m| m.write_file_block_meta(&dir_node, 0, &blk))?;
        Ok(removed)
    }

    /// Look `name` up in the directory. Walks all data blocks
    /// covered by the inode's `i_size`, not just the first —
    /// rootfs `/bin` overflows one 1 KiB block once we stage
    /// more than ~25 hardlinks alongside the busybox applets.
    /// # C: O(N_entries)
    pub fn lookup_in_dir(&self, dir_inode: &Inode, name: &[u8]) -> Result<u32, MountError> {
        if !dir_inode.is_dir() { return Err(MountError::NotDir); }
        let block_size = self.sb.block_size as u64;
        let total = dir_inode.size;
        let nblocks = ((total + block_size - 1) / block_size) as u32;
        for fb in 0..nblocks {
            let blk = self.read_file_block(dir_inode, fb)?;
            match dir::lookup(&blk, name)? {
                Some(e) => return Ok(e.inode),
                None    => continue,
            }
        }
        Err(MountError::NotFound)
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

/// Write `data` to `dev` at byte offset `byte_off`. RMW for any
/// partial-block write — `data` need not be sector-multiple.
/// Direct device write only — does NOT consult any journal scope.
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
/// # C: O(1)
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
