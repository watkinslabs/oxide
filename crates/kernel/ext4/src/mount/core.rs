use alloc::vec::Vec;

use crate::gdt;
use crate::jbd2::StagedBlock;
use crate::superblock::{SUPERBLOCK_LEN, SUPERBLOCK_OFFSET, Superblock};

use super::{GroupDesc, Mount, MountError, MountState};
use super::io::read_byte_range;

impl Mount {
    /// Open the filesystem on `dev`. Reads + parses the
    /// superblock + group descriptor table.
    /// # C: O(N_groups * desc_size + 1024)
    pub fn open(dev: alloc::sync::Arc<dyn block::BlockDevice>) -> Result<Self, MountError> {
        let sb_bytes = read_byte_range(&*dev, SUPERBLOCK_OFFSET, SUPERBLOCK_LEN)?;
        let sb = Superblock::parse(&sb_bytes)?;
        let groups = sb.group_count() as usize;
        let dsize = gdt::desc_size_for(&sb) as usize;
        let gdt_byte_offset = gdt_byte_offset_for(&sb);
        let gdt_len = groups * dsize;
        let gdt_buf = read_byte_range(&*dev, gdt_byte_offset, gdt_len)?;
        let state = MountState {
            gdt_buf,
            sb_free_blocks: sb.free_blocks_count,
            sb_free_inodes: sb.free_inodes_count,
            shadow: None,
        };
        let m = Self { dev, sb, state: sync::Spinlock::new(state) };
        let _ = m.recover_journal();
        let _ = m.orphan_cleanup();
        Ok(m)
    }

    /// Byte offset of the GDT on disk. Block 2 for 1 KiB-block
    /// images (block 0 = boot, block 1 = sb), block 1 otherwise
    /// (block 0 contains pad + sb at offset 1024).
    /// # C: O(1)
    pub fn gdt_byte_offset(&self) -> u64 { gdt_byte_offset_for(&self.sb) }

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
        let mut full_buf: Vec<u8> = Vec::with_capacity((n_blocks as usize) * bs as usize);
        for i in 0..n_blocks as u64 {
            let lba = first_blk + i;
            let block_bytes = self.read_metadata_block(lba)?;
            full_buf.extend_from_slice(&block_bytes);
        }
        full_buf[inner_off .. inner_off + data.len()].copy_from_slice(data);
        {
            let mut s = self.state.lock();
            if let Some(shadow) = s.shadow.as_mut() {
                for i in 0..n_blocks as u64 {
                    let lba = first_blk + i;
                    let lo = (i * bs) as usize;
                    let hi = lo + bs as usize;
                    shadow.insert(lba, full_buf[lo..hi].to_vec());
                }
                return Ok(());
            }
        }
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
}

fn gdt_byte_offset_for(sb: &Superblock) -> u64 {
    if sb.block_size == 1024 {
        (sb.block_size as u64) * 2
    } else {
        sb.block_size as u64
    }
}
