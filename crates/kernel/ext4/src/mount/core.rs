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
        // Feature gating (Linux EXT4_FEATURE_{INCOMPAT,RO_COMPAT}_SUPP): refuse a
        // fs whose INCOMPAT bits we don't implement (layout would be misread) or
        // whose RO_COMPAT bits we can't safely write (no RO-mount path yet).
        // Catches bigalloc/meta_bg/inline_data/encrypt/… instead of silently
        // misinterpreting them.
        if (sb.feature_incompat & !crate::superblock::SUPPORTED_INCOMPAT) != 0
            || (sb.feature_ro_compat & !crate::superblock::SUPPORTED_RO_COMPAT) != 0
        {
            return Err(MountError::UnsupportedFeature);
        }
        // metadata_csum verify on mount: refuse a superblock whose stored
        // s_checksum does not match (Linux ext4_superblock_csum_verify → EFSBADCRC).
        // No-op without metadata_csum.
        if !crate::csum::verify_superblock_csum(&sb, &sb_bytes) {
            return Err(MountError::BadChecksum);
        }
        let groups = sb.group_count() as usize;
        let dsize = gdt::desc_size_for(&sb) as usize;
        let gdt_byte_offset = gdt_byte_offset_for(&sb);
        let gdt_len = groups * dsize;
        let gdt_buf = read_byte_range(&*dev, gdt_byte_offset, gdt_len)?;
        // Verify every group descriptor's bg_checksum (Linux
        // ext4_group_desc_csum_verify). A corrupt GDT slot is refused rather
        // than misinterpreted (wrong bitmap/inode-table blocks).
        if sb.has_metadata_csum() {
            for n in 0..groups {
                let off = n * dsize;
                if off + dsize > gdt_buf.len()
                    || !crate::csum::verify_group_desc_csum(&sb, n as u32, &gdt_buf[off..off + dsize]) {
                    return Err(MountError::BadChecksum);
                }
            }
        }
        let state = MountState {
            gdt_buf,
            sb_free_blocks: sb.free_blocks_count,
            sb_free_inodes: sb.free_inodes_count,
            shadow: None,
            batch: false,
            undo: Vec::new(),
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
            if s.shadow.is_some() {
                // Batch mode: record each LBA's pre-op shadow value into the
                // current op's undo frame BEFORE overwriting, so op failure can
                // restore the shared running transaction. No frame => no undo
                // (non-batch nested scope keeps the original commit-or-drop-all).
                let record = s.batch && !s.undo.is_empty();
                for i in 0..n_blocks as u64 {
                    let lba = first_blk + i;
                    let lo = (i * bs) as usize;
                    let hi = lo + bs as usize;
                    if record {
                        let prev = s.shadow.as_ref().unwrap().get(&lba).cloned();
                        // Only the EARLIEST pre-value per LBA within this frame.
                        if !s.undo.last().unwrap().iter().any(|(l, _)| *l == lba) {
                            s.undo.last_mut().unwrap().push((lba, prev));
                        }
                    }
                    s.shadow.as_mut().unwrap().insert(lba, full_buf[lo..hi].to_vec());
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
        let (already_open, batch) = { let s = self.state.lock(); (s.shadow.is_some(), s.batch) };
        if already_open {
            if !batch { return f(self); }
            // Batch mode: this op JOINS the running transaction. Push an undo
            // frame so a failure rolls back only THIS op's staged blocks (and
            // its gdt_buf/counter mutations, refreshed from the restored shadow)
            // without discarding prior batched ops. Success merges the frame up
            // (or drops it at top level, leaving the writes in the running txn).
            self.state.lock().undo.push(Vec::new());
            let r = f(self);
            match r {
                Ok(v) => { self.batch_frame_commit(); self.maybe_commit_batch()?; Ok(v) }
                Err(e) => { self.batch_frame_rollback(); Err(e) }
            }
        } else {
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
    }

    /// Enable cross-operation batching: the metadata shadow persists across
    /// `run_journaled` scopes as one running jbd2 transaction, drained by
    /// `commit_batch`. Idempotent. # C: O(1)
    pub fn begin_batch(&self) {
        let mut s = self.state.lock();
        s.batch = true;
        if s.shadow.is_none() { s.shadow = Some(alloc::collections::BTreeMap::new()); }
    }

    /// Drain + commit the running transaction as ONE jbd2 commit, then reopen an
    /// empty running shadow (batch stays active). No-op when the shadow is empty
    /// or batching is off. Durability trigger — call on fsync/sync/unmount.
    /// # C: O(N shadow blocks) — one commit + 3 flushes for the whole batch
    pub fn commit_batch(&self) -> Result<(), MountError> {
        let staged: Vec<StagedBlock> = {
            let mut s = self.state.lock();
            if !s.batch { return Ok(()); }
            let drained = match s.shadow.take() { Some(m) => m, None => Default::default() };
            s.shadow = Some(alloc::collections::BTreeMap::new()); // fresh running txn
            drained.into_iter().map(|(target_lba, data)| StagedBlock { target_lba, data }).collect()
        };
        if !staged.is_empty() { let _ = self.commit_metadata(staged)?; }
        Ok(())
    }

    /// Size-triggered auto-commit: keep the running transaction bounded so its
    /// memory stays small and durability is periodic (Linux jbd2 commits on
    /// buffer pressure too). Fires only at a top-level batched op boundary.
    /// # C: amortized O(1); O(N) on the commit tick.
    fn maybe_commit_batch(&self) -> Result<(), MountError> {
        const BATCH_MAX_BLOCKS: usize = 512; // ~2 MiB of staged metadata
        let over = { let s = self.state.lock();
            s.undo.is_empty() && s.shadow.as_ref().map_or(0, |m| m.len()) >= BATCH_MAX_BLOCKS };
        if over { self.commit_batch()?; }
        Ok(())
    }

    /// Op succeeded: merge its undo frame into the parent (so an enclosing op's
    /// failure still rolls these writes back), or drop it at top level. # C: O(frame)
    fn batch_frame_commit(&self) {
        let mut s = self.state.lock();
        let frame = match s.undo.pop() { Some(f) => f, None => return };
        if let Some(parent) = s.undo.last_mut() {
            for (lba, prev) in frame {
                if !parent.iter().any(|(l, _)| *l == lba) { parent.push((lba, prev)); }
            }
        }
    }

    /// Op failed: replay its undo frame to restore the shared shadow to the
    /// pre-op state, then refresh the in-memory gdt_buf + free counters from the
    /// restored shadow/disk (they mirror shadow-staged blocks). # C: O(frame)
    fn batch_frame_rollback(&self) {
        let frame = { let mut s = self.state.lock(); s.undo.pop().unwrap_or_default() };
        {
            let mut s = self.state.lock();
            if let Some(shadow) = s.shadow.as_mut() {
                for (lba, prev) in frame.into_iter().rev() {
                    match prev { Some(bytes) => { shadow.insert(lba, bytes); }
                                 None => { shadow.remove(&lba); } }
                }
            }
        }
        // Mirrors of shadow-staged metadata: reload from the restored state so a
        // failed alloc/free doesn't leave gdt_buf / free-counters diverged.
        self.refresh_cached_meta();
    }

    /// Reload the in-memory `gdt_buf` + free counters from the (shadow-aware)
    /// current metadata, used after a batch op rollback: those mirrors are
    /// mutated in place by alloc/free and persisted to the shadow, so restoring
    /// the shadow requires re-reading them to stay in step. # C: O(gdt size) I/O
    fn refresh_cached_meta(&self) {
        // ext4 superblock field offsets (bytes into the 1024-byte SB @ byte 1024).
        const SB_BYTE_OFF: u64 = 1024;
        const SB_FREE_BLOCKS_LO: usize = 0x0C;
        const SB_FREE_INODES:    usize = 0x10;
        const SB_FREE_BLOCKS_HI: usize = 0x158;
        const SB_READ_LEN: usize = SB_FREE_BLOCKS_HI + 4;
        let gdt_off = gdt_byte_offset_for(&self.sb);
        let gdt_len = self.state.lock().gdt_buf.len();
        if let Ok(bytes) = self.read_meta_byte_range(gdt_off, gdt_len) {
            self.state.lock().gdt_buf = bytes;
        }
        if let Ok(sbb) = self.read_meta_byte_range(SB_BYTE_OFF, SB_READ_LEN) {
            let fb_lo = u32::from_le_bytes([sbb[SB_FREE_BLOCKS_LO], sbb[SB_FREE_BLOCKS_LO+1],
                                            sbb[SB_FREE_BLOCKS_LO+2], sbb[SB_FREE_BLOCKS_LO+3]]) as u64;
            let fb_hi = u32::from_le_bytes([sbb[SB_FREE_BLOCKS_HI], sbb[SB_FREE_BLOCKS_HI+1],
                                            sbb[SB_FREE_BLOCKS_HI+2], sbb[SB_FREE_BLOCKS_HI+3]]) as u64;
            let fi = u32::from_le_bytes([sbb[SB_FREE_INODES], sbb[SB_FREE_INODES+1],
                                         sbb[SB_FREE_INODES+2], sbb[SB_FREE_INODES+3]]);
            let mut s = self.state.lock();
            s.sb_free_blocks = (fb_hi << 32) | fb_lo;
            s.sb_free_inodes = fi;
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
