use alloc::vec::Vec;

use crate::gdt;
use crate::jbd2::StagedBlock;
use crate::superblock::{SUPERBLOCK_LEN, SUPERBLOCK_OFFSET, Superblock};

use super::{GroupDesc, Mount, MountError, MountState};
use super::io::read_byte_range;

/// Kernel: fn returning a unique id for the current execution CONTEXT (task).
/// The reentrant transaction gate keys ownership on this so a task that sleeps
/// mid-transaction (at I/O) is not mistaken for a different task on the same CPU.
/// 0 ⇒ unset (early single-threaded boot) → `ctx_id` returns 1.
#[cfg(target_os = "oxide-kernel")]
static CTX_ID_HOOK: ::core::sync::atomic::AtomicU64 = ::core::sync::atomic::AtomicU64::new(0);

/// Register the current-context id source. kmain calls this once (before the
/// rootfs mount / SMP bring-up) with a fn returning the current task id.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn set_ctx_id_hook(f: fn() -> u64) {
    CTX_ID_HOOK.store(f as usize as u64, ::core::sync::atomic::Ordering::Release);
}

/// Kernel: cooperative-yield the CPU while a transaction-gate waiter spins, so
/// the current gate OWNER (which sleeps on block I/O — reads/writes/flush —
/// while holding the gate) can be scheduled and release it. A pure busy-spin
/// here deadlocks: the owner parks on I/O, the waiter pins the CPU, and the
/// owner never runs to release (observed: `[CPU-STALL]` in truncate_inode).
#[cfg(target_os = "oxide-kernel")]
static YIELD_HOOK: ::core::sync::atomic::AtomicU64 = ::core::sync::atomic::AtomicU64::new(0);

/// Register the gate's spin-yield source. kmain sets this to `tick_yield`
/// (yields + opens the IRQ window so the owner's I/O completion lands).
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn set_yield_hook(f: fn()) {
    YIELD_HOOK.store(f as usize as u64, ::core::sync::atomic::Ordering::Release);
}

#[cfg(target_os = "oxide-kernel")]
fn txn_yield() {
    let raw = YIELD_HOOK.load(::core::sync::atomic::Ordering::Acquire);
    if raw == 0 { ::core::hint::spin_loop(); return; } // pre-registration boot
    // SAFETY: `raw` is a `fn()` pointer stored only by set_yield_hook (tick_yield).
    let f: fn() = unsafe { ::core::mem::transmute(raw as usize) };
    f();
}

/// Hosted: hand the OS scheduler the CPU so the gate owner thread can run.
#[cfg(not(target_os = "oxide-kernel"))]
fn txn_yield() { std::thread::yield_now(); }

pub(crate) fn cooperative_yield() { txn_yield(); }

/// Unique-per-concurrent-context id for the transaction gate.
#[cfg(target_os = "oxide-kernel")]
fn ctx_id() -> u64 {
    let raw = CTX_ID_HOOK.load(::core::sync::atomic::Ordering::Acquire);
    if raw == 0 { return 1; } // pre-registration: boot is single-threaded
    // SAFETY: `raw` is a `fn() -> u64` pointer stored only by set_ctx_id_hook.
    let f: fn() -> u64 = unsafe { ::core::mem::transmute(raw as usize) };
    let id = f();
    if id == 0 { 1 } else { id }
}

/// Hosted tests: a unique nonzero id per thread (thread-local, stable) so the
/// concurrent-churn tests exercise real cross-context serialization.
/// Host builds: a unique nonzero id per thread (thread-local, stable) so the
/// concurrent-churn tests exercise real cross-context serialization.
#[cfg(not(target_os = "oxide-kernel"))]
fn ctx_id() -> u64 {
    std::thread_local!(static ID: u64 = {
        static NEXT: ::core::sync::atomic::AtomicU64 = ::core::sync::atomic::AtomicU64::new(2);
        NEXT.fetch_add(1, ::core::sync::atomic::Ordering::Relaxed)
    });
    ID.with(|&id| id)
}

impl Mount {
    /// Open the filesystem on `dev`. Reads + parses the
    /// superblock + group descriptor table.
    /// # C: O(N_groups * desc_size + 1024)
    pub fn open(dev: alloc::sync::Arc<dyn block::BlockDevice>) -> Result<Self, MountError> {
        Self::open_with_orphan_cleanup(dev, true)
    }

    /// Open the filesystem, optionally deferring orphan cleanup to the caller.
    /// # C: O(N_groups * desc_size + 1024)
    pub(crate) fn open_with_orphan_cleanup(dev: alloc::sync::Arc<dyn block::BlockDevice>, cleanup_orphans: bool) -> Result<Self, MountError> {
        Self::open_with_behaviour(dev, cleanup_orphans, Default::default())
    }

    /// Open the filesystem with its behavioural options ALREADY decided.
    ///
    /// The options have to arrive before the open rather than after it: journal
    /// replay happens in here, and `noload`/`norecovery` is the option that
    /// says not to do it. An open that parsed its options afterwards had
    /// already replayed the log by the time it read the option asking it not
    /// to, which is why the option is passed in rather than looked up.
    /// # C: O(N_groups * desc_size + 1024)
    pub(crate) fn open_with_behaviour(
        dev: alloc::sync::Arc<dyn block::BlockDevice>,
        cleanup_orphans: bool,
        behaviour: crate::mount_opts::Ext4Behaviour,
    ) -> Result<Self, MountError> {
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
        let m = Self { dev, sb, state: sync::Spinlock::new(state), quota_sb: sync::Spinlock::new(alloc::sync::Weak::new()),
                       #[cfg(not(target_os = "oxide-kernel"))]
                       faults: super::faults::HostedFaults::new(),
                       txn_owner: ::core::sync::atomic::AtomicU64::new(0),
                       txn_depth: ::core::sync::atomic::AtomicU32::new(0),
                       creating: ::core::sync::atomic::AtomicBool::new(false),
                       opts: sync::Spinlock::new(crate::mount_opts::Ext4SbOpts {
                           behaviour, ..Default::default() }),
                       #[cfg(not(target_os = "oxide-kernel"))]
                       test_cred: sync::Spinlock::new(None) };
        // `noload`/`norecovery` decides this, and it decides it BEFORE the
        // replay rather than after. Every mount this code opens is writable, so
        // a dirty log plus the option is the combination that has no correct
        // answer and is refused here (Linux `ext4_fill_super`).
        let needs_recovery = (m.sb.feature_incompat & crate::superblock::INCOMPAT_RECOVER) != 0
            && m.sb.journal_inum != 0;
        const MOUNTED_READ_ONLY: bool = false;
        match crate::mount_opts::recovery_action(behaviour.noload, MOUNTED_READ_ONLY, needs_recovery) {
            Err(_) => return Err(MountError::UnsupportedFeature),
            Ok(crate::mount_opts::JournalRecovery::Replay) => { let _ = m.recover_journal(); }
            Ok(crate::mount_opts::JournalRecovery::Skip) => {}
        }
        if cleanup_orphans { let _ = m.orphan_cleanup(); }
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
        #[cfg(not(target_os = "oxide-kernel"))]
        if self.should_fail_metadata_write_for_tests() { return Err(MountError::BlockIo); }
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
                        // O(log n) keyed record; keep only the EARLIEST pre-value
                        // per LBA in this frame (contains_key guards the clone).
                        if !s.undo.last().unwrap().contains_key(&lba) {
                            let prev = s.shadow.as_ref().unwrap().get(&lba).cloned();
                            s.undo.last_mut().unwrap().insert(lba, prev);
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
    /// Serialize + run a top-level metadata transaction. Acquires the reentrant
    /// transaction gate for the current context so concurrent tasks/CPUs can't
    /// race the group bitmaps / GDT / superblock counters / shadow; nested
    /// same-context calls join without re-locking. # C: same as inner.
    pub fn run_journaled<R, F>(&self, f: F) -> Result<R, MountError>
    where F: FnOnce(&Self) -> Result<R, MountError>
    {
        self.txn_acquire();
        let r = self.run_journaled_inner(f);
        self.txn_release();
        r
    }

    /// Reentrant transaction-gate acquire keyed on `ctx_id()`. Nested calls on
    /// the same context bump the depth; a different context spins until free.
    /// # C: O(contention)
    pub(super) fn txn_acquire(&self) {
        use ::core::sync::atomic::Ordering;
        let me = ctx_id();
        if self.txn_owner.load(Ordering::Acquire) == me {
            self.txn_depth.fetch_add(1, Ordering::Relaxed);
            return;
        }
        while self.txn_owner.compare_exchange_weak(0, me, Ordering::AcqRel, Ordering::Relaxed).is_err() {
            // Yield (not busy-spin): the gate owner sleeps on block I/O while
            // holding the gate, so it must be able to run and release it.
            txn_yield();
        }
        self.txn_depth.store(1, Ordering::Relaxed);
    }

    /// Release one level of the transaction gate; frees it at depth 0.
    /// # C: O(1)
    pub(super) fn txn_release(&self) {
        use ::core::sync::atomic::Ordering;
        if self.txn_depth.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.txn_owner.store(0, Ordering::Release);
        }
    }

    fn run_journaled_inner<R, F>(&self, f: F) -> Result<R, MountError>
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
            self.state.lock().undo.push(alloc::collections::BTreeMap::new());
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
                Err(e) => {
                    self.refresh_cached_meta();
                    Err(e)
                }
            }
        }
    }

    /// Run a top-level create op with `creating` set (which defers the
    /// size-triggered batch commit until AFTER the transaction gate is released:
    /// the batch commit's `dev.flush` SLEEPS on the virtio completion, and
    /// yielding I/O while the gate is held livelocks a spinning contender). The
    /// gate is now taken inside `run_journaled` for EVERY mutator, so creates no
    /// longer need a separate lock; the commit still drains the shadow atomically
    /// under `state.lock`, so ordering is preserved.
    /// # C: same as the inner op + amortized O(1) deferred commit
    pub(crate) fn create_op<R, F>(&self, f: F) -> Result<R, MountError>
    where F: FnOnce(&Self) -> Result<R, MountError>
    {
        let r = {
            self.creating.store(true, ::core::sync::atomic::Ordering::Release);
            let r = self.run_journaled(f);
            self.creating.store(false, ::core::sync::atomic::Ordering::Release);
            r
        };
        let v = match r {
            Ok(v) => v,
            Err(e) => {
                self.refresh_cached_meta();
                return Err(e);
            }
        };
        self.maybe_commit_batch()?;
        Ok(v)
    }

    /// Reload the in-memory `gdt_buf` + free counters from the (shadow-aware)
    /// current metadata, used after a batch op rollback: those mirrors are
    /// mutated in place by alloc/free and persisted to the shadow, so restoring
    /// the shadow requires re-reading them to stay in step. # C: O(gdt size) I/O
    pub(crate) fn refresh_cached_meta(&self) {
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
