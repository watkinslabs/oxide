use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use crate::gdt;
use crate::jbd2::StagedBlock;
use super::gdt_byte_offset_for;
use super::super::{GroupDesc, Mount, MountError};
use super::super::MetadataRead;
use super::super::io::read_byte_range;

impl Mount {
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
        {
            let mut s = self.state.lock();
            if s.running_generation == 0 {
                s.next_generation = s.next_generation.wrapping_add(1).max(1);
                s.running_generation = s.next_generation;
            }
        }
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
                s.metadata_epoch = s.metadata_epoch.wrapping_add(1);
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
        self.commit_metadata(staged.clone())?;
        self.cache_committed(&staged);
        Ok(())
    }

    /// Publish checkpointed metadata into the clean buffer cache. The running
    /// transaction's shadow remains the only source for uncheckpointed bytes.
    /// # C: O(N staged blocks)
    #[inline(never)]
    pub(in crate::mount) fn cache_committed(&self, staged: &[StagedBlock]) {
        let mut s = self.state.lock();
        s.metadata_epoch = s.metadata_epoch.wrapping_add(1);
        for block in staged {
            let buf = alloc::sync::Arc::new(block.data.clone());
            publish_metadata(&mut s, block.target_lba, buf);
        }
    }

    /// A direct data write has replaced these on-disk bytes without going
    /// through `metadata_write`; discard any clean buffer that aliases them.
    /// The next metadata reader must observe the write, not a stale cache line.
    /// # C: O(N affected fs blocks)
    pub(crate) fn invalidate_metadata_cache_range(&self, byte_off: u64, len: usize) {
        if len == 0 { return; }
        let bs = self.sb.block_size as u64;
        let first = byte_off / bs;
        let last = byte_off.saturating_add(len as u64).saturating_sub(1) / bs;
        let mut state = self.state.lock();
        state.metadata_epoch = state.metadata_epoch.wrapping_add(1);
        for lba in first..=last {
            if state.metadata_cache.remove(&lba).is_some() {
                state.metadata_order.retain(|held| *held != lba);
            }
        }
    }

    /// Read one fs-block from the transaction shadow, then the clean metadata
    /// buffer cache, then the underlying device.  This is the ext4 equivalent
    /// of Linux's buffer-cache lookup before `sb_bread` submits I/O.
    /// # C: O(log N) cache lookup or O(1) device I/O on a cold block
    #[inline(never)]
    pub(crate) fn read_metadata_block_shared(&self, lba: u64)
        -> Result<alloc::sync::Arc<Vec<u8>>, MountError>
    {
        // An invalidation can race the completion of the device read. Retry
        // from the top until one generation is observed consistently; this is
        // a state transition loop, not recursive re-entry that can grow the
        // call stack under sustained journal traffic.
        loop {
        let bs = self.sb.block_size as u64;
        let (cached, owner, created, epoch) = {
            let mut s = self.state.lock();
            if let Some(buf) = s.shadow.as_ref().and_then(|m| m.get(&lba).cloned()) {
                if buf.len() == bs as usize { return Ok(alloc::sync::Arc::new(buf)); }
                // A journal shadow is an in-flight full filesystem block. A
                // short value cannot be interpreted as metadata: Linux's
                // buffer-head/page-cache contract never publishes a partial
                // block as a readable buffer.
                return Err(MountError::Inode(crate::InodeError::BadLen));
            }
            let cached = match s.metadata_cache.get(&lba).cloned() {
                Some(buf) if buf.len() == bs as usize => Some(buf),
                Some(_) => {
                    // Clean cache entries are replaceable. Drop a malformed
                    // entry and perform the authoritative device read below;
                    // retaining it would turn one bad cache publication into
                    // a repeatable SIGBUS on every file fault for this block.
                    s.metadata_cache.remove(&lba);
                    None
                }
                None => None,
            };
            if cached.is_some() { (cached, None, false, s.metadata_epoch) }
            else if let Some(read) = s.metadata_reads.get(&lba).cloned() { (None, Some(read), false, s.metadata_epoch) }
            else {
                let read = Arc::new(MetadataRead::new());
                s.metadata_reads.insert(lba, Arc::clone(&read));
                (None, Some(read), true, s.metadata_epoch)
            }
        };
        if let Some(buf) = cached { return Ok(buf); }

        // If another reader owns this LBA, wait for its single completion.
        // Only the creator recorded by `created` performs the device read.
        if !created {
            let (read_epoch, result) = wait_metadata_read(owner.unwrap());
            if read_epoch == epoch { return result; }
            continue;
        }
        let result = match read_byte_range(&*self.dev, lba * bs, self.sb.block_size as usize) {
            Err(error) => Err(error),
            Ok(buf) if buf.len() != bs as usize =>
                Err(MountError::Inode(crate::InodeError::BadLen)),
            Ok(buf) => {
                let buf = Arc::new(buf);
                let mut s = self.state.lock();
                if s.metadata_epoch == epoch { publish_metadata(&mut s, lba, Arc::clone(&buf)); }
                Ok(buf)
            }
        };
        let read = owner.unwrap();
        let returned = result.clone();
        let mut s = self.state.lock();
        s.metadata_reads.remove(&lba);
        drop(s);
        read.complete(epoch, result);
        if self.state.lock().metadata_epoch != epoch { continue; }
        break returned;
        }
    }

    /// Owned copy of one metadata block, for the callers that edit the bytes
    /// before writing them back. A reader that only inspects the block should
    /// take [`Mount::read_metadata_block_shared`] instead: this copies the
    /// whole filesystem block.
    /// # C: O(block size) on top of the shared read
    #[inline]
    pub(crate) fn read_metadata_block(&self, lba: u64) -> Result<Vec<u8>, MountError> {
        self.read_metadata_block_shared(lba).map(|buf| (*buf).clone())
    }



}

fn wait_metadata_read(read: Arc<MetadataRead>) -> (u64, Result<Arc<Vec<u8>>, MountError>) {
    #[cfg(target_os = "oxide-kernel")]
    if sched::current().is_some() && !sched::preempt::in_atomic() {
        let _ = unsafe { sched::live::wait_event_uninterruptible(&read.wait, || {
            read.done.load(Ordering::Acquire)
        }) };
    } else {
        while !read.done.load(Ordering::Acquire) { core::hint::spin_loop(); }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    while !read.done.load(Ordering::Acquire) { core::hint::spin_loop(); }
    read.result.lock().as_ref().cloned().expect("metadata read completion publishes a result")
}

/// Cap on clean metadata buffers held at once. Bounded so a streaming
/// metadata workload cannot pin unlimited memory.
const META_CACHE_MAX_BLOCKS: usize = 8192;

/// Publish one clean metadata buffer, retiring the oldest when the cache is
/// full. A full cache used to be emptied outright, which discarded the inode
/// table and extent blocks the running workload was reading and sent every
/// subsequent reader back to the device.
/// # C: O(log N) amortised
fn publish_metadata(state: &mut crate::MountState, lba: u64, buf: alloc::sync::Arc<Vec<u8>>) {
    if state.metadata_cache.insert(lba, buf).is_none() {
        state.metadata_order.push_back(lba);
    }
    while state.metadata_cache.len() > META_CACHE_MAX_BLOCKS {
        match state.metadata_order.pop_front() {
            Some(oldest) => { state.metadata_cache.remove(&oldest); }
            None => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
    use core::sync::atomic::{AtomicU64, AtomicU32};
    use std::sync::Mutex;
    use std::thread;

    struct DelayedDisk {
        inner: Arc<MemDisk<sync::TaskList>>,
        target: AtomicU64,
        reads: AtomicU32,
        delay_lock: Mutex<()>,
    }

    impl BlockDevice for DelayedDisk {
        fn block_size(&self) -> u32 { self.inner.block_size() }
        fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }
        fn submit(&self, request: BlockRequest, completion: block::BlockCompletion) {
            if request.op == BlockOp::Read && request.start_block == self.target.load(Ordering::Acquire) {
                self.reads.fetch_add(1, Ordering::AcqRel);
                let _guard = self.delay_lock.lock().unwrap();
                thread::sleep(std::time::Duration::from_millis(40));
            }
            self.inner.submit(request, completion);
        }
        fn submit_sync(&self, request: &mut BlockRequest) -> block::KResult<()> {
            self.inner.submit_sync(request)
        }
        fn flush(&self) -> block::KResult<()> { self.inner.flush() }
    }

    #[test]
    fn metadata_read_publishes_error_after_done() {
        let read = Arc::new(MetadataRead::new());
        read.complete(7, Err(MountError::BlockIo));
        assert!(read.done.load(Ordering::Acquire));
        assert_eq!(read.result.lock().as_ref().cloned(), Some((7, Err(MountError::BlockIo))));
    }

    #[test]
    fn metadata_read_publishes_owned_buffer_after_done() {
        let read = Arc::new(MetadataRead::new());
        let bytes = Arc::new(vec![0x5a; 4096]);
        read.complete(9, Ok(Arc::clone(&bytes)));
        assert!(read.done.load(Ordering::Acquire));
        assert_eq!(read.result.lock().as_ref().unwrap().1.as_ref().unwrap().as_slice(), bytes.as_slice());
    }

    #[test]
    fn concurrent_cold_metadata_read_has_one_device_owner() {
        let image = include_bytes!("../../tests/mini-j.img");
        let sectors = image.len() as u64 / 512;
        let inner = MemDisk::<sync::TaskList>::new(512, sectors);
        let mut request = BlockRequest::new_write(0, sectors as u32, image.to_vec());
        inner.submit_sync(&mut request).unwrap();
        let disk = Arc::new(DelayedDisk {
            inner,
            target: AtomicU64::new(u64::MAX),
            reads: AtomicU32::new(0),
            delay_lock: Mutex::new(()),
        });
        let mount = Arc::new(Mount::open(Arc::clone(&disk) as Arc<dyn BlockDevice>).unwrap());
        let lba = mount.group_desc(0).unwrap().inode_table as u64;
        mount.state.lock().metadata_cache.clear();
        disk.target.store(lba * u64::from(mount.sb.block_size) / 512, Ordering::Release);
        let a = Arc::clone(&mount);
        let b = Arc::clone(&mount);
        let left = thread::spawn(move || a.read_metadata_block(lba).unwrap());
        thread::sleep(std::time::Duration::from_millis(5));
        let right = thread::spawn(move || b.read_metadata_block(lba).unwrap());
        assert_eq!(left.join().unwrap(), right.join().unwrap());
        assert_eq!(disk.reads.load(Ordering::Acquire), 1);
    }
}
