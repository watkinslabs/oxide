//! Extent-mapped direct-I/O submission for regular ext4 files.
//!
//! The block device owns each submitted request. This module owns only the
//! filesystem transfer: its extent snapshot, aggregate buffer, first error,
//! completion count, and inode-DIO lifetime token. There is no page-cache
//! transfer hidden behind the polled interface.

use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use block::{BlockOp, BlockRequest};
use sync::{Spinlock, Inode as InodeLockClass};
use vfs::file_ops::{DirectIo, DirectSubmit};
use vfs::{File, VfsError};

use super::data::{DioToken, Ext4FileData};
use crate::extent_rw::PhysRun;

/// One extent-backed request aggregate. The block layer invokes the request
/// callbacks; the io_uring completion is invoked only after every request has
/// returned, exactly once. # C: O(1) state plus submitted blocks
pub(crate) struct DioState {
    data: Arc<Ext4FileData>,
    buf: Spinlock<Vec<u8>, InodeLockClass>,
    error: Spinlock<Option<VfsError>, InodeLockClass>,
    done: Spinlock<Option<vfs::file_ops::DirectDone>, InodeLockClass>,
    token: Spinlock<Option<DioToken>, InodeLockClass>,
    remaining: AtomicU32,
    result_len: usize,
    write: bool,
    invalidate_start: u64,
    invalidate_end: u64,
}

/// Plan only the DIO write shape that can complete without allocation or
/// unwritten-extent conversion. This is deliberately ungated so the Linux
/// admission boundary is tested without a device or a boot. # C: O(extents)
fn in_place_write_plan(extents: &[PhysRun], off: u64, end: u64, bs: u64)
    -> Option<Vec<(usize, u64, usize)>>
{
    let mut covered = off;
    let mut plans = Vec::new();
    for run in extents {
        let run_start = u64::from(run.logical) * bs;
        let run_end = run_start.saturating_add(u64::from(run.len) * bs);
        let start = core::cmp::max(off, run_start);
        let finish = core::cmp::min(end, run_end);
        if start >= finish { continue; }
        if run.unwritten || start != covered { return None; }
        covered = finish;
        let logical_blocks = (start - run_start) / bs;
        plans.push(((start - off) as usize,
                    run.phys.saturating_add(logical_blocks),
                    (finish - start) as usize));
    }
    (covered == end).then_some(plans)
}

impl DioState {
    /// # C: O(1)
    fn new(data: Arc<Ext4FileData>, io: DirectIo, token: DioToken, requests: u32,
           result_len: usize, write: bool, invalidate_start: u64,
           invalidate_end: u64) -> Arc<Self>
    {
        Arc::new(Self {
            data,
            buf: Spinlock::new(io.buf),
            error: Spinlock::new(None),
            done: Spinlock::new(Some(io.done)),
            token: Spinlock::new(Some(token)),
            remaining: AtomicU32::new(requests),
            result_len,
            write,
            invalidate_start,
            invalidate_end,
        })
    }

    /// Store one block request's result, then retire the aggregate on the last
    /// completion. The first device error is the transfer's error. # C: O(1)
    fn complete(self: &Arc<Self>, at: usize, req: BlockRequest, result: block::KResult<()>) {
        if result.is_ok() {
            let mut buf = self.buf.lock();
            let end = at.saturating_add(req.buffer.len()).min(buf.len());
            let n = end.saturating_sub(at);
            buf[at..end].copy_from_slice(&req.buffer[..n]);
        } else {
            let mut error = self.error.lock();
            if error.is_none() { *error = Some(VfsError::Eio); }
        }
        if self.remaining.fetch_sub(1, Ordering::AcqRel) == 1 { self.finish(); }
    }

    /// Finish filesystem work in process context, after the device has
    /// completed. Linux's iomap DIO completion cannot invalidate mapped cache
    /// pages or do other sleepable work from a block completion callback.
    /// # C: O(pages in range) plus the completion callback
    fn finish_process(&self) {
        if self.write {
            let _invalidate = unsafe { self.data.invalidate_lock.write() };
            let first = self.invalidate_start / hal::PAGE_SIZE_BYTES;
            let last = self.invalidate_end.saturating_add(hal::PAGE_SIZE_BYTES - 1)
                / hal::PAGE_SIZE_BYTES;
            if first < last { self.data.frames.try_invalidate_pages(first, last - 1); }
        }
        self.data.dio_queue.lock().retain(|q| !core::ptr::eq(&**q, self));
        self.token.lock().take();
        let result = self.error.lock().take()
            .map_or(Ok(self.result_len), Err);
        let buf = core::mem::take(&mut *self.buf.lock());
        if let Some(done) = self.done.lock().take() { done(buf, result); }
    }

    /// Device callbacks may run in interrupt/softirq context. Defer the
    /// filesystem completion half to the kernel workqueue; hosted tests run it
    /// inline because they have no worker. # C: O(1)
    fn finish(self: &Arc<Self>) {
        if !self.write { self.finish_process(); return; }
        let raw = Box::into_raw(Box::new(FinishJob { state: self.clone() })) as usize;
        #[cfg(target_os = "oxide-kernel")]
        if sched::live::workqueue::queue_work(run_finish, raw) { return; }
        // SAFETY: queue_work returned false, so ownership remains here.
        let job = unsafe { Box::from_raw(raw as *mut FinishJob) };
        job.state.finish_process();
    }
}

struct FinishJob { state: Arc<DioState> }

#[cfg(target_os = "oxide-kernel")]
fn run_finish(raw: usize) {
    // SAFETY: raw is owned by this one queued work item.
    let job = unsafe { Box::from_raw(raw as *mut FinishJob) };
    job.state.finish_process();
}

/// Poll the filesystem's underlying block completion queue. The aggregate
/// itself is reaped by io_uring after this call, so this method only drives the
/// device owner. # C: O(completions)
pub(crate) fn poll(file: &File) -> Option<usize> {
    let d = file.inode().private::<Ext4FileData>()?;
    if !d.st.mount.dev.can_poll() { return None; }
    Some(d.st.mount.dev.poll_completions())
}

/// The ext4 description has a poll owner only when the mounted device does.
/// # C: O(1)
pub(crate) fn can_poll(file: &File) -> bool {
    file.inode().private::<Ext4FileData>()
        .is_some_and(|d| d.st.mount.dev.can_poll())
}

/// Submit one extent-mapped direct transfer as owned block requests. Writes
/// are admitted only for initialized, in-place extent overwrites: allocation,
/// unwritten conversion, inode extension, and journal-data ordering remain in
/// the synchronous Linux-shaped owner until they have a process-context
/// completion owner of their own.
/// # C: O(extents) planning plus O(requests) submission
pub(crate) fn submit(file: &File, io: DirectIo) -> DirectSubmit {
    let Some(data) = file.inode().private_arc::<Ext4FileData>() else {
        return DirectSubmit::Unsupported(io);
    };
    if !can_poll(file) {
        return DirectSubmit::Unsupported(io);
    }
    let bs = data.st.mount.sb.block_size as u64;
    let dev_bs = data.st.mount.dev.block_size() as u64;
    if bs == 0 || dev_bs == 0 || bs % dev_bs != 0
        || io.off % bs != 0 || (io.len() as u64) % bs != 0 {
        return DirectSubmit::Failed(VfsError::Einval);
    }
    let inode = match data.st.mount.read_inode(data.ino) {
        Ok(i) => i,
        Err(_) => return DirectSubmit::Failed(VfsError::Eio),
    };
    let end = match io.off.checked_add(io.len() as u64) {
        Some(v) => v,
        None => return DirectSubmit::Failed(VfsError::Einval),
    };
    // Extending and partial-tail writes need ext4 allocation/size publication
    // and therefore stay on the synchronous owner, just as Linux's iomap
    // write path does when it cannot finish metadata in the poll context.
    if io.write && end > inode.size { return DirectSubmit::Unsupported(io); }
    let result_len = if io.off >= inode.size {
        0
    } else {
        core::cmp::min(io.len() as u64, inode.size - io.off) as usize
    };
    let request_end = if result_len == 0 {
        io.off
    } else {
        core::cmp::min(end, io.off.saturating_add(
            ((result_len as u64 + bs - 1) / bs) * bs))
    };
    let token = data.begin_dio();
    // Linux drains dirty cache pages before handing an extent snapshot to the
    // device. The shared invalidate lock keeps truncate/remap from changing
    // that snapshot while it is assembled; `DioToken` carries the lifetime
    // after this short process-context preparation phase.
    let _invalidate = unsafe { data.invalidate_lock.read() };
    if data.frames.writeback_range(io.off, end).is_err() {
        return DirectSubmit::Failed(VfsError::Eio);
    }
    let _inode_lock = if io.write || data.st.mount.behaviour().dio_read_nolock_enabled() {
        None
    } else {
        Some(file.inode().inode_lock_shared())
    };
    let extents = match data.st.mount.collect_phys_extents(&inode.i_block) {
        Ok(v) => v,
        Err(_) => return DirectSubmit::Failed(VfsError::Eio),
    };
    let plans = if io.write {
        match in_place_write_plan(&extents, io.off, request_end, bs) {
            Some(plans) => plans,
            None => return DirectSubmit::Unsupported(io),
        }
    } else {
        let mut plans: Vec<(usize, u64, usize)> = Vec::new();
        for run in extents {
            let run_start = u64::from(run.logical) * bs;
            let run_end = run_start.saturating_add(u64::from(run.len) * bs);
            let start = core::cmp::max(io.off, run_start);
            let finish = core::cmp::min(request_end, run_end);
            if start >= finish { continue; }
            if run.unwritten { continue; }
            let logical_blocks = (start - run_start) / bs;
            let bytes = (finish - start) as usize;
            let phys = run.phys.saturating_add(logical_blocks);
            let at = (start - io.off) as usize;
            plans.push((at, phys, bytes));
        }
        plans
    };
    let write = io.write;
    let off = io.off;
    if write { file.file_update_time(); }
    let state = DioState::new(data.clone(), io, token, plans.len() as u32,
                              result_len, write, off, request_end);
    data.dio_queue.lock().push(state.clone());
    if plans.is_empty() {
        state.remaining.store(1, Ordering::Release);
        state.finish();
        return DirectSubmit::Queued;
    }
    state.remaining.store(plans.len() as u32, Ordering::Release);
    for (at, phys, bytes) in plans {
        let blocks = bytes as u64 / bs;
        let start = phys.saturating_mul(bs) / dev_bs;
        let n = blocks.saturating_mul(bs / dev_bs);
        if n > u32::MAX as u64 {
            state.complete(at, BlockRequest::default(), Err(block::BlockError::Einval));
            continue;
        }
        let write = state.write;
        let request = BlockRequest {
            op: if write { BlockOp::Write } else { BlockOp::Read },
            start_block: start,
            len_blocks: n as u32,
            buffer: if write {
                state.buf.lock()[at..at + bytes].to_vec()
            } else { alloc::vec![0u8; bytes] },
            polled: true,
            ..BlockRequest::default()
        };
        let q = state.clone();
        data.st.mount.dev.submit(request, alloc::boxed::Box::new(move |req, result| {
            q.complete(at, req, result);
        }));
    }
    DirectSubmit::Queued
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use super::*;

    fn run(logical: u32, phys: u64, len: u32, unwritten: bool) -> PhysRun {
        PhysRun { logical, phys, len, unwritten }
    }

    #[test]
    fn in_place_plan_covers_adjacent_initialized_runs() {
        let extents = [run(0, 100, 2, false), run(2, 900, 2, false)];
        assert_eq!(in_place_write_plan(&extents, 0, 4 * 4096, 4096),
            Some(vec![(0, 100, 2 * 4096), (2 * 4096, 900, 2 * 4096)]));
    }

    #[test]
    fn in_place_plan_refuses_a_logical_hole() {
        let extents = [run(0, 100, 1, false), run(2, 102, 1, false)];
        assert!(in_place_write_plan(&extents, 0, 3 * 4096, 4096).is_none());
    }

    #[test]
    fn in_place_plan_refuses_unwritten_storage() {
        let extents = [run(0, 100, 2, true)];
        assert!(in_place_write_plan(&extents, 0, 4096, 4096).is_none());
    }

    #[test]
    fn in_place_plan_accepts_an_empty_range_without_extents() {
        assert_eq!(in_place_write_plan(&[], 4096, 4096, 4096), Some(Vec::new()));
    }
}
