//! Owned NVMe request posting, CQE retirement, and synchronous adaptation.

use super::*;
use sched::live::wait_list::WaitList;

pub(super) struct Requests {
    pending: Vec<PendingRequest>,
    deferred: Vec<DeferredRequest>,
    dispatching: bool,
}

impl Requests {
    pub(super) const fn new() -> Self { Self { pending: Vec::new(), deferred: Vec::new(), dispatching: false } }
}

struct PendingRequest {
    cid: u16,
    dma: Option<crate::queue::IoDma>,
    request: BlockRequest,
    completion: BlockCompletion,
    write: bool,
    len: usize,
}

struct DeferredRequest {
    request: BlockRequest,
    completion: BlockCompletion,
    write: bool,
    lba: u64,
    count: u16,
    len: usize,
    queued_ns: u64,
}

struct Plan {
    write: bool,
    lba: u64,
    count: u16,
    len: usize,
}

struct Aggregate {
    state: Spinlock<AggregateState, DriverLockClass>,
}

struct AggregateState {
    request: BlockRequest,
    completion: Option<BlockCompletion>,
    remaining: usize,
    error: Option<BlockError>,
}

struct SyncResult {
    done: AtomicBool,
    result: Spinlock<Option<(BlockRequest, KResult<()>)>, DriverLockClass>,
    waiters: WaitList,
}

impl SyncResult {
    fn new() -> Self {
        Self { done: AtomicBool::new(false), result: Spinlock::new(None), waiters: WaitList::new() }
    }
}

impl Aggregate {
    fn new(request: BlockRequest, completion: BlockCompletion, remaining: usize) -> Self {
        Self { state: Spinlock::new(AggregateState { request, completion: Some(completion), remaining, error: None }) }
    }

    fn finish_child(&self, child: BlockRequest, result: KResult<()>, offset: usize) {
        let completion = {
            let mut state = self.state.lock();
            if let Err(error) = result {
                if state.error.is_none() { state.error = Some(error); }
            } else if state.request.op == BlockOp::Read {
                let end = offset.saturating_add(child.buffer.len());
                if end > state.request.buffer.len() {
                    state.error = Some(BlockError::Eio);
                } else {
                    state.request.buffer[offset..end].copy_from_slice(&child.buffer);
                }
            }
            state.remaining = state.remaining.saturating_sub(1);
            if state.remaining != 0 { None } else {
                let request = core::mem::take(&mut state.request);
                let completion = state.completion.take();
                Some((request, completion, state.error))
            }
        };
        if let Some((request, Some(completion), error)) = completion {
            completion(request, error.map_or(Ok(()), Err));
        }
    }
}

impl NvmeBlk {
    fn enqueue_or_post(
        &self, request: BlockRequest, completion: BlockCompletion, plan: Plan, deferred_head: bool,
    ) -> Result<(), (BlockRequest, BlockCompletion, BlockError)> {
        if self.unavailable() { return Err((request, completion, BlockError::Eio)); }
        let bdf = self.ctrl.lock().bdf();
        let mut dma = if plan.count == 0 { None } else {
            match crate::queue::IoDma::allocate(bdf) {
                Some(dma) => Some(dma),
                None => return Err((request, completion, BlockError::Enomem)),
            }
        };
        if plan.write {
            let bounce = dma.as_ref().map(|dma| dma.data_va() as *mut u8).unwrap_or(core::ptr::null_mut());
            if bounce.is_null() { return Err((request, completion, BlockError::Eio)); }
            // SAFETY: this command-private data run is not in an SQ entry yet; plan bounded len to its allocation.
            unsafe { for (offset, byte) in request.buffer[..plan.len].iter().enumerate() { core::ptr::write_volatile(bounce.add(offset), *byte); } }
            pmm::dma::clean_to_device(bounce as u64, plan.len);
        }
        let mut ctrl = self.ctrl.lock();
        let mut requests = self.requests.lock();
        if self.unavailable() { return Err((request, completion, BlockError::Eio)); }
        if deferred_head { requests.dispatching = false; }
        if requests.pending.len() >= ctrl.io_capacity() || (!deferred_head && (!requests.deferred.is_empty() || requests.dispatching)) {
            requests.deferred.push(DeferredRequest {
                request, completion, write: plan.write, lba: plan.lba, count: plan.count, len: plan.len,
                queued_ns: wait::now_ns(),
            });
            return Ok(());
        }
        let Some(cid) = (0..ctrl.io_capacity() as u16)
            .find(|cid| !requests.pending.iter().any(|request| request.cid == *cid)) else {
            return Err((request, completion, BlockError::Eio));
        };
        let posted = if let Some(dma) = dma.as_ref() {
            ctrl.rw_submit(cid, dma, plan.write, plan.lba, plan.count - 1)
        } else {
            ctrl.flush_submit(cid)
        };
        if !posted { return Err((request, completion, BlockError::Eio)); }
        // The controller lock stays held from doorbell publication through this
        // insertion. CQ draining takes this same lock first, so a fast CQE can
        // never be retired before its CID owns this canonical record.
        requests.pending.push(PendingRequest { cid, dma: dma.take(), request, completion, write: plan.write, len: plan.len });
        Ok(())
    }

    fn submit_rw(&self, mut request: BlockRequest, completion: BlockCompletion) {
        let len = match (request.len_blocks as usize).checked_mul(self.blk_size as usize) {
            Some(len) if request.len_blocks != 0 => len,
            _ => { completion(request, Err(BlockError::Einval)); return; }
        };
        if request.op == BlockOp::Read {
            if request.buffer.len() < len { request.buffer.resize(len, 0); }
        } else if request.buffer.len() < len {
            completion(request, Err(BlockError::Einval));
            return;
        }
        let per_command = self.chunk_bytes() / self.blk_size as usize;
        if per_command == 0 { completion(request, Err(BlockError::Eio)); return; }
        let total = request.len_blocks as usize;
        let chunks = total.div_ceil(per_command);
        let aggregate = Arc::new(Aggregate::new(request, completion, chunks));
        let (write, base, ioprio, polled) = {
            let state = aggregate.state.lock();
            (state.request.op == BlockOp::Write, state.request.start_block, state.request.ioprio, state.request.polled)
        };
        for index in 0..chunks {
            let block_offset = index * per_command;
            let count = core::cmp::min(per_command, total - block_offset);
            let byte_offset = block_offset * self.blk_size as usize;
            let bytes = count * self.blk_size as usize;
            let mut child = if write {
                let data = aggregate.state.lock().request.buffer[byte_offset..byte_offset + bytes].to_vec();
                BlockRequest::new_write(base + block_offset as u64, count as u32, data)
            } else {
                BlockRequest::new_read(base + block_offset as u64, count as u32, self.blk_size)
            };
            child.ioprio = ioprio;
            child.polled = polled;
            let plan = Plan { write, lba: child.start_block, count: count as u16, len: bytes };
            let owner = aggregate.clone();
            let child_completion: BlockCompletion = alloc::boxed::Box::new(move |child, result| owner.finish_child(child, result, byte_offset));
            if let Err((child, child_completion, error)) = self.enqueue_or_post(child, child_completion, plan, false) {
                child_completion(child, Err(error));
            }
        }
    }

    fn start_deferred_requests(&self) {
        loop {
            let deferred = {
                let ctrl = self.ctrl.lock();
                let mut requests = self.requests.lock();
                if requests.deferred.is_empty() { return; }
                if requests.pending.len() >= ctrl.io_capacity() { return; }
                let now = wait::now_ns();
                let waiting: Vec<block::elevator::Waiting> = requests.deferred.iter()
                    .map(|request| block::elevator::Waiting { ioprio: request.request.ioprio, queued_ns: request.queued_ns })
                    .collect();
                let Some(index) = block::elevator::select(&waiting, now, block::elevator::PRIO_AGING_EXPIRE_NS) else { return; };
                requests.dispatching = true;
                requests.deferred.remove(index)
            };
            let plan = Plan { write: deferred.write, lba: deferred.lba, count: deferred.count, len: deferred.len };
            if let Err((request, completion, error)) = self.enqueue_or_post(deferred.request, deferred.completion, plan, true) {
                self.requests.lock().dispatching = false;
                completion(request, Err(error));
            }
        }
    }

    fn take_completed(&self) -> Result<Option<(PendingRequest, u16)>, ()> {
        let mut ctrl = self.ctrl.lock();
        let Some(cqe) = ctrl.reap_io() else { return Ok(None); };
        let (cq_pa, cq_head, cq_phase) = ctrl.io_cq_cursor();
        self.irq.configure_cq(cq_pa, cq_head, cq_phase);
        let mut requests = self.requests.lock();
        let Some(index) = requests.pending.iter().position(|request| request.cid == cqe.cid) else { return Err(()); };
        Ok(Some((requests.pending.remove(index), cqe.status)))
    }

    fn deliver_completed(&self, mut pending: PendingRequest, status: u16) {
        let result = if status != 0 || self.unavailable() {
            Err(BlockError::Eio)
        } else if !pending.write && pending.len != 0 {
            let Some(dma) = pending.dma.as_ref() else { return (pending.completion)(pending.request, Err(BlockError::Eio)); };
            if pending.request.buffer.len() < pending.len { Err(BlockError::Eio) } else {
                let bounce = dma.data_va() as *const u8;
                pmm::dma::invalidate_from_device(bounce as u64, pending.len);
                // SAFETY: the CID-matched CQE retired this command; request buffer and private run are length-checked.
                unsafe { for (offset, byte) in pending.request.buffer[..pending.len].iter_mut().enumerate() { *byte = core::ptr::read_volatile(bounce.add(offset)); } }
                Ok(())
            }
        } else {
            Ok(())
        };
        drop(pending.dma.take());
        (pending.completion)(pending.request, result);
    }

    pub(super) fn fail_owned_requests(&self) {
        let (pending, deferred) = {
            let mut requests = self.requests.lock();
            (core::mem::take(&mut requests.pending), core::mem::take(&mut requests.deferred))
        };
        for pending in pending { (pending.completion)(pending.request, Err(BlockError::Eio)); }
        for deferred in deferred { (deferred.completion)(deferred.request, Err(BlockError::Eio)); }
    }

    /// Drain every CQE that the hard IRQ made visible. # C: O(completions)
    pub(crate) fn completion_bottom_half(&self) {
        if !self.irq.take_wake() { return; }
        loop {
            match self.take_completed() {
                Ok(Some((pending, status))) => {
                    self.deliver_completed(pending, status);
                    self.start_deferred_requests();
                }
                Ok(None) => return,
                Err(()) => {
                    self.poisoned.store(true, Ordering::Release);
                    self.quiesce_and_free();
                    return;
                }
            }
        }
    }

    fn submit_one_sync(&self, request: BlockRequest) -> KResult<BlockRequest> {
        let state = Arc::new(SyncResult::new());
        let completion_state = state.clone();
        self.submit(request, alloc::boxed::Box::new(move |request, result| {
            *completion_state.result.lock() = Some((request, result));
            completion_state.done.store(true, Ordering::Release);
            completion_state.waiters.wake_all();
        }));
        let deadline = wait::now_ns().saturating_add(wait::IO_TIMEOUT_NS);
        while !state.done.load(Ordering::Acquire) {
            if self.unavailable() || wait::now_ns() >= deadline {
                self.poisoned.store(true, Ordering::Release);
                return Err(BlockError::Eio);
            }
            if !wait::poll_enabled(|| state.done.load(Ordering::Acquire), deadline) {
                wait::park_checked(&state.waiters, deadline, || state.done.load(Ordering::Acquire));
            }
        }
        let Some((request, result)) = state.result.lock().take() else { return Err(BlockError::Eio); };
        result.map(|()| request)
    }
}

impl BlockDevice for NvmeBlk {
    fn block_size(&self) -> u32 { self.blk_size }
    fn capacity_blocks(&self) -> u64 { self.capacity }

    fn submit(&self, request: BlockRequest, completion: BlockCompletion) {
        match request.op {
            BlockOp::Read | BlockOp::Write => self.submit_rw(request, completion),
            BlockOp::Flush => {
                let plan = Plan { write: false, lba: 0, count: 0, len: 0 };
                if let Err((request, completion, error)) = self.enqueue_or_post(request, completion, plan, false) {
                    completion(request, Err(error));
                }
            }
            BlockOp::Discard | BlockOp::WriteZeroes { .. } => completion(request, Err(BlockError::Eopnotsupp)),
        }
    }

    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        let request = core::mem::take(req);
        let request = self.submit_one_sync(request)?;
        *req = request;
        Ok(())
    }

    fn flush(&self) -> KResult<()> {
        let mut request = BlockRequest::new_flush();
        self.submit_sync(&mut request)
    }
}
