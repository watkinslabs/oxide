extern crate alloc;
use super::request::{alloc_request, blk_execute_rq, blk_mq_complete_request, blk_mq_end_request, blk_mq_end_request_batch, blk_mq_free_request};
use crate::linux_block::core;
use crate::linux_block::types::*;
use ::core::ptr::{null_mut, null};
use ::core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const TEST_GFP: u32 = 0;
const TEST_OPF: u32 = REQ_OP_READ;
const TEST_HCTX_IDX: u32 = 0;
const POISON_STATUS: u8 = BLK_STS_OK;

static COMPLETE_CALLS: AtomicUsize = AtomicUsize::new(0);
static EXIT_CALLS: AtomicUsize = AtomicUsize::new(0);
static END_IO_CALLS: AtomicUsize = AtomicUsize::new(0);
static BATCH_PTR: AtomicUsize = AtomicUsize::new(0);
static ASYNC_READY: AtomicBool = AtomicBool::new(false);
static ASYNC_DONE: AtomicBool = AtomicBool::new(false);
static ASYNC_RX: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>> = std::sync::Mutex::new(None);

fn reset_counters() {
    COMPLETE_CALLS.store(0, Ordering::SeqCst);
    EXIT_CALLS.store(0, Ordering::SeqCst);
    END_IO_CALLS.store(0, Ordering::SeqCst);
    BATCH_PTR.store(0, Ordering::SeqCst);
    ASYNC_READY.store(false, Ordering::SeqCst);
    ASYNC_DONE.store(false, Ordering::SeqCst);
}

unsafe extern "C" fn count_complete(_rq: *mut LinuxRequest) {
    COMPLETE_CALLS.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn count_exit(_set: *mut LinuxBlkMqTagSet, _rq: *mut LinuxRequest, _tag: u32) {
    EXIT_CALLS.fetch_add(1, Ordering::SeqCst);
}

// A driver whose completion handler hands the request back for the block layer to free.
unsafe extern "C" fn end_io_free(_rq: *mut LinuxRequest, _status: u8, _iob: *const LinuxIoCompBatch) -> i32 {
    END_IO_CALLS.fetch_add(1, Ordering::SeqCst);
    RQ_END_IO_FREE
}

// A driver whose completion handler keeps the request and releases it itself.
unsafe extern "C" fn end_io_takes_and_frees(rq: *mut LinuxRequest, _status: u8, _iob: *const LinuxIoCompBatch) -> i32 {
    END_IO_CALLS.fetch_add(1, Ordering::SeqCst);
    // SAFETY: rq is the live request blk_mq_end_request is completing; returning RQ_END_IO_NONE claims its
    // ownership, so freeing it here is exactly what that return value licenses.
    unsafe { blk_mq_free_request(rq); }
    RQ_END_IO_NONE
}

unsafe extern "C" fn end_io_batch_free(_rq: *mut LinuxRequest, status: u8, iob: *const LinuxIoCompBatch) -> i32 {
    assert_eq!(status, BLK_STS_OK);
    assert!(!iob.is_null());
    END_IO_CALLS.fetch_add(1, Ordering::SeqCst);
    BATCH_PTR.store(iob as usize, Ordering::SeqCst);
    RQ_END_IO_FREE
}

unsafe extern "C" fn end_io_batch_takes_and_frees(rq: *mut LinuxRequest, status: u8, iob: *const LinuxIoCompBatch) -> i32 {
    assert_eq!(status, BLK_STS_OK);
    assert!(!iob.is_null());
    END_IO_CALLS.fetch_add(1, Ordering::SeqCst);
    BATCH_PTR.store(iob as usize, Ordering::SeqCst);
    // SAFETY: this batch callback returns RQ_END_IO_NONE, so it owns and releases the live request here.
    unsafe { blk_mq_free_request(rq); }
    RQ_END_IO_NONE
}

// A driver that completes inline and then reuses the request's status field, as a recycled allocation
// would: the value blk_execute_rq reports must be the one the completion carried, not a later read.
unsafe extern "C" fn queue_rq_completes_then_poisons(_hctx: *mut LinuxBlkMqHwCtx, qd: *const LinuxBlkMqQueueData) -> u8 {
    if qd.is_null() { return BLK_STS_IOERR; }
    // SAFETY: qd points to the LinuxBlkMqQueueData stack struct blk_execute_rq_nowait borrowed to this call,
    // and its `rq` is the live request being submitted.
    let rq = unsafe { (*qd).rq };
    // SAFETY: rq is that live request; ending it runs blk_execute_rq's own completion, which records the
    // status out of band. The store afterwards then poisons the request's own status field.
    unsafe {
        blk_mq_end_request(rq, BLK_STS_IOERR);
        (*rq).status = POISON_STATUS;
    }
    BLK_STS_OK
}

unsafe extern "C" fn queue_rq_completes_from_worker(_hctx: *mut LinuxBlkMqHwCtx, qd: *const LinuxBlkMqQueueData) -> u8 {
    if qd.is_null() { return BLK_STS_IOERR; }
    // SAFETY: qd is the live queue-data borrow supplied by blk_execute_rq_nowait during this callback.
    let rq = unsafe { (*qd).rq } as usize;
    let rx = ASYNC_RX.lock().expect("async receiver lock").take().expect("async receiver installed");
    std::thread::spawn(move || {
        ASYNC_READY.store(true, Ordering::Release);
        rx.recv().expect("release asynchronous completion");
        // SAFETY: blk_execute_rq keeps the request and its completion record live until this completion runs.
        unsafe { blk_mq_end_request(rq as *mut LinuxRequest, BLK_STS_AGAIN); }
        ASYNC_DONE.store(true, Ordering::Release);
    });
    BLK_STS_OK
}

fn ops(queue_rq: Option<QueueRqFn>, complete: Option<CompleteFn>, exit_request: Option<ExitRequestFn>) -> LinuxBlkMqOps {
    LinuxBlkMqOps {
        queue_rq,
        commit_rqs: None,
        queue_rqs: null_mut(),
        get_budget: None,
        put_budget: None,
        set_rq_budget_token: None,
        get_rq_budget_token: None,
        timeout: null_mut(),
        poll: null_mut(),
        complete,
        init_hctx: null_mut(),
        exit_hctx: null_mut(),
        init_request: None,
        exit_request,
        cleanup_rq: None,
        busy: None,
        map_queues: None,
        show_rq: null_mut(),
    }
}

// Build a queue carrying `o` as its registered blk_mq_ops. The caller owns both and must keep `o` alive
// for as long as the queue is used.
fn queue_with_ops(o: &LinuxBlkMqOps) -> *mut LinuxRequestQueue {
    let q = core::blk_alloc_queue(TEST_GFP);
    assert!(!q.is_null());
    // SAFETY: q is the fresh unpublished blk_alloc_queue Box; mq_ops/tag_set are plain fields of it, and
    // `o` outlives the queue by the caller contract stated above.
    unsafe {
        (*q).mq_ops = o as *const LinuxBlkMqOps;
        (*q).tag_set = null_mut();
    }
    q
}

// Linux frees a request whose completion had no end_io callback at all.
#[test]
fn ending_a_request_with_no_end_io_frees_it_here() {
    let _modules = crate::test_serial::claim();
    reset_counters();
    let o = ops(None, Some(count_complete), Some(count_exit));
    let q = queue_with_ops(&o);
    // SAFETY: q is the live queue built above, which is alloc_request's precondition.
    let rq = unsafe { alloc_request(q, TEST_OPF, TEST_HCTX_IDX) };
    assert!(!rq.is_null());
    // SAFETY: rq is that live request and has no end_io installed, so blk_mq_end_request owns its release.
    unsafe { blk_mq_end_request(rq, BLK_STS_OK); }
    assert_eq!(EXIT_CALLS.load(Ordering::SeqCst), 1, "the request is freed exactly once");
    assert_eq!(COMPLETE_CALLS.load(Ordering::SeqCst), 0, "ending a request does not dispatch complete");
    // SAFETY: q is the test's own queue allocation; the request above is already released.
    unsafe { core::blk_cleanup_queue(q); }
}

// RQ_END_IO_FREE hands the request back for the completion path to free — and nothing may touch it after.
#[test]
fn end_io_free_frees_the_request_and_dispatches_no_complete() {
    let _modules = crate::test_serial::claim();
    reset_counters();
    let o = ops(None, Some(count_complete), Some(count_exit));
    let q = queue_with_ops(&o);
    // SAFETY: q is the live queue built above.
    let rq = unsafe { alloc_request(q, TEST_OPF, TEST_HCTX_IDX) };
    // SAFETY: rq is the live request; end_io is its own Option<fn> field.
    unsafe { (*rq).end_io = Some(end_io_free); }
    // SAFETY: rq is still live and its callback returns RQ_END_IO_FREE, licensing the free that follows.
    unsafe { blk_mq_end_request(rq, BLK_STS_IOERR); }
    assert_eq!(END_IO_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(EXIT_CALLS.load(Ordering::SeqCst), 1, "freed exactly once");
    assert_eq!(COMPLETE_CALLS.load(Ordering::SeqCst), 0, "no use of the request after its callback");
    // SAFETY: q is the test's own queue allocation; the request above is already released.
    unsafe { core::blk_cleanup_queue(q); }
}

// RQ_END_IO_NONE means the callback kept the request — it may already have freed it, so the completion
// path must not read its queue back or hand it to the complete op.
#[test]
fn end_io_none_leaves_the_request_untouched_after_the_callback() {
    let _modules = crate::test_serial::claim();
    reset_counters();
    let o = ops(None, Some(count_complete), Some(count_exit));
    let q = queue_with_ops(&o);
    // SAFETY: q is the live queue built above.
    let rq = unsafe { alloc_request(q, TEST_OPF, TEST_HCTX_IDX) };
    // SAFETY: rq is the live request; end_io is its own Option<fn> field.
    unsafe { (*rq).end_io = Some(end_io_takes_and_frees); }
    // SAFETY: rq is live on entry; the callback takes its ownership and frees it, and nothing below reads it.
    unsafe { blk_mq_end_request(rq, BLK_STS_OK); }
    assert_eq!(END_IO_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(EXIT_CALLS.load(Ordering::SeqCst), 1, "the callback's free is the only free");
    assert_eq!(COMPLETE_CALLS.load(Ordering::SeqCst), 0, "no complete dispatch on a request we no longer own");
    // SAFETY: q is the test's own queue allocation; the request above is already released.
    unsafe { core::blk_cleanup_queue(q); }
}

// The complete op belongs to blk_mq_complete_request, which is the only entry point that dispatches it.
#[test]
fn complete_request_dispatches_the_complete_op() {
    let _modules = crate::test_serial::claim();
    reset_counters();
    let o = ops(None, Some(count_complete), Some(count_exit));
    let q = queue_with_ops(&o);
    // SAFETY: q is the live queue built above.
    let rq = unsafe { alloc_request(q, TEST_OPF, TEST_HCTX_IDX) };
    // SAFETY: rq is the live request and the queue carries a complete op, which takes ownership of it.
    unsafe { blk_mq_complete_request(rq); }
    assert_eq!(COMPLETE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(EXIT_CALLS.load(Ordering::SeqCst), 0, "complete owns the request; it is not freed here");
    // SAFETY: rq is still the live request — count_complete kept it — and q is the test's own queue.
    unsafe {
        blk_mq_free_request(rq);
        core::blk_cleanup_queue(q);
    }
}

// blk_execute_rq reports the status its completion carried. Re-reading the request afterwards is not
// sound (it may belong to someone else by then), and this pins that the answer does not come from there.
#[test]
fn execute_rq_reports_the_completion_status_not_a_later_read() {
    let _modules = crate::test_serial::claim();
    reset_counters();
    let o = ops(Some(queue_rq_completes_then_poisons), Some(count_complete), Some(count_exit));
    let q = queue_with_ops(&o);
    // SAFETY: q is the live queue built above.
    let rq = unsafe { alloc_request(q, TEST_OPF, TEST_HCTX_IDX) };
    assert!(!rq.is_null());
    // SAFETY: rq is that live request; blk_execute_rq installs its own completion and the driver's
    // queue_rq keeps the request alive (its completion returns RQ_END_IO_NONE), so it is still ours after.
    let st = unsafe { blk_execute_rq(rq, false) };
    assert_eq!(st, BLK_STS_IOERR, "the completion carried BLK_STS_IOERR");
    assert_eq!(EXIT_CALLS.load(Ordering::SeqCst), 0, "the caller still owns the request");
    // SAFETY: rq is the still-live request this test owns, and q is its queue; neither is read afterwards.
    unsafe {
        blk_mq_free_request(rq);
        core::blk_cleanup_queue(q);
    }
    assert_eq!(EXIT_CALLS.load(Ordering::SeqCst), 1);
}

#[test]
fn execute_rq_waits_for_an_asynchronous_driver_completion() {
    let _modules = crate::test_serial::claim();
    reset_counters();
    let (tx, rx) = std::sync::mpsc::channel();
    *ASYNC_RX.lock().expect("async receiver lock") = Some(rx);
    let o = ops(Some(queue_rq_completes_from_worker), None, Some(count_exit));
    let q = queue_with_ops(&o);
    // SAFETY: q is the live queue built above and remains live until the worker joins.
    let rq = unsafe { alloc_request(q, TEST_OPF, TEST_HCTX_IDX) };
    assert!(!rq.is_null());
    let rq_addr = rq as usize;
    let worker = std::thread::spawn(move || {
        // SAFETY: rq_addr names the live request retained by the test until this worker returns.
        unsafe { blk_execute_rq(rq_addr as *mut LinuxRequest, false) }
    });
    while !ASYNC_READY.load(Ordering::Acquire) { std::thread::yield_now(); }
    tx.send(()).expect("release asynchronous completion");
    assert_eq!(worker.join().expect("execute worker"), BLK_STS_AGAIN);
    while !ASYNC_DONE.load(Ordering::Acquire) { std::thread::yield_now(); }
    assert_eq!(EXIT_CALLS.load(Ordering::SeqCst), 0, "the execute caller still owns the request");
    // SAFETY: the asynchronous callback finished and returned ownership to this test; q remains live.
    unsafe {
        blk_mq_free_request(rq);
        core::blk_cleanup_queue(q);
    }
    assert_eq!(EXIT_CALLS.load(Ordering::SeqCst), 1);
}

#[test]
fn end_request_batch_drains_every_request_and_preserves_callback_ownership() {
    let _modules = crate::test_serial::claim();
    reset_counters();
    let o = ops(None, None, Some(count_exit));
    let q = queue_with_ops(&o);
    // SAFETY: q is the live queue built above and alloc_request's required owner.
    let first = unsafe { alloc_request(q, TEST_OPF, TEST_HCTX_IDX) };
    // SAFETY: same live queue; this produces a distinct request allocation.
    let second = unsafe { alloc_request(q, TEST_OPF, TEST_HCTX_IDX) };
    assert!(!first.is_null() && !second.is_null());
    // SAFETY: both requests are live and uniquely owned by this test before the batch consumes them.
    unsafe {
        (*first).end_io = Some(end_io_batch_free);
        (*first).rq_next = second;
        (*second).end_io = Some(end_io_batch_takes_and_frees);
        (*second).rq_next = null_mut();
    }
    let mut batch = LinuxIoCompBatch {
        req_list: LinuxRqList { head: first, tail: second },
        need_ts: false,
        complete: None,
        poll_ctx: null_mut(),
    };
    let batch_addr = &batch as *const LinuxIoCompBatch as usize;
    // SAFETY: batch owns the two-request intrusive list above and each callback has a valid ownership answer.
    unsafe { blk_mq_end_request_batch(&mut batch); }
    assert!(batch.req_list.head.is_null() && batch.req_list.tail.is_null());
    assert_eq!(END_IO_CALLS.load(Ordering::SeqCst), 2);
    assert_eq!(BATCH_PTR.load(Ordering::SeqCst), batch_addr);
    assert_eq!(EXIT_CALLS.load(Ordering::SeqCst), 2, "each request was released exactly once");
    // SAFETY: the batch released both requests; q is the remaining test-owned queue allocation.
    unsafe { core::blk_cleanup_queue(q); }
}

// A queue with no registered ops at all must still complete and release its requests.
#[test]
fn ending_a_request_on_an_opless_queue_frees_it() {
    let _modules = crate::test_serial::claim();
    reset_counters();
    let q = core::blk_alloc_queue(TEST_GFP);
    // SAFETY: q is the fresh blk_alloc_queue Box; mq_ops is a plain field of it.
    unsafe { (*q).mq_ops = null(); }
    // SAFETY: q is that live queue, which is alloc_request's precondition.
    let rq = unsafe { alloc_request(q, TEST_OPF, TEST_HCTX_IDX) };
    // SAFETY: rq is the live request; with no end_io the completion path owes its release.
    unsafe { blk_mq_end_request(rq, BLK_STS_OK); }
    assert_eq!(EXIT_CALLS.load(Ordering::SeqCst), 0, "an opless queue has no exit_request to call");
    // SAFETY: q is the test's own queue allocation; the request above is already released.
    unsafe { core::blk_cleanup_queue(q); }
}
