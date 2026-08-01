extern crate alloc;
use super::request::{alloc_request, blk_execute_rq, blk_mq_complete_request, blk_mq_end_request, blk_mq_free_request};
use crate::linux_block::core;
use crate::linux_block::types::*;
use ::core::ffi::c_void;
use ::core::ptr::{null_mut, null};
use ::core::sync::atomic::{AtomicUsize, Ordering};

const TEST_GFP: u32 = 0;
const TEST_OPF: u32 = REQ_OP_READ;
const TEST_HCTX_IDX: u32 = 0;
const POISON_STATUS: u8 = BLK_STS_OK;

static COMPLETE_CALLS: AtomicUsize = AtomicUsize::new(0);
static EXIT_CALLS: AtomicUsize = AtomicUsize::new(0);
static END_IO_CALLS: AtomicUsize = AtomicUsize::new(0);

fn reset_counters() {
    COMPLETE_CALLS.store(0, Ordering::SeqCst);
    EXIT_CALLS.store(0, Ordering::SeqCst);
    END_IO_CALLS.store(0, Ordering::SeqCst);
}

unsafe extern "C" fn count_complete(_rq: *mut LinuxRequest) {
    COMPLETE_CALLS.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn count_exit(_set: *mut LinuxBlkMqTagSet, _rq: *mut LinuxRequest, _tag: u32) {
    EXIT_CALLS.fetch_add(1, Ordering::SeqCst);
}

// A driver whose completion handler hands the request back for the block layer to free.
unsafe extern "C" fn end_io_free(_rq: *mut LinuxRequest, _status: u8, _iob: *const c_void) -> i32 {
    END_IO_CALLS.fetch_add(1, Ordering::SeqCst);
    RQ_END_IO_FREE
}

// A driver whose completion handler keeps the request and releases it itself.
unsafe extern "C" fn end_io_takes_and_frees(rq: *mut LinuxRequest, _status: u8, _iob: *const c_void) -> i32 {
    END_IO_CALLS.fetch_add(1, Ordering::SeqCst);
    // SAFETY: rq is the live request blk_mq_end_request is completing; returning RQ_END_IO_NONE claims its
    // ownership, so freeing it here is exactly what that return value licenses.
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
