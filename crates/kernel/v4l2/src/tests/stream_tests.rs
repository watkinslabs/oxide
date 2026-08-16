//! Starting and stopping the stream, completion, dequeue and readiness.

use core::sync::atomic::Ordering;
use syscall::errno::Errno;

use super::harness::{FakeCtx, Rig};
use crate::uapi::ioctl::*;
use crate::uapi::layout as l;
use crate::uapi::flags;
use crate::usermem::{r32, r64, w32};
use crate::vb2::{poll, BufState};

#[test]
fn streamon_needs_buffers_and_streamon_twice_is_a_no_op() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    // Nothing allocated at all.
    assert_eq!(rig.streamon(&ctx), Err(Errno::Einval));
    rig.reqbufs(2, &ctx).expect("buffers allocate");
    // Allocated but none queued: the device would run dry immediately.
    assert_eq!(rig.streamon(&ctx), Err(Errno::Einval));
    rig.qbuf(0, &ctx).expect("buffer queues");
    rig.streamon(&ctx).expect("stream starts");
    assert_eq!(rig.ops.start_count.load(Ordering::Acquire), 1);
    // Starting again succeeds and does nothing, which is what makes an
    // application's start path idempotent.
    rig.streamon(&ctx).expect("a second start is not an error");
    assert_eq!(rig.ops.start_count.load(Ordering::Acquire), 1);
}

#[test]
fn a_refused_start_leaves_the_pool_reusable() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(3, &ctx).expect("buffers allocate");
    rig.qbuf(0, &ctx).expect("buffer queues");
    rig.qbuf(1, &ctx).expect("buffer queues");
    rig.ops.refuse_start.store(true, Ordering::Release);
    assert_eq!(rig.streamon(&ctx), Err(Errno::Eio));
    {
        let state = rig.device.state.lock();
        assert!(!state.queue.streaming);
        assert_eq!(state.queue.queued.len(), 2, "both buffers go back on the queue");
        assert_eq!(state.queue.buffer(0).unwrap().state, BufState::Queued);
        assert_eq!(state.queue.buffer(1).unwrap().state, BufState::Queued);
        // Order must survive, or the second attempt captures frames out of
        // sequence.
        assert_eq!(state.queue.queued.front().copied(), Some(0));
    }
    rig.ops.refuse_start.store(false, Ordering::Release);
    rig.streamon(&ctx).expect("a second attempt works on the same pool");
}

#[test]
fn streamoff_returns_every_buffer_whatever_it_was_doing() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(3, &ctx).expect("buffers allocate");
    for i in 0..3 { rig.qbuf(i, &ctx).expect("buffer queues"); }
    rig.streamon(&ctx).expect("stream starts");
    assert!(rig.complete(0, 1, 100));
    rig.streamoff(&ctx).expect("stream stops");
    let state = rig.device.state.lock();
    assert!(!state.queue.streaming);
    assert!(state.queue.done.is_empty());
    assert!(state.queue.queued.is_empty());
    for i in 0..3 {
        assert_eq!(state.queue.buffer(i).unwrap().state, BufState::Dequeued,
                   "buffer {i} is unrecoverable if it is left anywhere else");
    }
    assert_eq!(rig.ops.stop_count.load(Ordering::Acquire), 1);
}

#[test]
fn streamoff_on_a_stopped_queue_succeeds() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(1, &ctx).expect("buffers allocate");
    rig.streamoff(&ctx).expect("stopping a stopped queue is not an error");
    assert_eq!(rig.ops.stop_count.load(Ordering::Acquire), 0,
               "the transport is not touched when it was never started");
}

#[test]
fn a_completed_buffer_comes_back_with_its_payload_and_timestamp() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(2, &ctx).expect("buffers allocate");
    rig.qbuf(0, &ctx).expect("buffer queues");
    rig.qbuf(1, &ctx).expect("buffer queues");
    rig.streamon(&ctx).expect("stream starts");
    assert!(rig.complete(0, 7, 4321));
    let mut arg = alloc::vec![0u8; l::BUFFER_SIZE];
    w32(&mut arg, l::BUF_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    rig.call(VIDIOC_DQBUF, &mut arg, &ctx).expect("dequeue succeeds");
    assert_eq!(r32(&arg, l::BUF_INDEX), 0);
    assert_eq!(r32(&arg, l::BUF_BYTESUSED), 4321);
    assert_eq!(r32(&arg, l::BUF_SEQUENCE), 7);
    assert!(r32(&arg, l::BUF_FLAGS) & flags::BUF_FLAG_DONE != 0);
    assert_eq!(r32(&arg, l::BUF_FLAGS) & flags::BUF_FLAG_ERROR, 0);
    // The stamp is a `timeval`, so nanoseconds arrive split into whole
    // seconds and microseconds.
    assert_eq!(r64(&arg, l::BUF_TIMESTAMP_SEC), 5);
    assert_eq!(r64(&arg, l::BUF_TIMESTAMP_USEC), 0);
    assert_eq!(rig.device.state.lock().queue.buffer(0).unwrap().state, BufState::Dequeued);
}

#[test]
fn a_payload_larger_than_the_plane_is_clipped() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(1, &ctx).expect("buffers allocate");
    rig.qbuf(0, &ctx).expect("buffer queues");
    rig.streamon(&ctx).expect("stream starts");
    // A driver reporting more than it was given would have the caller read
    // past the mapping.
    assert!(rig.complete(0, 1, u32::MAX));
    let length = rig.device.state.lock().queue.buffer(0).unwrap().planes[0].length;
    assert_eq!(rig.device.state.lock().queue.buffer(0).unwrap().planes[0].bytesused, length);
}

#[test]
fn dqbuf_admission_follows_the_reference_order() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let mut arg = alloc::vec![0u8; l::BUFFER_SIZE];
    w32(&mut arg, l::BUF_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    // Not streaming outranks emptiness: a caller must learn the stream is off
    // rather than be told to try again.
    assert_eq!(rig.call(VIDIOC_DQBUF, &mut arg, &ctx), Err(Errno::Einval));
    rig.reqbufs(2, &ctx).expect("buffers allocate");
    rig.qbuf(0, &ctx).expect("buffer queues");
    rig.streamon(&ctx).expect("stream starts");
    // Streaming and empty, non-blocking.
    assert_eq!(rig.call(VIDIOC_DQBUF, &mut arg, &ctx), Err(Errno::Eagain));
    // A blocking caller waits instead.
    let blocking = FakeCtx::new(false);
    assert_eq!(rig.call(VIDIOC_DQBUF, &mut arg, &blocking), Err(Errno::Eintr));
    assert_eq!(blocking.waits.load(Ordering::Acquire), 1);
    // A failed queue outranks emptiness.
    rig.device.state.lock().queue.error = true;
    assert_eq!(rig.call(VIDIOC_DQBUF, &mut arg, &ctx), Err(Errno::Eio));
    rig.device.state.lock().queue.error = false;
    // The end-of-stream marker outranks both, and is not EAGAIN.
    rig.device.state.lock().queue.last_buffer_dequeued = true;
    assert_eq!(rig.call(VIDIOC_DQBUF, &mut arg, &ctx), Err(Errno::Epipe));
}

#[test]
fn the_last_buffer_marker_makes_the_next_dequeue_epipe() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(1, &ctx).expect("buffers allocate");
    rig.qbuf(0, &ctx).expect("buffer queues");
    rig.streamon(&ctx).expect("stream starts");
    {
        let mut state = rig.device.state.lock();
        let mut bytesused = [0u32; l::MAX_PLANES];
        bytesused[0] = 10;
        crate::vb2::stream::buffer_done(&mut state.queue, &crate::vb2::Completion {
            index: 0, state: BufState::Done, bytesused, timestamp_ns: 0,
            sequence: 0, field: flags::FIELD_NONE, last: true,
        });
    }
    let mut arg = alloc::vec![0u8; l::BUFFER_SIZE];
    w32(&mut arg, l::BUF_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    rig.call(VIDIOC_DQBUF, &mut arg, &ctx).expect("the last buffer is delivered");
    assert!(r32(&arg, l::BUF_FLAGS) & flags::BUF_FLAG_LAST != 0);
    assert_eq!(rig.call(VIDIOC_DQBUF, &mut arg, &ctx), Err(Errno::Epipe));
}

#[test]
fn buffers_are_delivered_in_completion_order() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(3, &ctx).expect("buffers allocate");
    for i in 0..3 { rig.qbuf(i, &ctx).expect("buffer queues"); }
    rig.streamon(&ctx).expect("stream starts");
    assert!(rig.complete(2, 1, 10));
    assert!(rig.complete(0, 2, 20));
    assert!(rig.complete(1, 3, 30));
    let mut seen = alloc::vec::Vec::new();
    for _ in 0..3 {
        let mut arg = alloc::vec![0u8; l::BUFFER_SIZE];
        w32(&mut arg, l::BUF_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
        rig.call(VIDIOC_DQBUF, &mut arg, &ctx).expect("dequeue succeeds");
        seen.push(r32(&arg, l::BUF_INDEX));
    }
    assert_eq!(seen, alloc::vec![2, 0, 1]);
}

#[test]
fn a_completion_the_driver_was_not_holding_is_not_believed() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(2, &ctx).expect("buffers allocate");
    rig.qbuf(0, &ctx).expect("buffer queues");
    rig.streamon(&ctx).expect("stream starts");
    // Buffer 1 was never queued, so it is not the driver's to complete.
    assert!(rig.complete(1, 1, 10));
    assert_eq!(rig.device.state.lock().queue.buffer(1).unwrap().state, BufState::Error);
    let mut arg = alloc::vec![0u8; l::BUFFER_SIZE];
    w32(&mut arg, l::BUF_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    rig.call(VIDIOC_DQBUF, &mut arg, &ctx).expect("it still comes back to the caller");
    assert_eq!(r32(&arg, l::BUF_INDEX), 1);
    assert!(r32(&arg, l::BUF_FLAGS) & flags::BUF_FLAG_ERROR != 0);
}

#[test]
fn a_buffer_returned_unused_goes_back_on_the_queue_not_the_done_list() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(1, &ctx).expect("buffers allocate");
    rig.qbuf(0, &ctx).expect("buffer queues");
    rig.streamon(&ctx).expect("stream starts");
    let landed = {
        let mut state = rig.device.state.lock();
        crate::vb2::stream::buffer_done(&mut state.queue, &crate::vb2::Completion {
            index: 0, state: BufState::Queued, bytesused: [0; l::MAX_PLANES],
            timestamp_ns: 0, sequence: 0, field: flags::FIELD_NONE, last: false,
        })
    };
    assert!(!landed, "an unused buffer must not wake a waiting reader");
    let state = rig.device.state.lock();
    assert!(state.queue.done.is_empty());
    assert_eq!(state.queue.queued.front().copied(), Some(0));
}

#[test]
fn poll_reports_error_off_stream_and_readable_only_with_a_completed_buffer() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    {
        let state = rig.device.state.lock();
        // Not streaming is an error, not "not ready": a program polling a
        // stopped device must be woken rather than wait forever.
        assert_eq!(poll::queue_mask(&state.queue), poll::POLL_ERR);
    }
    rig.reqbufs(2, &ctx).expect("buffers allocate");
    rig.qbuf(0, &ctx).expect("buffer queues");
    rig.streamon(&ctx).expect("stream starts");
    assert_eq!(poll::queue_mask(&rig.device.state.lock().queue), 0);
    assert!(rig.complete(0, 1, 10));
    assert_eq!(poll::queue_mask(&rig.device.state.lock().queue), poll::POLL_IN);
    // The end-of-stream marker reads as readable so the dequeue it provokes
    // can report the pipe closed.
    {
        let mut state = rig.device.state.lock();
        state.queue.done.clear();
        state.queue.last_buffer_dequeued = true;
        assert_eq!(poll::queue_mask(&state.queue), poll::POLL_IN);
        state.queue.error = true;
        assert_eq!(poll::queue_mask(&state.queue), poll::POLL_ERR);
    }
    // An event contributes the priority bit and nothing else.
    let state = rig.device.state.lock();
    assert_eq!(poll::poll_mask(&state.queue, true) & poll::POLL_PRI, poll::POLL_PRI);
}

#[test]
fn closing_the_owning_handle_frees_the_pool_and_stops_the_transport() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(2, &ctx).expect("buffers allocate");
    rig.qbuf(0, &ctx).expect("buffer queues");
    rig.streamon(&ctx).expect("stream starts");
    assert!(rig.alloc.outstanding.load(Ordering::Acquire) > 0);
    crate::device::close(&rig.handle);
    assert_eq!(rig.ops.stop_count.load(Ordering::Acquire), 1);
    assert_eq!(rig.alloc.outstanding.load(Ordering::Acquire), 0);
    assert_eq!(rig.device.state.lock().queue.num_buffers(), 0);
}

#[test]
fn a_second_handle_cannot_take_a_claimed_queue() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(2, &ctx).expect("first handle claims the queue");
    let other = crate::device::open(&rig.device);
    let mut arg = alloc::vec![0u8; l::REQUESTBUFFERS_SIZE];
    w32(&mut arg, l::REQBUFS_COUNT, 4);
    w32(&mut arg, l::REQBUFS_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    w32(&mut arg, l::REQBUFS_MEMORY, flags::MEMORY_MMAP);
    assert_eq!(crate::ioctl::dispatch(&other, VIDIOC_REQBUFS, &mut arg, &ctx), Err(Errno::Ebusy));
    crate::device::close(&other);
}

#[test]
fn a_blocking_dequeue_publishes_its_wait() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(2, &ctx).expect("buffers allocate");
    rig.qbuf(0, &ctx).expect("buffer queues");
    rig.streamon(&ctx).expect("stream starts");
    // The wait must be visible WHILE it lasts, or the two rules keyed on it —
    // a second dequeue, and a reallocation under a parked reader — can never
    // fire. The context observes the flag from inside the wait, which is the
    // only moment it is true; asserting after the call returns would pass
    // whether the flag was ever set or not.
    let blocking = FakeCtx::new(false);
    let mut arg = alloc::vec![0u8; l::BUFFER_SIZE];
    w32(&mut arg, l::BUF_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    assert_eq!(rig.call(VIDIOC_DQBUF, &mut arg, &blocking), Err(Errno::Eintr));
    assert!(blocking.saw_waiting.load(Ordering::Acquire),
            "the parked reader must be visible to everyone else while it sleeps");
    assert!(!rig.device.state.lock().queue.waiting_in_dqbuf,
            "and must not survive the wait it describes");

    // With a reader parked, a second dequeue is EBUSY and a reallocating
    // REQBUFS is refused; freeing everything is still allowed.
    rig.device.state.lock().queue.waiting_in_dqbuf = true;
    assert_eq!(rig.call(VIDIOC_DQBUF, &mut arg, &ctx), Err(Errno::Ebusy));
    let mut req = alloc::vec![0u8; l::REQUESTBUFFERS_SIZE];
    w32(&mut req, l::REQBUFS_COUNT, 4);
    w32(&mut req, l::REQBUFS_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    w32(&mut req, l::REQBUFS_MEMORY, flags::MEMORY_MMAP);
    rig.streamoff(&ctx).expect("stop so the streaming check does not mask this");
    assert_eq!(rig.call(VIDIOC_REQBUFS, &mut req, &ctx), Err(Errno::Ebusy));
    w32(&mut req, l::REQBUFS_COUNT, 0);
    rig.call(VIDIOC_REQBUFS, &mut req, &ctx).expect("freeing is not refused");
    rig.device.state.lock().queue.waiting_in_dqbuf = false;
}
