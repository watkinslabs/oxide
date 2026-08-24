//! Buffer allocation arithmetic and the queue commands' error contract.

use core::sync::atomic::Ordering;
use syscall::errno::Errno;

use super::harness::{FakeCtx, Rig};
use crate::uapi::ioctl::*;
use crate::uapi::layout as l;
use crate::uapi::flags;
use crate::usermem::{r32, r64, w32};
use crate::vb2::{self, BufState};

#[test]
fn reqbufs_allocates_pages_enough_for_the_image() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let made = rig.reqbufs(4, &ctx).expect("buffers allocate");
    assert_eq!(made, 4);
    let state = rig.device.state.lock();
    assert_eq!(state.queue.num_buffers(), 4);
    let plane = &state.queue.buffer(0).unwrap().planes[0];
    // The default format is the first entry at its first size: 320x240 YUYV.
    assert_eq!(plane.length, 320 * 240 * 2);
    assert_eq!(plane.frames.len(), (320u32 * 240 * 2).div_ceil(4096) as usize);
    // Cookies are page-aligned and distinct, or two planes would map to the
    // same offset.
    let a = state.queue.buffer(0).unwrap().planes[0].offset;
    let b = state.queue.buffer(1).unwrap().planes[0].offset;
    assert_ne!(a, b);
    assert_eq!(a % 4096, 0);
    assert_eq!(b % 4096, 0);
    assert_eq!(state.queue.plane_by_offset(b), Some((1, 0)));
    assert_eq!(state.queue.plane_by_offset(b + 1), None);
}

#[test]
fn reqbufs_of_zero_frees_everything_and_returns_the_memory() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(3, &ctx).expect("buffers allocate");
    assert!(rig.alloc.outstanding.load(Ordering::Acquire) > 0);
    assert_eq!(rig.reqbufs(0, &ctx), Ok(0));
    assert_eq!(rig.alloc.outstanding.load(Ordering::Acquire), 0);
    assert_eq!(rig.device.state.lock().queue.num_buffers(), 0);
    assert_eq!(rig.device.state.lock().queue.owner, None);
}

#[test]
fn reqbufs_reallocating_replaces_the_previous_pool() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(4, &ctx).expect("first allocation");
    let first = rig.alloc.outstanding.load(Ordering::Acquire);
    rig.reqbufs(2, &ctx).expect("second allocation replaces the first");
    assert_eq!(rig.device.state.lock().queue.num_buffers(), 2);
    assert_eq!(rig.alloc.outstanding.load(Ordering::Acquire), first / 2);
}

#[test]
fn a_memory_model_the_driver_did_not_declare_is_einval() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let mut arg = alloc::vec![0u8; l::REQUESTBUFFERS_SIZE];
    w32(&mut arg, l::REQBUFS_COUNT, 2);
    w32(&mut arg, l::REQBUFS_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    w32(&mut arg, l::REQBUFS_MEMORY, flags::MEMORY_DMABUF);
    assert_eq!(rig.call(VIDIOC_REQBUFS, &mut arg, &ctx), Err(Errno::Einval));
    w32(&mut arg, l::REQBUFS_MEMORY, flags::MEMORY_OVERLAY);
    assert_eq!(rig.call(VIDIOC_REQBUFS, &mut arg, &ctx), Err(Errno::Einval));
    w32(&mut arg, l::REQBUFS_MEMORY, 99);
    assert_eq!(rig.call(VIDIOC_REQBUFS, &mut arg, &ctx), Err(Errno::Einval));
    // The models it did declare come back in the capabilities word.
    w32(&mut arg, l::REQBUFS_MEMORY, flags::MEMORY_MMAP);
    rig.call(VIDIOC_REQBUFS, &mut arg, &ctx).expect("mmap is supported");
    let caps = r32(&arg, l::REQBUFS_CAPABILITIES);
    assert!(caps & flags::BUF_CAP_SUPPORTS_MMAP != 0);
    assert!(caps & flags::BUF_CAP_SUPPORTS_USERPTR != 0);
    assert_eq!(caps & flags::BUF_CAP_SUPPORTS_DMABUF, 0);
}

#[test]
fn reqbufs_while_streaming_is_ebusy() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(2, &ctx).expect("buffers allocate");
    rig.qbuf(0, &ctx).expect("buffer queues");
    rig.streamon(&ctx).expect("stream starts");
    let mut state = rig.device.state.lock();
    let alloc = rig.alloc.clone();
    let outcome = vb2::reqbufs::reqbufs(&mut state.queue, rig.handle.id,
                                        flags::BUF_TYPE_VIDEO_CAPTURE, flags::MEMORY_MMAP, 4,
                                        |c| Ok(crate::vb2::QueueSetup {
                                            count: c, num_planes: 1,
                                            plane_sizes: [4096; l::MAX_PLANES] }),
                                        alloc.as_ref());
    assert_eq!(outcome.err(), Some(Errno::Ebusy));
}

#[test]
fn create_bufs_grows_the_pool_without_disturbing_it() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(2, &ctx).expect("buffers allocate");
    rig.qbuf(0, &ctx).expect("buffer queues");
    let mut arg = alloc::vec![0u8; l::CREATE_BUFFERS_SIZE];
    w32(&mut arg, l::CREATE_COUNT, 3);
    w32(&mut arg, l::CREATE_MEMORY, flags::MEMORY_MMAP);
    w32(&mut arg, l::CREATE_FORMAT + l::FORMAT_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    rig.call(VIDIOC_CREATE_BUFS, &mut arg, &ctx).expect("pool grows");
    assert_eq!(r32(&arg, l::CREATE_INDEX), 2, "new buffers start after the old ones");
    assert_eq!(r32(&arg, l::CREATE_COUNT), 3);
    let state = rig.device.state.lock();
    assert_eq!(state.queue.num_buffers(), 5);
    assert_eq!(state.queue.buffer(0).unwrap().state, BufState::Queued);
}

#[test]
fn create_bufs_will_not_mix_memory_models() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(2, &ctx).expect("buffers allocate");
    let mut arg = alloc::vec![0u8; l::CREATE_BUFFERS_SIZE];
    w32(&mut arg, l::CREATE_COUNT, 1);
    w32(&mut arg, l::CREATE_MEMORY, flags::MEMORY_USERPTR);
    w32(&mut arg, l::CREATE_FORMAT + l::FORMAT_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    assert_eq!(rig.call(VIDIOC_CREATE_BUFS, &mut arg, &ctx), Err(Errno::Einval));
}

#[test]
fn querybuf_reports_the_mmap_cookie_and_length() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(2, &ctx).expect("buffers allocate");
    let mut arg = alloc::vec![0u8; l::BUFFER_SIZE];
    w32(&mut arg, l::BUF_INDEX, 1);
    w32(&mut arg, l::BUF_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    rig.call(VIDIOC_QUERYBUF, &mut arg, &ctx).expect("querybuf succeeds");
    assert_eq!(r32(&arg, l::BUF_INDEX), 1);
    assert_eq!(r32(&arg, l::BUF_MEMORY), flags::MEMORY_MMAP);
    assert_eq!(r32(&arg, l::BUF_LENGTH), 320 * 240 * 2);
    let cookie = r64(&arg, l::BUF_M);
    let expect = rig.device.state.lock().queue.buffer(1).unwrap().planes[0].offset as u64;
    assert_eq!(cookie, expect);
    // Nothing has been queued, so no state flag is set.
    assert_eq!(r32(&arg, l::BUF_FLAGS) & flags::BUF_FLAG_QUEUED, 0);
    // An index past the pool is EINVAL, which is how an application stops
    // walking it.
    w32(&mut arg, l::BUF_INDEX, 2);
    assert_eq!(rig.call(VIDIOC_QUERYBUF, &mut arg, &ctx), Err(Errno::Einval));
}

#[test]
fn qbuf_twice_on_the_same_buffer_is_einval() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(2, &ctx).expect("buffers allocate");
    rig.qbuf(0, &ctx).expect("first queue succeeds");
    assert_eq!(rig.qbuf(0, &ctx), Err(Errno::Einval),
               "a second queue would have the frame delivered twice");
    // A different buffer is still fine.
    rig.qbuf(1, &ctx).expect("a different buffer queues");
}

#[test]
fn qbuf_reports_the_queued_flag_back_to_the_caller() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(1, &ctx).expect("buffers allocate");
    let mut arg = alloc::vec![0u8; l::BUFFER_SIZE];
    w32(&mut arg, l::BUF_INDEX, 0);
    w32(&mut arg, l::BUF_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    w32(&mut arg, l::BUF_MEMORY, flags::MEMORY_MMAP);
    rig.call(VIDIOC_QBUF, &mut arg, &ctx).expect("queue succeeds");
    let reported = r32(&arg, l::BUF_FLAGS);
    assert!(reported & flags::BUF_FLAG_QUEUED != 0);
    assert!(reported & flags::BUF_FLAG_TIMESTAMP_MONOTONIC != 0);
}

#[test]
fn a_memory_model_that_does_not_match_the_pool_is_einval() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(1, &ctx).expect("buffers allocate");
    let mut arg = alloc::vec![0u8; l::BUFFER_SIZE];
    w32(&mut arg, l::BUF_INDEX, 0);
    w32(&mut arg, l::BUF_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    w32(&mut arg, l::BUF_MEMORY, flags::MEMORY_USERPTR);
    assert_eq!(rig.call(VIDIOC_QBUF, &mut arg, &ctx), Err(Errno::Einval));
}

#[test]
fn prepare_buf_marks_the_buffer_and_refuses_a_second_time() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(1, &ctx).expect("buffers allocate");
    let mut arg = alloc::vec![0u8; l::BUFFER_SIZE];
    w32(&mut arg, l::BUF_INDEX, 0);
    w32(&mut arg, l::BUF_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    w32(&mut arg, l::BUF_MEMORY, flags::MEMORY_MMAP);
    rig.call(VIDIOC_PREPARE_BUF, &mut arg, &ctx).expect("prepare succeeds");
    assert!(r32(&arg, l::BUF_FLAGS) & flags::BUF_FLAG_PREPARED != 0);
    assert_eq!(rig.call(VIDIOC_PREPARE_BUF, &mut arg, &ctx), Err(Errno::Einval));
    // A prepared buffer still queues.
    rig.qbuf(0, &ctx).expect("a prepared buffer queues");
}

#[test]
fn remove_bufs_refuses_a_buffer_the_queue_still_owns() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(4, &ctx).expect("buffers allocate");
    rig.qbuf(1, &ctx).expect("buffer queues");
    let mut arg = alloc::vec![0u8; l::REQUESTBUFFERS_SIZE];
    w32(&mut arg, 0, 1);
    w32(&mut arg, 4, 2);
    assert_eq!(rig.call(VIDIOC_REMOVE_BUFS, &mut arg, &ctx), Err(Errno::Ebusy));
    // The idle tail can go, and the survivors are renumbered so the indices an
    // application enumerates still name them.
    w32(&mut arg, 0, 2);
    w32(&mut arg, 4, 2);
    rig.call(VIDIOC_REMOVE_BUFS, &mut arg, &ctx).expect("idle buffers are removed");
    let state = rig.device.state.lock();
    assert_eq!(state.queue.num_buffers(), 2);
    assert_eq!(state.queue.buffer(0).unwrap().index, 0);
    assert_eq!(state.queue.buffer(1).unwrap().index, 1);
    // A range past the end is refused before anything is freed.
    drop(state);
    w32(&mut arg, 0, 1);
    w32(&mut arg, 4, 5);
    assert_eq!(rig.call(VIDIOC_REMOVE_BUFS, &mut arg, &ctx), Err(Errno::Einval));
    assert_eq!(rig.device.state.lock().queue.num_buffers(), 2);
}

#[test]
fn expbuf_refuses_rather_than_returning_a_descriptor_that_names_nothing() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(1, &ctx).expect("buffers allocate");
    let mut arg = alloc::vec![0u8; l::EXPORTBUFFER_SIZE];
    w32(&mut arg, l::EXPBUF_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    w32(&mut arg, l::EXPBUF_INDEX, 0);
    assert_eq!(rig.call(VIDIOC_EXPBUF, &mut arg, &ctx), Err(Errno::Einval));
    // The type and index are still validated first, so a caller learns which
    // of the two was wrong before it learns exporting is unavailable.
    w32(&mut arg, l::EXPBUF_INDEX, 9);
    assert_eq!(rig.call(VIDIOC_EXPBUF, &mut arg, &ctx), Err(Errno::Einval));
}
