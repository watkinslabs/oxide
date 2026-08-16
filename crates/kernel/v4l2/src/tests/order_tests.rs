//! The order the dispatch applies its checks in, and the priority ladder.
//!
//! Order is the contract here, not an implementation detail: a program that
//! lost its device, one built against a newer kernel, and one outranked by a
//! recorder must each get the answer that tells them which happened.

use syscall::errno::Errno;

use super::harness::{FakeCtx, Rig};
use crate::prio::{self, PrioState};
use crate::uapi::flags;
use crate::uapi::ioctl::*;
use crate::uapi::layout as l;
use crate::usermem::w32;

#[test]
fn a_command_this_core_does_not_implement_is_enotty() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let mut arg = alloc::vec![0u8; l::CAPABILITY_SIZE];
    // A V4L2-typed command with an ordinal nothing here answers.
    assert_eq!(rig.call(0xc040_5629, &mut arg, &ctx), Err(Errno::Enotty));
    // A command belonging to another subsystem entirely.
    assert_eq!(rig.call(0x8004_5500, &mut arg, &ctx), Err(Errno::Enotty));
    // A camera has no analogue standard, and that is ENOTTY rather than
    // EINVAL so an application does not offer a standard selector.
    let mut std = alloc::vec![0u8; 8];
    assert_eq!(rig.call(VIDIOC_G_STD, &mut std, &ctx), Err(Errno::Enotty));
    assert_eq!(rig.call(VIDIOC_QUERYSTD, &mut std, &ctx), Err(Errno::Enotty));
}

#[test]
fn a_gone_device_answers_enodev_before_anything_else() {
    let ops = super::harness::FakeOps::new();
    let _ = &ops;
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    crate::device::unregister(&rig.device);
    let mut arg = alloc::vec![0u8; l::CAPABILITY_SIZE];
    // Even the first command an application sends, and even an unknown one:
    // the device being gone outranks both.
    assert_eq!(rig.call(VIDIOC_QUERYCAP, &mut arg, &ctx), Err(Errno::Enodev));
    assert_eq!(rig.call(0xc040_5629, &mut arg, &ctx), Err(Errno::Enodev));
}

#[test]
fn unregistering_stops_the_transport_and_returns_the_buffers() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(2, &ctx).expect("buffers allocate");
    rig.qbuf(0, &ctx).expect("buffer queues");
    rig.streamon(&ctx).expect("stream starts");
    crate::device::unregister(&rig.device);
    use core::sync::atomic::Ordering;
    assert_eq!(rig.ops.stop_count.load(Ordering::Acquire), 1);
    assert!(!rig.device.state.lock().queue.streaming);
    assert!(!rig.device.registered());
}

#[test]
fn the_priority_ladder_locks_out_only_a_strictly_lower_handle() {
    let state = PrioState::new();
    assert_eq!(state.max(), flags::PRIORITY_UNSET);
    state.change(flags::PRIORITY_UNSET, flags::PRIORITY_INTERACTIVE).expect("claim");
    assert_eq!(state.max(), flags::PRIORITY_INTERACTIVE);
    // Equal priority shares the device; two interactive programs coexist.
    assert_eq!(state.check(flags::PRIORITY_INTERACTIVE), Ok(()));
    assert_eq!(state.check(flags::PRIORITY_BACKGROUND), Err(Errno::Ebusy));
    assert_eq!(state.check(flags::PRIORITY_RECORD), Ok(()));
    // A recorder outranks everything below it.
    state.change(flags::PRIORITY_UNSET, flags::PRIORITY_RECORD).expect("claim");
    assert_eq!(state.max(), flags::PRIORITY_RECORD);
    assert_eq!(state.check(flags::PRIORITY_INTERACTIVE), Err(Errno::Ebusy));
    // The unset level never blocks: a handle that never chose is not
    // arbitrated against.
    assert_eq!(state.check(flags::PRIORITY_UNSET), Ok(()));
    // Releasing the recorder lowers the device only because it was the last
    // holder of that level.
    state.release(flags::PRIORITY_RECORD);
    assert_eq!(state.max(), flags::PRIORITY_INTERACTIVE);
    state.release(flags::PRIORITY_INTERACTIVE);
    assert_eq!(state.max(), flags::PRIORITY_UNSET);
    // Releasing a level nobody holds does not wrap the count into a level
    // held forever.
    state.release(flags::PRIORITY_RECORD);
    assert_eq!(state.max(), flags::PRIORITY_UNSET);
}

#[test]
fn only_the_state_changing_commands_are_arbitrated() {
    for cmd in [VIDIOC_S_FMT, VIDIOC_S_INPUT, VIDIOC_S_CTRL, VIDIOC_S_EXT_CTRLS,
                VIDIOC_S_PARM, VIDIOC_REQBUFS, VIDIOC_CREATE_BUFS, VIDIOC_PREPARE_BUF,
                VIDIOC_STREAMON, VIDIOC_STREAMOFF, VIDIOC_S_SELECTION, VIDIOC_S_CROP,
                VIDIOC_REMOVE_BUFS] {
        assert!(prio::needs_prio(cmd), "{cmd:#x} changes what another handle sees");
    }
    for cmd in [VIDIOC_QUERYCAP, VIDIOC_G_FMT, VIDIOC_TRY_FMT, VIDIOC_ENUM_FMT,
                VIDIOC_G_CTRL, VIDIOC_QUERYCTRL, VIDIOC_QBUF, VIDIOC_DQBUF,
                VIDIOC_QUERYBUF, VIDIOC_DQEVENT, VIDIOC_SUBSCRIBE_EVENT] {
        assert!(!prio::needs_prio(cmd), "{cmd:#x} must not need a priority");
    }
}

#[test]
fn a_recorder_locks_out_a_background_handles_writes_but_not_its_reads() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let recorder = crate::device::open(&rig.device);
    {
        let mut arg = alloc::vec![0u8; 4];
        w32(&mut arg, 0, flags::PRIORITY_RECORD);
        crate::ioctl::dispatch(&recorder, VIDIOC_S_PRIORITY, &mut arg, &ctx)
            .expect("the recorder claims the device");
    }
    {
        let mut arg = alloc::vec![0u8; 4];
        w32(&mut arg, 0, flags::PRIORITY_BACKGROUND);
        rig.call(VIDIOC_S_PRIORITY, &mut arg, &ctx).expect("the preview lowers itself");
    }
    let mut fmt = alloc::vec![0u8; l::FORMAT_SIZE];
    w32(&mut fmt, l::FORMAT_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    assert_eq!(rig.call(VIDIOC_S_FMT, &mut fmt, &ctx), Err(Errno::Ebusy));
    // Reading is never arbitrated.
    rig.call(VIDIOC_G_FMT, &mut fmt, &ctx).expect("the preview can still look");
    rig.call(VIDIOC_TRY_FMT, &mut fmt, &ctx).expect("and can still negotiate");
    // The recorder itself is not blocked.
    crate::ioctl::dispatch(&recorder, VIDIOC_S_FMT, &mut fmt, &ctx)
        .expect("the recorder writes freely");
    crate::device::close(&recorder);
    // With the recorder gone the preview regains the device.
    rig.call(VIDIOC_S_FMT, &mut fmt, &ctx).expect("the lock is released on close");
}

#[test]
fn a_priority_outside_the_enumeration_is_refused() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let mut arg = alloc::vec![0u8; 4];
    w32(&mut arg, 0, flags::PRIORITY_UNSET);
    assert_eq!(rig.call(VIDIOC_S_PRIORITY, &mut arg, &ctx), Err(Errno::Einval),
               "the unset level describes a device nobody claimed; it is not settable");
    w32(&mut arg, 0, 99);
    assert_eq!(rig.call(VIDIOC_S_PRIORITY, &mut arg, &ctx), Err(Errno::Einval));
    w32(&mut arg, 0, flags::PRIORITY_RECORD);
    rig.call(VIDIOC_S_PRIORITY, &mut arg, &ctx).expect("a real level is accepted");
    let mut got = alloc::vec![0u8; 4];
    rig.call(VIDIOC_G_PRIORITY, &mut got, &ctx).expect("read it back");
    assert_eq!(crate::usermem::r32(&got, 0), flags::PRIORITY_RECORD);
}

#[test]
fn inputs_enumerate_and_switching_is_refused_once_buffers_exist() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    for index in 0..super::harness::INPUTS.len() as u32 {
        let mut arg = alloc::vec![0u8; l::INPUT_SIZE];
        w32(&mut arg, l::INPUT_INDEX, index);
        rig.call(VIDIOC_ENUMINPUT, &mut arg, &ctx).expect("input enumerates");
        assert_eq!(crate::usermem::r32(&arg, l::INPUT_TYPE), flags::INPUT_TYPE_CAMERA);
    }
    let mut past = alloc::vec![0u8; l::INPUT_SIZE];
    w32(&mut past, l::INPUT_INDEX, super::harness::INPUTS.len() as u32);
    assert_eq!(rig.call(VIDIOC_ENUMINPUT, &mut past, &ctx), Err(Errno::Einval));

    let mut set = alloc::vec![0u8; 4];
    w32(&mut set, 0, 1);
    rig.call(VIDIOC_S_INPUT, &mut set, &ctx).expect("switching succeeds while idle");
    let mut got = alloc::vec![0u8; 4];
    rig.call(VIDIOC_G_INPUT, &mut got, &ctx).expect("read it back");
    assert_eq!(crate::usermem::r32(&got, 0), 1);
    w32(&mut set, 0, 5);
    assert_eq!(rig.call(VIDIOC_S_INPUT, &mut set, &ctx), Err(Errno::Einval));
    rig.reqbufs(2, &ctx).expect("buffers allocate");
    w32(&mut set, 0, 0);
    assert_eq!(rig.call(VIDIOC_S_INPUT, &mut set, &ctx), Err(Errno::Ebusy));
}

#[test]
fn cropping_reports_the_whole_frame_and_refuses_a_smaller_rectangle() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let mut cap = alloc::vec![0u8; l::CROPCAP_SIZE];
    w32(&mut cap, l::CROPCAP_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    rig.call(VIDIOC_CROPCAP, &mut cap, &ctx).expect("cropcap succeeds");
    assert_eq!(crate::usermem::r32(&cap, l::CROPCAP_BOUNDS_WIDTH), 320);
    assert_eq!(crate::usermem::r32(&cap, l::CROPCAP_PIXELASPECT_NUM), 1);
    assert_eq!(crate::usermem::r32(&cap, l::CROPCAP_PIXELASPECT_DEN), 1);

    let mut crop = alloc::vec![0u8; l::CROP_SIZE];
    w32(&mut crop, l::CROP_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    rig.call(VIDIOC_G_CROP, &mut crop, &ctx).expect("g_crop succeeds");
    assert_eq!(crate::usermem::r32(&crop, l::CROP_C_WIDTH), 320);
    rig.call(VIDIOC_S_CROP, &mut crop, &ctx).expect("setting the whole frame is the identity");
    w32(&mut crop, l::CROP_C_WIDTH, 160);
    assert_eq!(rig.call(VIDIOC_S_CROP, &mut crop, &ctx), Err(Errno::Einval),
               "a device that cannot crop must say so rather than ignore the request");

    let mut sel = alloc::vec![0u8; l::SELECTION_SIZE];
    w32(&mut sel, l::SEL_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    w32(&mut sel, l::SEL_TARGET, flags::SEL_TGT_CROP_BOUNDS);
    rig.call(VIDIOC_G_SELECTION, &mut sel, &ctx).expect("g_selection succeeds");
    assert_eq!(crate::usermem::r32(&sel, l::SEL_R_HEIGHT), 240);
    w32(&mut sel, l::SEL_TARGET, flags::SEL_TGT_COMPOSE);
    assert_eq!(rig.call(VIDIOC_G_SELECTION, &mut sel, &ctx), Err(Errno::Einval));
}

#[test]
fn a_short_argument_is_refused_rather_than_read_past() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let mut tiny = alloc::vec![0u8; 2];
    assert_eq!(rig.call(VIDIOC_QUERYCAP, &mut tiny, &ctx), Err(Errno::Einval));
    assert_eq!(rig.call(VIDIOC_STREAMON, &mut tiny, &ctx), Err(Errno::Einval));
    assert_eq!(rig.call(VIDIOC_G_FMT, &mut tiny, &ctx), Err(Errno::Einval));
    assert_eq!(rig.call(VIDIOC_QBUF, &mut tiny, &ctx), Err(Errno::Einval));
    assert_eq!(rig.call(VIDIOC_DQEVENT, &mut tiny, &ctx), Err(Errno::Einval));
}
