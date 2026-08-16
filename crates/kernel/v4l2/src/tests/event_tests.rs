//! Event subscription, delivery, overflow and dequeue.

use syscall::errno::Errno;

use super::harness::{FakeCtx, Rig};
use crate::event::{Event, EventQueue};
use crate::uapi::ctrl_ids as cid;
use crate::uapi::ioctl::*;
use crate::uapi::layout as l;
use crate::uapi::flags;
use crate::usermem::{r32, r64, w32};

fn subscribe(rig: &Rig, ctx: &FakeCtx, ev_type: u32, id: u32, sub_flags: u32)
    -> Result<(), Errno>
{
    let mut arg = alloc::vec![0u8; l::EVENT_SUBSCRIPTION_SIZE];
    w32(&mut arg, l::EVSUB_TYPE, ev_type);
    w32(&mut arg, l::EVSUB_ID, id);
    w32(&mut arg, l::EVSUB_FLAGS, sub_flags);
    rig.call(VIDIOC_SUBSCRIBE_EVENT, &mut arg, ctx)
}

#[test]
fn the_catch_all_type_cannot_be_subscribed_but_can_be_unsubscribed() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    assert_eq!(subscribe(&rig, &ctx, flags::EVENT_ALL, 0, 0), Err(Errno::Einval),
               "nothing ever delivers it, so a waiter would hang");
    subscribe(&rig, &ctx, flags::EVENT_CTRL, cid::CID_BRIGHTNESS, 0).expect("subscribe");
    subscribe(&rig, &ctx, flags::EVENT_FRAME_SYNC, 0, 0).expect("subscribe");
    let mut arg = alloc::vec![0u8; l::EVENT_SUBSCRIPTION_SIZE];
    w32(&mut arg, l::EVSUB_TYPE, flags::EVENT_ALL);
    rig.call(VIDIOC_UNSUBSCRIBE_EVENT, &mut arg, &ctx).expect("unsubscribe everything");
    let mut dq = alloc::vec![0u8; l::EVENT_SIZE];
    assert_eq!(rig.call(VIDIOC_DQEVENT, &mut dq, &ctx), Err(Errno::Enoent));
}

#[test]
fn subscribing_to_a_control_the_device_lacks_is_refused() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    assert_eq!(subscribe(&rig, &ctx, flags::EVENT_CTRL, cid::CID_ZOOM_ABSOLUTE, 0),
               Err(Errno::Einval),
               "an event that will never fire would hang a program waiting on it");
    assert_eq!(subscribe(&rig, &ctx, 0x1234, 0, 0), Err(Errno::Einval));
    subscribe(&rig, &ctx, flags::EVENT_PRIVATE_START + 3, 0, 0)
        .expect("a driver-private event is admitted");
}

#[test]
fn dqevent_on_an_empty_queue_is_enoent_not_eagain() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    subscribe(&rig, &ctx, flags::EVENT_CTRL, cid::CID_BRIGHTNESS, 0).expect("subscribe");
    let mut arg = alloc::vec![0u8; l::EVENT_SIZE];
    // Programs test for exactly this, and it differs from the buffer path's
    // EAGAIN on purpose.
    assert_eq!(rig.call(VIDIOC_DQEVENT, &mut arg, &ctx), Err(Errno::Enoent));
}

#[test]
fn the_initial_state_flag_delivers_the_control_straight_away() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    subscribe(&rig, &ctx, flags::EVENT_CTRL, cid::CID_CONTRAST,
              flags::EVENT_SUB_FL_SEND_INITIAL).expect("subscribe");
    let mut arg = alloc::vec![0u8; l::EVENT_SIZE];
    rig.call(VIDIOC_DQEVENT, &mut arg, &ctx).expect("the initial event is waiting");
    assert_eq!(r32(&arg, l::EVENT_TYPE), flags::EVENT_CTRL);
    assert_eq!(r32(&arg, l::EVENT_ID), cid::CID_CONTRAST);
    assert_eq!(r32(&arg, l::EVENT_PENDING), 0);
    assert_eq!(r32(&arg, l::EVENT_SEQUENCE), 1);
    assert_eq!(r64(&arg, l::EVENT_TIMESTAMP_SEC), 1234);
    assert_eq!(r64(&arg, l::EVENT_TIMESTAMP_NSEC), 567_000_000);
    let payload = &arg[l::EVENT_U..l::EVENT_U + l::EVENT_U_LEN];
    assert_eq!(r32(payload, l::EVENT_CTRL_TYPE), cid::CTRL_TYPE_INTEGER);
    assert_eq!(r32(payload, l::EVENT_CTRL_VALUE), 50);
    assert_eq!(r32(payload, l::EVENT_CTRL_MAXIMUM), 100);
    assert!(r32(payload, l::EVENT_CTRL_CHANGES) & flags::EVENT_CTRL_CH_VALUE != 0);
}

#[test]
fn a_control_change_reaches_a_watching_handle_but_not_its_author() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let watcher = crate::device::open(&rig.device);
    {
        let mut arg = alloc::vec![0u8; l::EVENT_SUBSCRIPTION_SIZE];
        w32(&mut arg, l::EVSUB_TYPE, flags::EVENT_CTRL);
        w32(&mut arg, l::EVSUB_ID, cid::CID_BRIGHTNESS);
        crate::ioctl::dispatch(&watcher, VIDIOC_SUBSCRIBE_EVENT, &mut arg, &ctx)
            .expect("the watcher subscribes");
    }
    subscribe(&rig, &ctx, flags::EVENT_CTRL, cid::CID_BRIGHTNESS, 0)
        .expect("the author subscribes too");
    let mut set = alloc::vec![0u8; l::CONTROL_SIZE];
    w32(&mut set, l::CONTROL_ID, cid::CID_BRIGHTNESS);
    crate::usermem::w32i(&mut set, l::CONTROL_VALUE, 30);
    rig.call(VIDIOC_S_CTRL, &mut set, &ctx).expect("the author writes");

    let mut got = alloc::vec![0u8; l::EVENT_SIZE];
    crate::ioctl::dispatch(&watcher, VIDIOC_DQEVENT, &mut got, &ctx)
        .expect("the watcher is told");
    assert_eq!(r32(&got, l::EVENT_ID), cid::CID_BRIGHTNESS);
    let payload = &got[l::EVENT_U..l::EVENT_U + l::EVENT_U_LEN];
    assert_eq!(r32(payload, l::EVENT_CTRL_VALUE), 30);
    // Without the feedback flag the author does not process its own write.
    let mut mine = alloc::vec![0u8; l::EVENT_SIZE];
    assert_eq!(rig.call(VIDIOC_DQEVENT, &mut mine, &ctx), Err(Errno::Enoent));
    crate::device::close(&watcher);
}

#[test]
fn the_feedback_flag_echoes_a_handles_own_write_back_to_it() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    subscribe(&rig, &ctx, flags::EVENT_CTRL, cid::CID_BRIGHTNESS,
              flags::EVENT_SUB_FL_ALLOW_FEEDBACK).expect("subscribe");
    let mut set = alloc::vec![0u8; l::CONTROL_SIZE];
    w32(&mut set, l::CONTROL_ID, cid::CID_BRIGHTNESS);
    crate::usermem::w32i(&mut set, l::CONTROL_VALUE, 30);
    rig.call(VIDIOC_S_CTRL, &mut set, &ctx).expect("write succeeds");
    let mut got = alloc::vec![0u8; l::EVENT_SIZE];
    rig.call(VIDIOC_DQEVENT, &mut got, &ctx).expect("the author hears its own write");
    assert_eq!(r32(&got, l::EVENT_ID), cid::CID_BRIGHTNESS);
}

#[test]
fn a_full_ring_drops_the_oldest_and_leaves_a_gap_in_the_sequence() {
    let mut q = EventQueue::new();
    // A depth of two, so the third delivery must evict the first.
    q.subscribe(flags::EVENT_FRAME_SYNC, 0, 0, 2).expect("subscribe");
    for n in 1..=3u32 { assert!(q.queue(Event::frame_sync(n), 0, 0)); }
    assert_eq!(q.available(), 2);
    let (first, pending) = q.dequeue().expect("an event is waiting");
    assert_eq!(pending, 1);
    let (second, pending) = q.dequeue().expect("an event is waiting");
    assert_eq!(pending, 0);
    // The sequence counts deliveries, including the one whose event was
    // evicted — which is the only way an application learns it lost one.
    assert_eq!(first.sequence, 2);
    assert_eq!(second.sequence, 3);
    assert_eq!(second.sequence - first.sequence, 1);
    assert_eq!(q.dequeue().err(), Some(Errno::Enoent));
    // The evicted event is gone: the two survivors are the two newest.
    assert_eq!(r32(&first.payload, l::EVENT_FRAME_SYNC_SEQUENCE), 2);
    assert_eq!(r32(&second.payload, l::EVENT_FRAME_SYNC_SEQUENCE), 3);
}

#[test]
fn a_control_ring_is_one_deep_so_only_the_newest_value_survives() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let watcher = crate::device::open(&rig.device);
    let mut sub = alloc::vec![0u8; l::EVENT_SUBSCRIPTION_SIZE];
    w32(&mut sub, l::EVSUB_TYPE, flags::EVENT_CTRL);
    w32(&mut sub, l::EVSUB_ID, cid::CID_BRIGHTNESS);
    crate::ioctl::dispatch(&watcher, VIDIOC_SUBSCRIBE_EVENT, &mut sub, &ctx).expect("subscribe");
    for value in [10i32, 20, 30] {
        let mut set = alloc::vec![0u8; l::CONTROL_SIZE];
        w32(&mut set, l::CONTROL_ID, cid::CID_BRIGHTNESS);
        crate::usermem::w32i(&mut set, l::CONTROL_VALUE, value);
        rig.call(VIDIOC_S_CTRL, &mut set, &ctx).expect("write succeeds");
    }
    let mut got = alloc::vec![0u8; l::EVENT_SIZE];
    crate::ioctl::dispatch(&watcher, VIDIOC_DQEVENT, &mut got, &ctx).expect("one event waits");
    let payload = &got[l::EVENT_U..l::EVENT_U + l::EVENT_U_LEN];
    assert_eq!(r32(payload, l::EVENT_CTRL_VALUE), 30,
               "the newest value is the one worth keeping");
    assert_eq!(r32(&got, l::EVENT_PENDING), 0);
    let mut more = alloc::vec![0u8; l::EVENT_SIZE];
    assert_eq!(crate::ioctl::dispatch(&watcher, VIDIOC_DQEVENT, &mut more, &ctx),
               Err(Errno::Enoent));
    crate::device::close(&watcher);
}

#[test]
fn events_are_delivered_in_arrival_order_across_subscriptions() {
    let mut q = EventQueue::new();
    q.subscribe(flags::EVENT_FRAME_SYNC, 0, 0, 4).expect("subscribe");
    q.subscribe(flags::EVENT_SOURCE_CHANGE, 0, 0, 4).expect("subscribe");
    assert!(q.queue(Event::frame_sync(1), 0, 0));
    assert!(q.queue(Event::source_change(0, flags::EVENT_SRC_CH_RESOLUTION), 0, 0));
    assert!(q.queue(Event::frame_sync(2), 0, 0));
    let types: alloc::vec::Vec<u32> = (0..3).map(|_| q.dequeue().unwrap().0.ev_type).collect();
    assert_eq!(types, alloc::vec![flags::EVENT_FRAME_SYNC, flags::EVENT_SOURCE_CHANGE,
                                  flags::EVENT_FRAME_SYNC]);
}

#[test]
fn an_unsubscribed_event_is_not_queued_and_does_not_advance_the_sequence() {
    let mut q = EventQueue::new();
    q.subscribe(flags::EVENT_FRAME_SYNC, 0, 0, 4).expect("subscribe");
    assert!(!q.queue(Event::source_change(0, 1), 0, 0));
    assert_eq!(q.available(), 0);
    assert!(q.queue(Event::frame_sync(1), 0, 0));
    assert_eq!(q.dequeue().unwrap().0.sequence, 1,
               "an event nobody wanted must not consume a sequence number");
}

#[test]
fn subscribing_twice_to_the_same_event_is_a_silent_success() {
    let mut q = EventQueue::new();
    q.subscribe(flags::EVENT_FRAME_SYNC, 0, 0, 2).expect("subscribe");
    q.subscribe(flags::EVENT_FRAME_SYNC, 0, 0, 2).expect("re-subscribing is not an error");
    assert!(q.queue(Event::frame_sync(1), 0, 0));
    assert_eq!(q.available(), 1, "one subscription, so one delivery");
}

#[test]
fn unsubscribing_one_event_leaves_the_others_deliverable() {
    let mut q = EventQueue::new();
    q.subscribe(flags::EVENT_FRAME_SYNC, 0, 0, 4).expect("subscribe");
    q.subscribe(flags::EVENT_SOURCE_CHANGE, 0, 0, 4).expect("subscribe");
    q.subscribe(flags::EVENT_EOS, 0, 0, 4).expect("subscribe");
    assert!(q.queue(Event::frame_sync(1), 0, 0));
    assert!(q.queue(Event::new(flags::EVENT_EOS, 0), 0, 0));
    q.unsubscribe(flags::EVENT_SOURCE_CHANGE, 0).expect("unsubscribe the middle one");
    // The queued events survive and still name the right types after the
    // subscription indices shifted.
    assert_eq!(q.available(), 2);
    assert_eq!(q.dequeue().unwrap().0.ev_type, flags::EVENT_FRAME_SYNC);
    assert_eq!(q.dequeue().unwrap().0.ev_type, flags::EVENT_EOS);
    assert!(!q.queue(Event::source_change(0, 1), 0, 0));
    assert!(q.queue(Event::frame_sync(2), 0, 0));
}
