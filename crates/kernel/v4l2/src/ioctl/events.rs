//! Event subscription and dequeue.

use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::device::FileHandle;
use crate::event::{Event, DEFAULT_ELEMS};
use crate::uapi::ctrl_ids as cid;
use crate::uapi::flags;
use crate::uapi::layout as l;
use crate::usermem::{r32, w32, w64, zero};
use super::Ctx;

/// Ring depth for one subscription.
///
/// A control's ring is one deep because the newest value is the only one worth
/// having: an application that missed two intermediate brightness values wants
/// the current one, not a backlog. Everything else keeps a short history, so a
/// burst of frame-sync events is not collapsed into one.
/// # C: O(1)
fn ring_depth(ev_type: u32) -> usize {
    match ev_type {
        flags::EVENT_CTRL => 1,
        _ => DEFAULT_ELEMS,
    }
}

/// `VIDIOC_SUBSCRIBE_EVENT`.
///
/// A subscription to a control the device does not have is refused: the event
/// would never fire, and an application waiting on it would hang rather than
/// learn the control is missing.
/// # C: O(subscriptions)
pub fn subscribe(handle: &Arc<FileHandle>, arg: &mut [u8], ctx: &dyn Ctx) -> Result<(), Errno> {
    if arg.len() < l::EVENT_SUBSCRIPTION_SIZE { return Err(Errno::Einval); }
    let ev_type = r32(arg, l::EVSUB_TYPE);
    let id = r32(arg, l::EVSUB_ID);
    let sub_flags = r32(arg, l::EVSUB_FLAGS);
    let device = handle.device.clone();
    match ev_type {
        flags::EVENT_CTRL => { device.controls.find(id).ok_or(Errno::Einval)?; }
        flags::EVENT_FRAME_SYNC | flags::EVENT_SOURCE_CHANGE | flags::EVENT_EOS
        | flags::EVENT_VSYNC | flags::EVENT_MOTION_DET => {}
        t if t >= flags::EVENT_PRIVATE_START => {}
        _ => return Err(Errno::Einval),
    }
    {
        let mut queue = handle.events.lock();
        queue.subscribe(ev_type, id, sub_flags, ring_depth(ev_type))?;
    }
    // The initial-state flag asks for the control's present value straight
    // away, so a program does not have to read it separately and race a change
    // that lands between the read and the subscription.
    if ev_type == flags::EVENT_CTRL && sub_flags & flags::EVENT_SUB_FL_SEND_INITIAL != 0 {
        if let Some(desc) = device.controls.find(id).copied() {
            let value = device.controls.value(id).unwrap_or(desc.default_value);
            let cflags = device.controls.flags(id).unwrap_or(0);
            let ev = Event::control(id, flags::EVENT_CTRL_CH_VALUE | flags::EVENT_CTRL_CH_FLAGS,
                                    desc.ctrl_type, value, cflags,
                                    desc.minimum as i32, desc.maximum as i32,
                                    desc.step as i32, desc.default_value as i32);
            let (sec, nsec) = ctx.now();
            handle.events.lock().queue(ev, sec, nsec);
            ctx.wake(&device);
        }
    }
    let _ = cid::CTRL_ID_MASK;
    Ok(())
}

/// `VIDIOC_UNSUBSCRIBE_EVENT`. The catch-all type drops everything, which is
/// how a program detaches without listing what it subscribed to.
/// # C: O(subscriptions)
pub fn unsubscribe(handle: &Arc<FileHandle>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::EVENT_SUBSCRIPTION_SIZE { return Err(Errno::Einval); }
    handle.events.lock().unsubscribe(r32(arg, l::EVSUB_TYPE), r32(arg, l::EVSUB_ID))
}

/// `VIDIOC_DQEVENT`.
///
/// An empty queue is `ENOENT`. That differs from the buffer path's `EAGAIN`
/// on purpose and programs test for it, so the two must not be unified.
/// # C: O(1)
pub fn dqevent(handle: &Arc<FileHandle>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::EVENT_SIZE { return Err(Errno::Einval); }
    let (ev, pending) = handle.events.lock().dequeue()?;
    w32(arg, l::EVENT_TYPE, ev.ev_type);
    zero(arg, l::EVENT_U, l::EVENT_U_LEN);
    let span = l::EVENT_U..l::EVENT_U + l::EVENT_U_LEN;
    if arg.len() >= span.end { arg[span].copy_from_slice(&ev.payload); }
    w32(arg, l::EVENT_PENDING, pending);
    w32(arg, l::EVENT_SEQUENCE, ev.sequence);
    w64(arg, l::EVENT_TIMESTAMP_SEC, ev.timestamp_sec);
    w64(arg, l::EVENT_TIMESTAMP_NSEC, ev.timestamp_nsec);
    w32(arg, l::EVENT_ID, ev.id);
    zero(arg, l::EVENT_RESERVED, l::EVENT_RESERVED_LEN);
    Ok(())
}
