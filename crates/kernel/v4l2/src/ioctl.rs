//! The command surface: one entry point, one ordered set of checks, one
//! handler per command.
//!
//! Module manifest:
//! - `caps`: `QUERYCAP`, priority, `LOG_STATUS`.
//! - `fmt`: format enumeration and negotiation, frame sizes and intervals,
//!   streaming parameters, cropping and selection.
//! - `bufs`: the whole buffer-queue command set.
//! - `ctrls`: controls, plain and extended.
//! - `inputs`: inputs and video standards.
//! - `events`: event subscription and dequeue.
//!
//! Every handler takes the caller's argument as bytes and writes its answer
//! back into the same bytes — the reference's copy-in, work, copy-out shape.
//! No handler touches user memory directly except through [`Ctx`], which is
//! why the whole surface is exercised by hosted tests.

pub mod caps;
pub mod fmt;
pub mod bufs;
pub mod ctrls;
pub mod inputs;
pub mod events;

use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::device::{FileHandle, VideoDevice};
use crate::uapi::ioctl::*;
use crate::usermem::UserMem;

/// What a handler needs from the world outside the device core.
pub trait Ctx {
    /// Monotonic time as `(seconds, nanoseconds)`, for event and buffer
    /// timestamps. # C: O(1)
    fn now(&self) -> (u64, u64);
    /// Was the file opened with `O_NONBLOCK`? # C: O(1)
    fn nonblocking(&self) -> bool;
    /// Sleep until a buffer reaches the done list or the wait is interrupted.
    /// # C: O(1)
    fn wait_for_buffer(&self, device: &Arc<VideoDevice>) -> Result<(), Errno>;
    /// The calling process's memory, for the pointers an argument embeds.
    /// # C: O(1)
    fn user(&self) -> &dyn UserMem;
    /// Wake everything watching this device after a command changed its
    /// readiness. # C: O(handles)
    fn wake(&self, device: &Arc<VideoDevice>) { let _ = device; }
}

/// Is this a command the device core implements?
///
/// A V4L2-typed command that is not on this list is `ENOTTY`, the same answer
/// a non-V4L2 command gets, because an application probing for a feature must
/// not be able to tell "this kernel does not implement it" from "this device
/// does not have it".
/// # C: O(1)
pub fn is_known(cmd: u64) -> bool {
    matches!(cmd,
        VIDIOC_QUERYCAP | VIDIOC_LOG_STATUS | VIDIOC_G_PRIORITY | VIDIOC_S_PRIORITY
        | VIDIOC_ENUM_FMT | VIDIOC_G_FMT | VIDIOC_S_FMT | VIDIOC_TRY_FMT
        | VIDIOC_ENUM_FRAMESIZES | VIDIOC_ENUM_FRAMEINTERVALS
        | VIDIOC_G_PARM | VIDIOC_S_PARM
        | VIDIOC_CROPCAP | VIDIOC_G_CROP | VIDIOC_S_CROP
        | VIDIOC_G_SELECTION | VIDIOC_S_SELECTION
        | VIDIOC_REQBUFS | VIDIOC_CREATE_BUFS | VIDIOC_QUERYBUF | VIDIOC_QBUF
        | VIDIOC_DQBUF | VIDIOC_PREPARE_BUF | VIDIOC_EXPBUF | VIDIOC_REMOVE_BUFS
        | VIDIOC_STREAMON | VIDIOC_STREAMOFF
        | VIDIOC_ENUMINPUT | VIDIOC_G_INPUT | VIDIOC_S_INPUT
        | VIDIOC_ENUMSTD | VIDIOC_G_STD | VIDIOC_S_STD | VIDIOC_QUERYSTD
        | VIDIOC_G_CTRL | VIDIOC_S_CTRL | VIDIOC_QUERYCTRL | VIDIOC_QUERYMENU
        | VIDIOC_QUERY_EXT_CTRL
        | VIDIOC_G_EXT_CTRLS | VIDIOC_S_EXT_CTRLS | VIDIOC_TRY_EXT_CTRLS
        | VIDIOC_SUBSCRIBE_EVENT | VIDIOC_UNSUBSCRIBE_EVENT | VIDIOC_DQEVENT)
}

/// Run one command against `handle`.
///
/// The order of the checks is the contract, not an implementation detail. A
/// gone device answers before an unknown command, an unknown command before a
/// priority conflict, and a priority conflict before anything the driver could
/// observe — so a program that lost the device, a program built against a
/// newer kernel, and a program outranked by a recorder each get the answer
/// that tells them which of those happened.
/// # C: per command
pub fn dispatch(handle: &Arc<FileHandle>, cmd: u64, arg: &mut [u8], ctx: &dyn Ctx)
    -> Result<(), Errno>
{
    let device = handle.device.clone();
    if !device.registered() { return Err(Errno::Enodev); }
    if !is_known(cmd) { return Err(Errno::Enotty); }
    if crate::prio::needs_prio(cmd) { device.prio.check(handle.priority())?; }
    match cmd {
        VIDIOC_QUERYCAP => caps::querycap(&device, arg),
        VIDIOC_LOG_STATUS => Ok(()),
        VIDIOC_G_PRIORITY => caps::g_priority(handle, arg),
        VIDIOC_S_PRIORITY => caps::s_priority(handle, arg),

        VIDIOC_ENUM_FMT => fmt::enum_fmt(&device, arg),
        VIDIOC_G_FMT => fmt::g_fmt(&device, arg),
        VIDIOC_S_FMT => fmt::s_fmt(&device, arg),
        VIDIOC_TRY_FMT => fmt::try_fmt(&device, arg),
        VIDIOC_ENUM_FRAMESIZES => fmt::enum_framesizes(&device, arg),
        VIDIOC_ENUM_FRAMEINTERVALS => fmt::enum_frameintervals(&device, arg),
        VIDIOC_G_PARM => fmt::g_parm(&device, arg),
        VIDIOC_S_PARM => fmt::s_parm(&device, arg),
        VIDIOC_CROPCAP => fmt::cropcap(&device, arg),
        VIDIOC_G_CROP => fmt::g_crop(&device, arg),
        VIDIOC_S_CROP => fmt::s_crop(&device, arg),
        VIDIOC_G_SELECTION => fmt::g_selection(&device, arg),
        VIDIOC_S_SELECTION => fmt::s_selection(&device, arg),

        VIDIOC_REQBUFS => bufs::reqbufs(handle, arg),
        VIDIOC_CREATE_BUFS => bufs::create_bufs(handle, arg),
        VIDIOC_QUERYBUF => bufs::querybuf(handle, arg, ctx),
        VIDIOC_QBUF => bufs::qbuf(handle, arg, ctx),
        VIDIOC_DQBUF => bufs::dqbuf(handle, arg, ctx),
        VIDIOC_PREPARE_BUF => bufs::prepare_buf(handle, arg, ctx),
        VIDIOC_EXPBUF => bufs::expbuf(handle, arg),
        VIDIOC_REMOVE_BUFS => bufs::remove_bufs(handle, arg),
        VIDIOC_STREAMON => bufs::streamon(handle, arg, ctx),
        VIDIOC_STREAMOFF => bufs::streamoff(handle, arg, ctx),

        VIDIOC_ENUMINPUT => inputs::enuminput(&device, arg),
        VIDIOC_G_INPUT => inputs::g_input(&device, arg),
        VIDIOC_S_INPUT => inputs::s_input(&device, arg),
        VIDIOC_ENUMSTD | VIDIOC_G_STD | VIDIOC_S_STD | VIDIOC_QUERYSTD => {
            // A camera has no analogue video standard. The reference answers
            // `ENOTTY` for the standard commands on such a device, which is
            // how an application learns not to offer a standard selector.
            Err(Errno::Enotty)
        }

        VIDIOC_G_CTRL => ctrls::g_ctrl(&device, arg),
        VIDIOC_S_CTRL => ctrls::s_ctrl(handle, arg, ctx),
        VIDIOC_QUERYCTRL => ctrls::queryctrl(&device, arg),
        VIDIOC_QUERY_EXT_CTRL => ctrls::query_ext_ctrl(&device, arg),
        VIDIOC_QUERYMENU => ctrls::querymenu(&device, arg),
        VIDIOC_G_EXT_CTRLS => ctrls::g_ext_ctrls(&device, arg, ctx),
        VIDIOC_S_EXT_CTRLS => ctrls::s_ext_ctrls(handle, arg, ctx),
        VIDIOC_TRY_EXT_CTRLS => ctrls::try_ext_ctrls(&device, arg, ctx),

        VIDIOC_SUBSCRIBE_EVENT => events::subscribe(handle, arg, ctx),
        VIDIOC_UNSUBSCRIBE_EVENT => events::unsubscribe(handle, arg),
        VIDIOC_DQEVENT => events::dqevent(handle, arg),
        _ => Err(Errno::Enotty),
    }
}
