//! The `/dev/videoN` node — the only part of this crate that touches the
//! kernel, and the only part a hosted test cannot reach.
//!
//! Module manifest:
//! - `frames`: plane memory, as refcounted kernel RAM pages.
//! - `ctx`: the clock, the blocking wait, the caller's memory, the wake.
//! - `publish`: node publication through the driver model, and the wait list.
//! - `fileops`: the file operations and the ioctl entry point.
//!
//! Every decision this layer would otherwise make lives above it, ungated, so
//! it can be tested. What is left here is copying, sleeping and registering.

pub mod frames;
pub mod ctx;
pub mod publish;
pub mod fileops;

use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::device::{self, Registration, VideoDevice};

pub use fileops::handle_ioctl;
pub use frames::{fill_plane, read_plane, write_plane, FrameAlloc};

/// Register a video device and publish its node in one step, which is what a
/// driver actually wants: a device with no node is invisible, and a node with
/// no device answers nothing.
/// # C: O(devices)
pub fn register_and_publish(reg: Registration) -> Result<Arc<VideoDevice>, Errno> {
    let device = device::register(reg)?;
    match publish::publish(&device) {
        Ok(()) => Ok(device),
        Err(e) => { device::unregister(&device); Err(e) }
    }
}

/// Withdraw a device's node and unregister it. # C: O(devices)
pub fn unpublish(device: &Arc<VideoDevice>) {
    publish::withdraw(device.index);
    device::unregister(device);
}

/// Report one completed buffer and wake everything waiting for it. This is the
/// call a driver makes from its frame path.
/// # C: O(planes)
pub fn buffer_done(device: &Arc<VideoDevice>, completion: &crate::vb2::Completion) -> bool {
    let landed = {
        let mut state = device.state.lock();
        crate::vb2::stream::buffer_done(&mut state.queue, completion)
    };
    if landed { publish::wake(device); }
    landed
}
