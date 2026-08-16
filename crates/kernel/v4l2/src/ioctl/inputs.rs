//! Input enumeration and selection.

use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::device::VideoDevice;
use crate::uapi::layout as l;
use crate::usermem::{r32, w32, w64, wstr, zero};

/// `VIDIOC_ENUMINPUT`. Walking past the last input is `EINVAL`, which ends the
/// enumeration a program does before it will open a stream.
/// # C: O(1)
pub fn enuminput(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::INPUT_SIZE { return Err(Errno::Einval); }
    let index = r32(arg, l::INPUT_INDEX) as usize;
    let input = device.ops.inputs().get(index).ok_or(Errno::Einval)?;
    wstr(arg, l::INPUT_NAME, l::INPUT_NAME_LEN, input.name);
    w32(arg, l::INPUT_TYPE, input.input_type);
    w32(arg, l::INPUT_AUDIOSET, 0);
    w32(arg, l::INPUT_TUNER, 0);
    // A camera belongs to no analogue video standard, and the zero set is how
    // that is stated.
    w64(arg, l::INPUT_STD, 0);
    w32(arg, l::INPUT_STATUS, input.status);
    w32(arg, l::INPUT_CAPABILITIES, input.capabilities);
    zero(arg, l::INPUT_RESERVED, l::INPUT_RESERVED_LEN);
    Ok(())
}

/// `VIDIOC_G_INPUT`. # C: O(1)
pub fn g_input(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < 4 { return Err(Errno::Einval); }
    w32(arg, 0, device.state.lock().input);
    Ok(())
}

/// `VIDIOC_S_INPUT`.
///
/// Refused while buffers are allocated: a different input can have a different
/// sensor and so a different format, and switching it under a sized pool would
/// have the device write frames that do not fit.
/// # C: O(1)
pub fn s_input(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < 4 { return Err(Errno::Einval); }
    let index = r32(arg, 0);
    if index as usize >= device.ops.inputs().len() { return Err(Errno::Einval); }
    {
        let state = device.state.lock();
        if state.queue.is_busy() { return Err(Errno::Ebusy); }
    }
    device.ops.set_input(index)?;
    device.state.lock().input = index;
    w32(arg, 0, index);
    Ok(())
}
