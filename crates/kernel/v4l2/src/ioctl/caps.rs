//! `VIDIOC_QUERYCAP` and the priority commands.

use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::device::{FileHandle, VideoDevice};
use crate::uapi::flags;
use crate::uapi::layout as l;
use crate::usermem::{w32, wstr, zero};

/// `VIDIOC_QUERYCAP`: the first command every application sends, and the one
/// that decides whether it will use the device at all.
/// # C: O(1)
pub fn querycap(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::CAPABILITY_SIZE { return Err(Errno::Einval); }
    wstr(arg, l::CAP_DRIVER, l::CAP_DRIVER_LEN, &device.identity.driver);
    wstr(arg, l::CAP_CARD, l::CAP_CARD_LEN, &device.identity.card);
    wstr(arg, l::CAP_BUS_INFO, l::CAP_BUS_INFO_LEN, &device.identity.bus_info);
    w32(arg, l::CAP_VERSION, flags::V4L2_VERSION);
    w32(arg, l::CAP_CAPABILITIES, device.capabilities());
    w32(arg, l::CAP_DEVICE_CAPS, device.device_caps);
    zero(arg, l::CAP_RESERVED, l::CAP_RESERVED_LEN);
    Ok(())
}

/// `VIDIOC_G_PRIORITY`. # C: O(1)
pub fn g_priority(handle: &Arc<FileHandle>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < 4 { return Err(Errno::Einval); }
    w32(arg, 0, handle.priority());
    Ok(())
}

/// `VIDIOC_S_PRIORITY`. A level outside the enumeration is `EINVAL`; the
/// unset level is not settable, since it exists only to describe a device no
/// handle has claimed.
/// # C: O(1)
pub fn s_priority(handle: &Arc<FileHandle>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < 4 { return Err(Errno::Einval); }
    let prio = crate::usermem::r32(arg, 0);
    if prio == flags::PRIORITY_UNSET || prio > flags::PRIORITY_RECORD {
        return Err(Errno::Einval);
    }
    handle.set_priority(prio)
}
