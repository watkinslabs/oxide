//! Format enumeration and negotiation, frame sizes and intervals, streaming
//! parameters, cropping and selection.

use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::device::VideoDevice;
use crate::format::{self, Fract, PixFormat};
use crate::uapi::flags;
use crate::uapi::layout as l;
use crate::usermem::{r32, w32, wstr, zero};

/// Does this device serve `buf_type`?
///
/// The reference answers `EINVAL` — never `ENOTTY` — for a buffer type the
/// device does not have, because an application enumerates types by trying
/// them and needs the two answers to mean different things.
/// # C: O(1)
fn check_type(device: &Arc<VideoDevice>, buf_type: u32) -> Result<(), Errno> {
    let queue_type = device.state.lock().queue.buf_type;
    if buf_type != queue_type { return Err(Errno::Einval); }
    Ok(())
}

/// Read the pixel-format arm of a `v4l2_format` out of the caller's buffer.
/// # C: O(1)
fn read_pix(arg: &[u8]) -> PixFormat {
    let base = l::FORMAT_FMT;
    PixFormat {
        width: r32(arg, base + l::PIX_WIDTH),
        height: r32(arg, base + l::PIX_HEIGHT),
        pixelformat: r32(arg, base + l::PIX_PIXELFORMAT),
        field: r32(arg, base + l::PIX_FIELD),
        bytesperline: r32(arg, base + l::PIX_BYTESPERLINE),
        sizeimage: r32(arg, base + l::PIX_SIZEIMAGE),
        colorspace: r32(arg, base + l::PIX_COLORSPACE),
        flags: r32(arg, base + l::PIX_FLAGS),
        enc: r32(arg, base + l::PIX_ENC),
        quantization: r32(arg, base + l::PIX_QUANTIZATION),
        xfer_func: r32(arg, base + l::PIX_XFER_FUNC),
    }
}

/// Write the pixel-format arm back, clearing the rest of the union.
///
/// Zeroing the tail is not tidiness: the union is 200 bytes and a caller that
/// filled only part of it must not read another format's leftovers back out of
/// the bytes this device did not write.
/// # C: O(1)
fn write_pix(arg: &mut [u8], f: &PixFormat) {
    let base = l::FORMAT_FMT;
    zero(arg, base, l::FORMAT_FMT_LEN);
    w32(arg, base + l::PIX_WIDTH, f.width);
    w32(arg, base + l::PIX_HEIGHT, f.height);
    w32(arg, base + l::PIX_PIXELFORMAT, f.pixelformat);
    w32(arg, base + l::PIX_FIELD, f.field);
    w32(arg, base + l::PIX_BYTESPERLINE, f.bytesperline);
    w32(arg, base + l::PIX_SIZEIMAGE, f.sizeimage);
    w32(arg, base + l::PIX_COLORSPACE, f.colorspace);
    w32(arg, base + l::PIX_FLAGS, f.flags);
    w32(arg, base + l::PIX_ENC, f.enc);
    w32(arg, base + l::PIX_QUANTIZATION, f.quantization);
    w32(arg, base + l::PIX_XFER_FUNC, f.xfer_func);
}

/// `VIDIOC_ENUM_FMT`. Walking past the last format is `EINVAL`, which is what
/// ends an application's enumeration loop. # C: O(1)
pub fn enum_fmt(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::FMTDESC_SIZE { return Err(Errno::Einval); }
    check_type(device, r32(arg, l::FMTDESC_TYPE))?;
    let index = r32(arg, l::FMTDESC_INDEX) as usize;
    let table = device.ops.formats();
    let desc = table.get(index).ok_or(Errno::Einval)?;
    w32(arg, l::FMTDESC_FLAGS, desc.flags);
    wstr(arg, l::FMTDESC_DESCRIPTION, l::FMTDESC_DESCRIPTION_LEN, desc.description);
    w32(arg, l::FMTDESC_PIXELFORMAT, desc.pixelformat);
    w32(arg, l::FMTDESC_MBUS_CODE, 0);
    zero(arg, l::FMTDESC_RESERVED, l::FMTDESC_RESERVED_LEN);
    Ok(())
}

/// `VIDIOC_G_FMT`. # C: O(1)
pub fn g_fmt(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::FORMAT_SIZE { return Err(Errno::Einval); }
    check_type(device, r32(arg, l::FORMAT_TYPE))?;
    let current = device.state.lock().format;
    write_pix(arg, &current);
    Ok(())
}

/// `VIDIOC_TRY_FMT`: negotiate without installing. # C: O(formats)
pub fn try_fmt(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::FORMAT_SIZE { return Err(Errno::Einval); }
    check_type(device, r32(arg, l::FORMAT_TYPE))?;
    let mut want = read_pix(arg);
    if !format::try_fmt(device.ops.formats(), &mut want, device.ops.progressive()) {
        return Err(Errno::Einval);
    }
    write_pix(arg, &want);
    Ok(())
}

/// `VIDIOC_S_FMT`.
///
/// Refused while buffers exist: the buffers were sized for the old format, and
/// a device that changed format under them would write frames that do not fit.
/// The reference leaves this check to the driver; it lives here because the
/// core owns the queue, and a driver-by-driver copy of it is exactly the split
/// source of truth that lets one device forget it.
/// # C: O(formats)
pub fn s_fmt(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::FORMAT_SIZE { return Err(Errno::Einval); }
    check_type(device, r32(arg, l::FORMAT_TYPE))?;
    let mut want = read_pix(arg);
    if !format::try_fmt(device.ops.formats(), &mut want, device.ops.progressive()) {
        return Err(Errno::Einval);
    }
    {
        let mut state = device.state.lock();
        if state.queue.is_busy() { return Err(Errno::Ebusy); }
        state.format = want;
    }
    device.ops.set_format(&want);
    write_pix(arg, &want);
    Ok(())
}

/// `VIDIOC_ENUM_FRAMESIZES`. # C: O(formats)
pub fn enum_framesizes(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::FRMSIZEENUM_SIZE { return Err(Errno::Einval); }
    let pixelformat = r32(arg, l::FRMSIZE_PIXEL_FORMAT);
    let index = r32(arg, l::FRMSIZE_INDEX) as usize;
    let desc = device.ops.formats().iter().find(|d| d.pixelformat == pixelformat)
        .ok_or(Errno::Einval)?;
    let size = desc.sizes.get(index).ok_or(Errno::Einval)?;
    w32(arg, l::FRMSIZE_TYPE, flags::FRMSIZE_TYPE_DISCRETE);
    w32(arg, l::FRMSIZE_DISCRETE_WIDTH, size.width);
    w32(arg, l::FRMSIZE_DISCRETE_HEIGHT, size.height);
    zero(arg, l::FRMSIZE_RESERVED, l::FRMSIZE_RESERVED_LEN);
    Ok(())
}

/// `VIDIOC_ENUM_FRAMEINTERVALS`. The size must be one the format actually
/// offers: intervals are per size on real hardware, and answering for a size
/// the device cannot produce would have an application pace against a frame
/// rate it will never see.
/// # C: O(formats * sizes)
pub fn enum_frameintervals(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::FRMIVALENUM_SIZE { return Err(Errno::Einval); }
    let pixelformat = r32(arg, l::FRMIVAL_PIXEL_FORMAT);
    let width = r32(arg, l::FRMIVAL_WIDTH);
    let height = r32(arg, l::FRMIVAL_HEIGHT);
    let index = r32(arg, l::FRMIVAL_INDEX) as usize;
    let desc = device.ops.formats().iter().find(|d| d.pixelformat == pixelformat)
        .ok_or(Errno::Einval)?;
    if !desc.sizes.iter().any(|s| s.width == width && s.height == height) {
        return Err(Errno::Einval);
    }
    let interval = desc.intervals.get(index).ok_or(Errno::Einval)?;
    w32(arg, l::FRMIVAL_TYPE, flags::FRMIVAL_TYPE_DISCRETE);
    w32(arg, l::FRMIVAL_DISCRETE_NUM, interval.numerator);
    w32(arg, l::FRMIVAL_DISCRETE_DEN, interval.denominator);
    zero(arg, l::FRMIVAL_RESERVED, l::FRMIVAL_RESERVED_LEN);
    Ok(())
}

fn write_captureparm(arg: &mut [u8], interval: Fract, readbuffers: u32) {
    let base = l::STREAMPARM_PARM;
    zero(arg, base, l::STREAMPARM_PARM_LEN);
    w32(arg, base + l::CAPTUREPARM_CAPABILITY, flags::CAP_TIMEPERFRAME);
    w32(arg, base + l::CAPTUREPARM_CAPTUREMODE, 0);
    w32(arg, base + l::CAPTUREPARM_TIMEPERFRAME_NUM, interval.numerator);
    w32(arg, base + l::CAPTUREPARM_TIMEPERFRAME_DEN, interval.denominator);
    w32(arg, base + l::CAPTUREPARM_EXTENDEDMODE, 0);
    w32(arg, base + l::CAPTUREPARM_READBUFFERS, readbuffers);
}

/// `VIDIOC_G_PARM`. # C: O(1)
pub fn g_parm(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::STREAMPARM_SIZE { return Err(Errno::Einval); }
    check_type(device, r32(arg, l::STREAMPARM_TYPE))?;
    let interval = device.state.lock().interval;
    write_captureparm(arg, interval, crate::vb2::MAX_BUFFERS.min(4));
    Ok(())
}

/// `VIDIOC_S_PARM`: request a frame interval, and be told the one that will
/// actually be used. A zero denominator means "whatever you prefer", which is
/// how an application asks for the default rate without knowing it.
/// # C: O(intervals)
pub fn s_parm(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::STREAMPARM_SIZE { return Err(Errno::Einval); }
    check_type(device, r32(arg, l::STREAMPARM_TYPE))?;
    let base = l::STREAMPARM_PARM;
    let want = Fract {
        numerator: r32(arg, base + l::CAPTUREPARM_TIMEPERFRAME_NUM),
        denominator: r32(arg, base + l::CAPTUREPARM_TIMEPERFRAME_DEN),
    };
    let pixelformat = device.state.lock().format.pixelformat;
    let intervals = device.ops.formats().iter()
        .find(|d| d.pixelformat == pixelformat)
        .map(|d| d.intervals)
        .unwrap_or(&[]);
    let settled = format::clamp_interval(intervals, want).ok_or(Errno::Einval)?;
    device.state.lock().interval = settled;
    device.ops.set_interval(settled);
    write_captureparm(arg, settled, crate::vb2::MAX_BUFFERS.min(4));
    Ok(())
}

/// `VIDIOC_CROPCAP`: the frame's bounds and its pixel aspect. A sensor that
/// cannot crop still answers, because an application reads the pixel aspect
/// from here to display the image undistorted.
/// # C: O(1)
pub fn cropcap(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::CROPCAP_SIZE { return Err(Errno::Einval); }
    check_type(device, r32(arg, l::CROPCAP_TYPE))?;
    let f = device.state.lock().format;
    w32(arg, l::CROPCAP_BOUNDS_LEFT, 0);
    w32(arg, l::CROPCAP_BOUNDS_TOP, 0);
    w32(arg, l::CROPCAP_BOUNDS_WIDTH, f.width);
    w32(arg, l::CROPCAP_BOUNDS_HEIGHT, f.height);
    w32(arg, l::CROPCAP_DEFRECT_LEFT, 0);
    w32(arg, l::CROPCAP_DEFRECT_TOP, 0);
    w32(arg, l::CROPCAP_DEFRECT_WIDTH, f.width);
    w32(arg, l::CROPCAP_DEFRECT_HEIGHT, f.height);
    w32(arg, l::CROPCAP_PIXELASPECT_NUM, 1);
    w32(arg, l::CROPCAP_PIXELASPECT_DEN, 1);
    Ok(())
}

/// `VIDIOC_G_CROP`: the whole frame, on a device that does not crop.
/// # C: O(1)
pub fn g_crop(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::CROP_SIZE { return Err(Errno::Einval); }
    check_type(device, r32(arg, l::CROP_TYPE))?;
    let f = device.state.lock().format;
    w32(arg, l::CROP_C_LEFT, 0);
    w32(arg, l::CROP_C_TOP, 0);
    w32(arg, l::CROP_C_WIDTH, f.width);
    w32(arg, l::CROP_C_HEIGHT, f.height);
    Ok(())
}

/// `VIDIOC_S_CROP` on a device with a fixed frame. Setting the full frame is
/// the identity and succeeds; asking for anything else is `EINVAL`, so an
/// application learns the device cannot crop rather than believing a request
/// that was quietly ignored.
/// # C: O(1)
pub fn s_crop(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::CROP_SIZE { return Err(Errno::Einval); }
    check_type(device, r32(arg, l::CROP_TYPE))?;
    let f = device.state.lock().format;
    let matches_frame = r32(arg, l::CROP_C_LEFT) == 0 && r32(arg, l::CROP_C_TOP) == 0
        && r32(arg, l::CROP_C_WIDTH) == f.width && r32(arg, l::CROP_C_HEIGHT) == f.height;
    if matches_frame { Ok(()) } else { Err(Errno::Einval) }
}

/// `VIDIOC_G_SELECTION`. # C: O(1)
pub fn g_selection(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::SELECTION_SIZE { return Err(Errno::Einval); }
    check_type(device, r32(arg, l::SEL_TYPE))?;
    let target = r32(arg, l::SEL_TARGET);
    match target {
        flags::SEL_TGT_CROP | flags::SEL_TGT_CROP_DEFAULT | flags::SEL_TGT_CROP_BOUNDS
        | flags::SEL_TGT_NATIVE_SIZE => {}
        _ => return Err(Errno::Einval),
    }
    let f = device.state.lock().format;
    w32(arg, l::SEL_R_LEFT, 0);
    w32(arg, l::SEL_R_TOP, 0);
    w32(arg, l::SEL_R_WIDTH, f.width);
    w32(arg, l::SEL_R_HEIGHT, f.height);
    zero(arg, l::SEL_RESERVED, l::SEL_RESERVED_LEN);
    Ok(())
}

/// `VIDIOC_S_SELECTION` on a fixed-frame device: only the crop target is
/// settable, and only to the whole frame. # C: O(1)
pub fn s_selection(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::SELECTION_SIZE { return Err(Errno::Einval); }
    check_type(device, r32(arg, l::SEL_TYPE))?;
    if r32(arg, l::SEL_TARGET) != flags::SEL_TGT_CROP { return Err(Errno::Einval); }
    let f = device.state.lock().format;
    w32(arg, l::SEL_R_LEFT, 0);
    w32(arg, l::SEL_R_TOP, 0);
    w32(arg, l::SEL_R_WIDTH, f.width);
    w32(arg, l::SEL_R_HEIGHT, f.height);
    zero(arg, l::SEL_RESERVED, l::SEL_RESERVED_LEN);
    Ok(())
}
