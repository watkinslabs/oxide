//! The V4L2 numbers this probe sends, written out rather than derived.
//!
//! A probe that computed its own ioctl encodings from the kernel's own
//! constants would agree with the kernel by construction and prove nothing.
//! These are the values a program built against the system headers sends.

/// `VIDIOC_QUERYCAP`, `_IOR('V', 0, struct v4l2_capability)`.
pub const VIDIOC_QUERYCAP: libc::c_ulong = 0x8068_5600;
/// `VIDIOC_ENUM_FMT`, `_IOWR('V', 2, struct v4l2_fmtdesc)`.
pub const VIDIOC_ENUM_FMT: libc::c_ulong = 0xc040_5602;
/// `VIDIOC_G_FMT`, `_IOWR('V', 4, struct v4l2_format)`.
pub const VIDIOC_G_FMT: libc::c_ulong = 0xc0d0_5604;
/// `VIDIOC_S_FMT`, `_IOWR('V', 5, struct v4l2_format)`.
pub const VIDIOC_S_FMT: libc::c_ulong = 0xc0d0_5605;
/// `VIDIOC_REQBUFS`, `_IOWR('V', 8, struct v4l2_requestbuffers)`.
pub const VIDIOC_REQBUFS: libc::c_ulong = 0xc014_5608;
/// `VIDIOC_QUERYBUF`, `_IOWR('V', 9, struct v4l2_buffer)`.
pub const VIDIOC_QUERYBUF: libc::c_ulong = 0xc058_5609;
/// `VIDIOC_QBUF`, `_IOWR('V', 15, struct v4l2_buffer)`.
pub const VIDIOC_QBUF: libc::c_ulong = 0xc058_560f;
/// `VIDIOC_DQBUF`, `_IOWR('V', 17, struct v4l2_buffer)`.
pub const VIDIOC_DQBUF: libc::c_ulong = 0xc058_5611;
/// `VIDIOC_STREAMON`, `_IOW('V', 18, int)`.
pub const VIDIOC_STREAMON: libc::c_ulong = 0x4004_5612;
/// `VIDIOC_STREAMOFF`, `_IOW('V', 19, int)`.
pub const VIDIOC_STREAMOFF: libc::c_ulong = 0x4004_5613;
/// `VIDIOC_ENUMINPUT`, `_IOWR('V', 26, struct v4l2_input)`.
pub const VIDIOC_ENUMINPUT: libc::c_ulong = 0xc050_561a;
/// `VIDIOC_G_CTRL`, `_IOWR('V', 27, struct v4l2_control)`.
pub const VIDIOC_G_CTRL: libc::c_ulong = 0xc008_561b;
/// `VIDIOC_S_CTRL`, `_IOWR('V', 28, struct v4l2_control)`.
pub const VIDIOC_S_CTRL: libc::c_ulong = 0xc008_561c;
/// `VIDIOC_QUERYCTRL`, `_IOWR('V', 36, struct v4l2_queryctrl)`.
pub const VIDIOC_QUERYCTRL: libc::c_ulong = 0xc044_5624;

pub const V4L2_BUF_TYPE_VIDEO_CAPTURE: u32 = 1;
pub const V4L2_MEMORY_MMAP: u32 = 1;
pub const V4L2_CAP_VIDEO_CAPTURE: u32 = 0x0000_0001;
pub const V4L2_CAP_STREAMING: u32 = 0x0400_0000;
pub const V4L2_CAP_DEVICE_CAPS: u32 = 0x8000_0000;
pub const V4L2_BUF_FLAG_DONE: u32 = 0x0000_0004;
pub const V4L2_BUF_FLAG_ERROR: u32 = 0x0000_0040;
pub const V4L2_CID_BRIGHTNESS: u32 = 0x0098_0900;
pub const V4L2_CTRL_FLAG_NEXT_CTRL: u32 = 0x8000_0000;

pub const CAPABILITY_SIZE: usize = 104;
pub const FMTDESC_SIZE: usize = 64;
pub const FORMAT_SIZE: usize = 208;
pub const REQUESTBUFFERS_SIZE: usize = 20;
pub const BUFFER_SIZE: usize = 88;
pub const INPUT_SIZE: usize = 80;
pub const CONTROL_SIZE: usize = 8;
pub const QUERYCTRL_SIZE: usize = 68;

/// Read a little-endian `u32` out of a structure buffer. # C: O(1)
pub fn r32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
/// Read a little-endian `u64`. # C: O(1)
pub fn r64(b: &[u8], off: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(v)
}
/// Write a little-endian `u32`. # C: O(1)
pub fn w32(b: &mut [u8], off: usize, v: u32) { b[off..off + 4].copy_from_slice(&v.to_le_bytes()); }
/// Read a NUL-terminated name out of a fixed-width field. # C: O(cap)
pub fn name(b: &[u8], off: usize, cap: usize) -> String {
    let field = &b[off..off + cap];
    let end = field.iter().position(|c| *c == 0).unwrap_or(cap);
    String::from_utf8_lossy(&field[..end]).into_owned()
}
