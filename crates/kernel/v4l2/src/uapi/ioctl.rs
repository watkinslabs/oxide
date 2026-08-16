//! `VIDIOC_*` command numbers, fully expanded for the LP64 ABI.
//!
//! Every value here is the `_IOC` encoding a userspace program actually sends:
//! direction in bits 30-31, argument size in bits 16-29, the `'V'` type byte in
//! bits 8-15 and the command ordinal in bits 0-7. They are written expanded
//! rather than recomputed so a struct whose size drifts breaks the size
//! assertions in `layout` instead of silently renumbering a command.

/// `'V'`, the type byte every V4L2 command carries.
pub const V4L2_IOC_TYPE: u64 = 0x56;

pub const VIDIOC_QUERYCAP: u64 = 0x8068_5600;
pub const VIDIOC_ENUM_FMT: u64 = 0xc040_5602;
pub const VIDIOC_G_FMT: u64 = 0xc0d0_5604;
pub const VIDIOC_S_FMT: u64 = 0xc0d0_5605;
pub const VIDIOC_REQBUFS: u64 = 0xc014_5608;
pub const VIDIOC_QUERYBUF: u64 = 0xc058_5609;
pub const VIDIOC_QBUF: u64 = 0xc058_560f;
pub const VIDIOC_EXPBUF: u64 = 0xc040_5610;
pub const VIDIOC_DQBUF: u64 = 0xc058_5611;
pub const VIDIOC_STREAMON: u64 = 0x4004_5612;
pub const VIDIOC_STREAMOFF: u64 = 0x4004_5613;
pub const VIDIOC_G_PARM: u64 = 0xc0cc_5615;
pub const VIDIOC_S_PARM: u64 = 0xc0cc_5616;
pub const VIDIOC_G_STD: u64 = 0x8008_5617;
pub const VIDIOC_S_STD: u64 = 0x4008_5618;
pub const VIDIOC_ENUMSTD: u64 = 0xc048_5619;
pub const VIDIOC_ENUMINPUT: u64 = 0xc050_561a;
pub const VIDIOC_G_CTRL: u64 = 0xc008_561b;
pub const VIDIOC_S_CTRL: u64 = 0xc008_561c;
pub const VIDIOC_QUERYCTRL: u64 = 0xc044_5624;
pub const VIDIOC_QUERYMENU: u64 = 0xc02c_5625;
pub const VIDIOC_G_INPUT: u64 = 0x8004_5626;
pub const VIDIOC_S_INPUT: u64 = 0xc004_5627;
pub const VIDIOC_CROPCAP: u64 = 0xc02c_563a;
pub const VIDIOC_G_CROP: u64 = 0xc014_563b;
pub const VIDIOC_S_CROP: u64 = 0x4014_563c;
pub const VIDIOC_QUERYSTD: u64 = 0x8008_563f;
pub const VIDIOC_TRY_FMT: u64 = 0xc0d0_5640;
pub const VIDIOC_G_PRIORITY: u64 = 0x8004_5643;
pub const VIDIOC_S_PRIORITY: u64 = 0x4004_5644;
pub const VIDIOC_LOG_STATUS: u64 = 0x0000_5646;
pub const VIDIOC_G_EXT_CTRLS: u64 = 0xc020_5647;
pub const VIDIOC_S_EXT_CTRLS: u64 = 0xc020_5648;
pub const VIDIOC_TRY_EXT_CTRLS: u64 = 0xc020_5649;
pub const VIDIOC_ENUM_FRAMESIZES: u64 = 0xc02c_564a;
pub const VIDIOC_ENUM_FRAMEINTERVALS: u64 = 0xc034_564b;
pub const VIDIOC_DQEVENT: u64 = 0x8088_5659;
pub const VIDIOC_SUBSCRIBE_EVENT: u64 = 0x4020_565a;
pub const VIDIOC_UNSUBSCRIBE_EVENT: u64 = 0x4020_565b;
pub const VIDIOC_CREATE_BUFS: u64 = 0xc100_565c;
pub const VIDIOC_PREPARE_BUF: u64 = 0xc058_565d;
pub const VIDIOC_G_SELECTION: u64 = 0xc040_565e;
pub const VIDIOC_S_SELECTION: u64 = 0xc040_565f;
pub const VIDIOC_QUERY_EXT_CTRL: u64 = 0xc0e8_5667;
pub const VIDIOC_REMOVE_BUFS: u64 = 0xc014_5668;

/// Direction bits of an `_IOC` encoding.
pub const IOC_DIRSHIFT: u32 = 30;
/// Argument-size field position.
pub const IOC_SIZESHIFT: u32 = 16;
/// Argument-size field width mask (14 bits).
pub const IOC_SIZEMASK: u64 = 0x3fff;
/// Type-byte field position.
pub const IOC_TYPESHIFT: u32 = 8;
/// Command-ordinal field mask.
pub const IOC_NRMASK: u64 = 0xff;
/// `_IOC_READ`: the command copies OUT to the caller.
pub const IOC_READ: u64 = 2;
/// `_IOC_WRITE`: the command copies IN from the caller.
pub const IOC_WRITE: u64 = 1;

/// Type byte of an encoded command. # C: O(1)
pub fn ioc_type(cmd: u64) -> u64 { (cmd >> IOC_TYPESHIFT) & IOC_NRMASK }
/// Command ordinal within its type. # C: O(1)
pub fn ioc_nr(cmd: u64) -> u64 { cmd & IOC_NRMASK }
/// Declared argument size in bytes. # C: O(1)
pub fn ioc_size(cmd: u64) -> usize { ((cmd >> IOC_SIZESHIFT) & IOC_SIZEMASK) as usize }
/// Direction bits: `IOC_READ` copies out, `IOC_WRITE` copies in. # C: O(1)
pub fn ioc_dir(cmd: u64) -> u64 { (cmd >> IOC_DIRSHIFT) & 0x3 }
/// Is this command addressed to the V4L2 type byte? # C: O(1)
pub fn is_v4l2(cmd: u64) -> bool { ioc_type(cmd) == V4L2_IOC_TYPE }
