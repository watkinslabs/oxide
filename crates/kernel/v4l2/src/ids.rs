//! Device-number and inode identity owned by the video device core.

/// `VIDEO_MAJOR`: every `/dev/video*`, `/dev/vbi*`, `/dev/radio*`,
/// `/dev/v4l-subdev*` and `/dev/media*` node shares this major.
pub const VIDEO_MAJOR: u32 = 81;

/// The devtmpfs / sysfs class name a V4L2 node is published under.
pub const CLASS_NAME: &str = "video4linux";

/// First minor of the `videoN` range, and how many minors it spans.
pub const VIDEO_MINOR_BASE: u32 = 0;
pub const VIDEO_MINOR_COUNT: u32 = 64;
/// `vbiN`.
pub const VBI_MINOR_BASE: u32 = 224;
pub const VBI_MINOR_COUNT: u32 = 32;
/// `radioN`.
pub const RADIO_MINOR_BASE: u32 = 64;
pub const RADIO_MINOR_COUNT: u32 = 64;
/// `v4l-subdevN`.
pub const SUBDEV_MINOR_BASE: u32 = 128;
pub const SUBDEV_MINOR_COUNT: u32 = 32;

/// How many video devices this core will register at once.
pub const MAX_VIDEO_DEVICES: u32 = VIDEO_MINOR_COUNT;

/// High bits every V4L2 inode number carries so devfs numbers stay disjoint
/// from every other subsystem's.
pub const INO_TAG: u64 = 0x2600_0000;
