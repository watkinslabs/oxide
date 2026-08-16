//! Enumerations and bit flags of the V4L2 ABI: buffer types, memory models,
//! field orders, capability bits, buffer flags and buffer-queue capabilities.

// ---- v4l2_buf_type -------------------------------------------------------
pub const BUF_TYPE_VIDEO_CAPTURE: u32 = 1;
pub const BUF_TYPE_VIDEO_OUTPUT: u32 = 2;
pub const BUF_TYPE_VIDEO_OVERLAY: u32 = 3;
pub const BUF_TYPE_VBI_CAPTURE: u32 = 4;
pub const BUF_TYPE_VBI_OUTPUT: u32 = 5;
pub const BUF_TYPE_SLICED_VBI_CAPTURE: u32 = 6;
pub const BUF_TYPE_SLICED_VBI_OUTPUT: u32 = 7;
pub const BUF_TYPE_VIDEO_OUTPUT_OVERLAY: u32 = 8;
pub const BUF_TYPE_VIDEO_CAPTURE_MPLANE: u32 = 9;
pub const BUF_TYPE_VIDEO_OUTPUT_MPLANE: u32 = 10;
pub const BUF_TYPE_SDR_CAPTURE: u32 = 11;
pub const BUF_TYPE_SDR_OUTPUT: u32 = 12;
pub const BUF_TYPE_META_CAPTURE: u32 = 13;
pub const BUF_TYPE_META_OUTPUT: u32 = 14;

/// Does this buffer type carry a per-plane array rather than a single plane?
/// # C: O(1)
pub fn is_multiplanar(buf_type: u32) -> bool {
    matches!(buf_type, BUF_TYPE_VIDEO_CAPTURE_MPLANE | BUF_TYPE_VIDEO_OUTPUT_MPLANE)
}

/// Is this buffer type an output (userspace feeds the device)? # C: O(1)
pub fn is_output(buf_type: u32) -> bool {
    matches!(buf_type,
        BUF_TYPE_VIDEO_OUTPUT | BUF_TYPE_VIDEO_OUTPUT_MPLANE | BUF_TYPE_VIDEO_OVERLAY
        | BUF_TYPE_VIDEO_OUTPUT_OVERLAY | BUF_TYPE_VBI_OUTPUT | BUF_TYPE_SLICED_VBI_OUTPUT
        | BUF_TYPE_SDR_OUTPUT | BUF_TYPE_META_OUTPUT)
}

// ---- v4l2_memory ---------------------------------------------------------
pub const MEMORY_MMAP: u32 = 1;
pub const MEMORY_USERPTR: u32 = 2;
pub const MEMORY_OVERLAY: u32 = 3;
pub const MEMORY_DMABUF: u32 = 4;
/// `V4L2_MEMORY_FLAG_NON_COHERENT` in `v4l2_requestbuffers.flags`.
pub const MEMORY_FLAG_NON_COHERENT: u32 = 1 << 0;

// ---- v4l2_field ----------------------------------------------------------
pub const FIELD_ANY: u32 = 0;
pub const FIELD_NONE: u32 = 1;
pub const FIELD_TOP: u32 = 2;
pub const FIELD_BOTTOM: u32 = 3;
pub const FIELD_INTERLACED: u32 = 4;
pub const FIELD_SEQ_TB: u32 = 5;
pub const FIELD_SEQ_BT: u32 = 6;
pub const FIELD_ALTERNATE: u32 = 7;
pub const FIELD_INTERLACED_TB: u32 = 8;
pub const FIELD_INTERLACED_BT: u32 = 9;

// ---- v4l2_capability.capabilities / device_caps --------------------------
pub const CAP_VIDEO_CAPTURE: u32 = 0x0000_0001;
pub const CAP_VIDEO_OUTPUT: u32 = 0x0000_0002;
pub const CAP_VIDEO_OVERLAY: u32 = 0x0000_0004;
pub const CAP_VBI_CAPTURE: u32 = 0x0000_0010;
pub const CAP_VIDEO_CAPTURE_MPLANE: u32 = 0x0000_1000;
pub const CAP_VIDEO_OUTPUT_MPLANE: u32 = 0x0000_2000;
pub const CAP_VIDEO_M2M_MPLANE: u32 = 0x0000_4000;
pub const CAP_VIDEO_M2M: u32 = 0x0000_8000;
pub const CAP_TUNER: u32 = 0x0001_0000;
pub const CAP_AUDIO: u32 = 0x0002_0000;
pub const CAP_RADIO: u32 = 0x0004_0000;
pub const CAP_MODULATOR: u32 = 0x0008_0000;
pub const CAP_SDR_CAPTURE: u32 = 0x0010_0000;
pub const CAP_EXT_PIX_FORMAT: u32 = 0x0020_0000;
pub const CAP_SDR_OUTPUT: u32 = 0x0040_0000;
pub const CAP_META_CAPTURE: u32 = 0x0080_0000;
pub const CAP_READWRITE: u32 = 0x0100_0000;
pub const CAP_STREAMING: u32 = 0x0400_0000;
pub const CAP_META_OUTPUT: u32 = 0x0800_0000;
pub const CAP_TOUCH: u32 = 0x1000_0000;
pub const CAP_IO_MC: u32 = 0x2000_0000;
pub const CAP_DEVICE_CAPS: u32 = 0x8000_0000;

/// `v4l2_captureparm.capability`: the device honours `timeperframe`.
pub const CAP_TIMEPERFRAME: u32 = 0x1000;
/// `v4l2_captureparm.capturemode`: high-quality still capture.
pub const MODE_HIGHQUALITY: u32 = 0x0001;

// ---- v4l2_fmtdesc.flags --------------------------------------------------
pub const FMT_FLAG_COMPRESSED: u32 = 0x0001;
pub const FMT_FLAG_EMULATED: u32 = 0x0002;
pub const FMT_FLAG_CONTINUOUS_BYTESTREAM: u32 = 0x0004;
pub const FMT_FLAG_DYN_RESOLUTION: u32 = 0x0008;
pub const FMT_FLAG_ENC_CAP_FRAME_INTERVAL: u32 = 0x0010;
pub const FMT_FLAG_CSC_COLORSPACE: u32 = 0x0020;
pub const FMT_FLAG_CSC_XFER_FUNC: u32 = 0x0040;
pub const FMT_FLAG_CSC_YCBCR_ENC: u32 = 0x0080;
pub const FMT_FLAG_CSC_QUANTIZATION: u32 = 0x0100;

// ---- v4l2_buffer.flags ---------------------------------------------------
pub const BUF_FLAG_MAPPED: u32 = 0x0000_0001;
pub const BUF_FLAG_QUEUED: u32 = 0x0000_0002;
pub const BUF_FLAG_DONE: u32 = 0x0000_0004;
pub const BUF_FLAG_KEYFRAME: u32 = 0x0000_0008;
pub const BUF_FLAG_PFRAME: u32 = 0x0000_0010;
pub const BUF_FLAG_BFRAME: u32 = 0x0000_0020;
pub const BUF_FLAG_ERROR: u32 = 0x0000_0040;
pub const BUF_FLAG_IN_REQUEST: u32 = 0x0000_0080;
pub const BUF_FLAG_TIMECODE: u32 = 0x0000_0100;
pub const BUF_FLAG_M2M_HOLD_CAPTURE_BUF: u32 = 0x0000_0200;
pub const BUF_FLAG_PREPARED: u32 = 0x0000_0400;
pub const BUF_FLAG_NO_CACHE_INVALIDATE: u32 = 0x0000_0800;
pub const BUF_FLAG_NO_CACHE_CLEAN: u32 = 0x0000_1000;
pub const BUF_FLAG_TIMESTAMP_MASK: u32 = 0x0000_e000;
pub const BUF_FLAG_TIMESTAMP_UNKNOWN: u32 = 0x0000_0000;
pub const BUF_FLAG_TIMESTAMP_MONOTONIC: u32 = 0x0000_2000;
pub const BUF_FLAG_TIMESTAMP_COPY: u32 = 0x0000_4000;
pub const BUF_FLAG_TSTAMP_SRC_MASK: u32 = 0x0007_0000;
pub const BUF_FLAG_TSTAMP_SRC_EOF: u32 = 0x0000_0000;
pub const BUF_FLAG_TSTAMP_SRC_SOE: u32 = 0x0001_0000;
pub const BUF_FLAG_LAST: u32 = 0x0010_0000;
pub const BUF_FLAG_REQUEST_FD: u32 = 0x0080_0000;

// ---- v4l2_requestbuffers.capabilities / v4l2_create_buffers.capabilities -
pub const BUF_CAP_SUPPORTS_MMAP: u32 = 1 << 0;
pub const BUF_CAP_SUPPORTS_USERPTR: u32 = 1 << 1;
pub const BUF_CAP_SUPPORTS_DMABUF: u32 = 1 << 2;
pub const BUF_CAP_SUPPORTS_REQUESTS: u32 = 1 << 3;
pub const BUF_CAP_SUPPORTS_ORPHANED_BUFS: u32 = 1 << 4;
pub const BUF_CAP_SUPPORTS_M2M_HOLD_CAPTURE_BUF: u32 = 1 << 5;
pub const BUF_CAP_SUPPORTS_MMAP_CACHE_HINTS: u32 = 1 << 6;
pub const BUF_CAP_SUPPORTS_MAX_NUM_BUFFERS: u32 = 1 << 7;
pub const BUF_CAP_SUPPORTS_REMOVE_BUFS: u32 = 1 << 8;

// ---- v4l2_frmsizetypes / v4l2_frmivaltypes -------------------------------
pub const FRMSIZE_TYPE_DISCRETE: u32 = 1;
pub const FRMSIZE_TYPE_CONTINUOUS: u32 = 2;
pub const FRMSIZE_TYPE_STEPWISE: u32 = 3;
pub const FRMIVAL_TYPE_DISCRETE: u32 = 1;
pub const FRMIVAL_TYPE_CONTINUOUS: u32 = 2;
pub const FRMIVAL_TYPE_STEPWISE: u32 = 3;

// ---- v4l2_input ----------------------------------------------------------
pub const INPUT_TYPE_TUNER: u32 = 1;
pub const INPUT_TYPE_CAMERA: u32 = 2;
pub const INPUT_TYPE_TOUCH: u32 = 3;
pub const IN_ST_NO_POWER: u32 = 0x0000_0001;
pub const IN_ST_NO_SIGNAL: u32 = 0x0000_0002;
pub const IN_ST_NO_COLOR: u32 = 0x0000_0004;
pub const IN_CAP_DV_TIMINGS: u32 = 0x0000_0002;
pub const IN_CAP_STD: u32 = 0x0000_0004;
pub const IN_CAP_NATIVE_SIZE: u32 = 0x0000_0008;

// ---- v4l2_priority -------------------------------------------------------
pub const PRIORITY_UNSET: u32 = 0;
pub const PRIORITY_BACKGROUND: u32 = 1;
pub const PRIORITY_INTERACTIVE: u32 = 2;
pub const PRIORITY_RECORD: u32 = 3;
pub const PRIORITY_DEFAULT: u32 = PRIORITY_INTERACTIVE;

// ---- colorimetry ---------------------------------------------------------
pub const COLORSPACE_DEFAULT: u32 = 0;
pub const COLORSPACE_SMPTE170M: u32 = 1;
pub const COLORSPACE_REC709: u32 = 3;
pub const COLORSPACE_SRGB: u32 = 8;
pub const COLORSPACE_RAW: u32 = 11;
pub const XFER_FUNC_DEFAULT: u32 = 0;
pub const XFER_FUNC_709: u32 = 1;
pub const XFER_FUNC_SRGB: u32 = 2;
pub const XFER_FUNC_NONE: u32 = 5;
pub const YCBCR_ENC_DEFAULT: u32 = 0;
pub const YCBCR_ENC_601: u32 = 1;
pub const YCBCR_ENC_709: u32 = 2;
pub const QUANTIZATION_DEFAULT: u32 = 0;
pub const QUANTIZATION_FULL_RANGE: u32 = 1;
pub const QUANTIZATION_LIM_RANGE: u32 = 2;

// ---- v4l2_selection targets ----------------------------------------------
pub const SEL_TGT_CROP: u32 = 0x0000;
pub const SEL_TGT_CROP_DEFAULT: u32 = 0x0001;
pub const SEL_TGT_CROP_BOUNDS: u32 = 0x0002;
pub const SEL_TGT_NATIVE_SIZE: u32 = 0x0003;
pub const SEL_TGT_COMPOSE: u32 = 0x0100;
pub const SEL_TGT_COMPOSE_DEFAULT: u32 = 0x0101;
pub const SEL_TGT_COMPOSE_BOUNDS: u32 = 0x0102;
pub const SEL_TGT_COMPOSE_PADDED: u32 = 0x0103;

// ---- events ---------------------------------------------------------------
pub const EVENT_ALL: u32 = 0;
pub const EVENT_VSYNC: u32 = 1;
pub const EVENT_EOS: u32 = 2;
pub const EVENT_CTRL: u32 = 3;
pub const EVENT_FRAME_SYNC: u32 = 4;
pub const EVENT_SOURCE_CHANGE: u32 = 5;
pub const EVENT_MOTION_DET: u32 = 6;
pub const EVENT_PRIVATE_START: u32 = 0x0800_0000;
pub const EVENT_SUB_FL_SEND_INITIAL: u32 = 1 << 0;
pub const EVENT_SUB_FL_ALLOW_FEEDBACK: u32 = 1 << 1;
/// `v4l2_event_ctrl.changes`.
pub const EVENT_CTRL_CH_VALUE: u32 = 1 << 0;
pub const EVENT_CTRL_CH_FLAGS: u32 = 1 << 1;
pub const EVENT_CTRL_CH_RANGE: u32 = 1 << 2;
pub const EVENT_CTRL_CH_DIMENSIONS: u32 = 1 << 3;
/// `v4l2_event_src_change.changes`.
pub const EVENT_SRC_CH_RESOLUTION: u32 = 1 << 0;

// ---- device version reported in v4l2_capability.version -------------------
/// `LINUX_VERSION_CODE`-shaped triple this device core answers `QUERYCAP` with.
pub const V4L2_VERSION: u32 = (6 << 16) | (16 << 8);
