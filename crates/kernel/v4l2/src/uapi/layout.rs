//! Byte sizes and field offsets of every V4L2 structure crossing the ABI.
//!
//! One name per (struct, field). The wire encoders and decoders address the
//! caller's buffer only through these, so a layout mistake is a single-line
//! fix and a test that names the field, never a scattered literal.

// ---- v4l2_capability -----------------------------------------------------
pub const CAPABILITY_SIZE: usize = 104;
pub const CAP_DRIVER: usize = 0;
pub const CAP_DRIVER_LEN: usize = 16;
pub const CAP_CARD: usize = 16;
pub const CAP_CARD_LEN: usize = 32;
pub const CAP_BUS_INFO: usize = 48;
pub const CAP_BUS_INFO_LEN: usize = 32;
pub const CAP_VERSION: usize = 80;
pub const CAP_CAPABILITIES: usize = 84;
pub const CAP_DEVICE_CAPS: usize = 88;
pub const CAP_RESERVED: usize = 92;
pub const CAP_RESERVED_LEN: usize = 12;

// ---- v4l2_fmtdesc --------------------------------------------------------
pub const FMTDESC_SIZE: usize = 64;
pub const FMTDESC_INDEX: usize = 0;
pub const FMTDESC_TYPE: usize = 4;
pub const FMTDESC_FLAGS: usize = 8;
pub const FMTDESC_DESCRIPTION: usize = 12;
pub const FMTDESC_DESCRIPTION_LEN: usize = 32;
pub const FMTDESC_PIXELFORMAT: usize = 44;
pub const FMTDESC_MBUS_CODE: usize = 48;
pub const FMTDESC_RESERVED: usize = 52;
pub const FMTDESC_RESERVED_LEN: usize = 12;

// ---- v4l2_pix_format (inside v4l2_format, at FORMAT_FMT) -----------------
pub const PIX_FORMAT_SIZE: usize = 48;
pub const PIX_WIDTH: usize = 0;
pub const PIX_HEIGHT: usize = 4;
pub const PIX_PIXELFORMAT: usize = 8;
pub const PIX_FIELD: usize = 12;
pub const PIX_BYTESPERLINE: usize = 16;
pub const PIX_SIZEIMAGE: usize = 20;
pub const PIX_COLORSPACE: usize = 24;
pub const PIX_PRIV: usize = 28;
pub const PIX_FLAGS: usize = 32;
/// `ycbcr_enc`/`hsv_enc` share this word.
pub const PIX_ENC: usize = 36;
pub const PIX_QUANTIZATION: usize = 40;
pub const PIX_XFER_FUNC: usize = 44;

// ---- v4l2_format ---------------------------------------------------------
pub const FORMAT_SIZE: usize = 208;
pub const FORMAT_TYPE: usize = 0;
/// The union starts 8-aligned, so four padding bytes follow `type`.
pub const FORMAT_FMT: usize = 8;
pub const FORMAT_FMT_LEN: usize = 200;

// ---- v4l2_pix_format_mplane (the mplane arm of the same union) -----------
pub const PIX_MP_WIDTH: usize = 0;
pub const PIX_MP_HEIGHT: usize = 4;
pub const PIX_MP_PIXELFORMAT: usize = 8;
pub const PIX_MP_FIELD: usize = 12;
pub const PIX_MP_COLORSPACE: usize = 16;
pub const PIX_MP_PLANE_FMT: usize = 20;
pub const PIX_MP_NUM_PLANES: usize = 180;
pub const PIX_MP_FLAGS: usize = 181;
pub const PIX_MP_ENC: usize = 182;
pub const PIX_MP_QUANTIZATION: usize = 183;
pub const PIX_MP_XFER_FUNC: usize = 184;
pub const PIX_MP_RESERVED: usize = 185;
/// `struct v4l2_plane_pix_format`: `sizeimage`, `bytesperline`, 12 reserved.
pub const PLANE_PIX_FORMAT_SIZE: usize = 20;
pub const PLANE_PIX_SIZEIMAGE: usize = 0;
pub const PLANE_PIX_BYTESPERLINE: usize = 4;
/// `VIDEO_MAX_PLANES`.
pub const MAX_PLANES: usize = 8;

// ---- v4l2_frmsizeenum ----------------------------------------------------
pub const FRMSIZEENUM_SIZE: usize = 44;
pub const FRMSIZE_INDEX: usize = 0;
pub const FRMSIZE_PIXEL_FORMAT: usize = 4;
pub const FRMSIZE_TYPE: usize = 8;
/// Discrete arm: `width`,`height`.
pub const FRMSIZE_DISCRETE_WIDTH: usize = 12;
pub const FRMSIZE_DISCRETE_HEIGHT: usize = 16;
/// Stepwise arm: min/max/step for each axis.
pub const FRMSIZE_STEPWISE_MIN_WIDTH: usize = 12;
pub const FRMSIZE_STEPWISE_MAX_WIDTH: usize = 16;
pub const FRMSIZE_STEPWISE_STEP_WIDTH: usize = 20;
pub const FRMSIZE_STEPWISE_MIN_HEIGHT: usize = 24;
pub const FRMSIZE_STEPWISE_MAX_HEIGHT: usize = 28;
pub const FRMSIZE_STEPWISE_STEP_HEIGHT: usize = 32;
pub const FRMSIZE_RESERVED: usize = 36;
pub const FRMSIZE_RESERVED_LEN: usize = 8;

// ---- v4l2_frmivalenum ----------------------------------------------------
pub const FRMIVALENUM_SIZE: usize = 52;
pub const FRMIVAL_INDEX: usize = 0;
pub const FRMIVAL_PIXEL_FORMAT: usize = 4;
pub const FRMIVAL_WIDTH: usize = 8;
pub const FRMIVAL_HEIGHT: usize = 12;
pub const FRMIVAL_TYPE: usize = 16;
/// Discrete arm: one `v4l2_fract`.
pub const FRMIVAL_DISCRETE_NUM: usize = 20;
pub const FRMIVAL_DISCRETE_DEN: usize = 24;
pub const FRMIVAL_STEPWISE_MIN_NUM: usize = 20;
pub const FRMIVAL_STEPWISE_MIN_DEN: usize = 24;
pub const FRMIVAL_STEPWISE_MAX_NUM: usize = 28;
pub const FRMIVAL_STEPWISE_MAX_DEN: usize = 32;
pub const FRMIVAL_STEPWISE_STEP_NUM: usize = 36;
pub const FRMIVAL_STEPWISE_STEP_DEN: usize = 40;
pub const FRMIVAL_RESERVED: usize = 44;
pub const FRMIVAL_RESERVED_LEN: usize = 8;

// ---- v4l2_requestbuffers -------------------------------------------------
pub const REQUESTBUFFERS_SIZE: usize = 20;
pub const REQBUFS_COUNT: usize = 0;
pub const REQBUFS_TYPE: usize = 4;
pub const REQBUFS_MEMORY: usize = 8;
pub const REQBUFS_CAPABILITIES: usize = 12;
/// One byte, not a word: `flags` is `__u8` followed by three reserved bytes.
pub const REQBUFS_FLAGS: usize = 16;
pub const REQBUFS_RESERVED: usize = 17;
pub const REQBUFS_RESERVED_LEN: usize = 3;

// ---- v4l2_create_buffers -------------------------------------------------
pub const CREATE_BUFFERS_SIZE: usize = 256;
pub const CREATE_INDEX: usize = 0;
pub const CREATE_COUNT: usize = 4;
pub const CREATE_MEMORY: usize = 8;
/// The embedded `v4l2_format` is 8-aligned, so four padding bytes precede it.
pub const CREATE_FORMAT: usize = 16;
pub const CREATE_CAPABILITIES: usize = 224;
pub const CREATE_FLAGS: usize = 228;
pub const CREATE_MAX_NUM_BUFFERS: usize = 232;
pub const CREATE_RESERVED: usize = 236;
pub const CREATE_RESERVED_LEN: usize = 20;

// ---- v4l2_buffer ---------------------------------------------------------
pub const BUFFER_SIZE: usize = 88;
pub const BUF_INDEX: usize = 0;
pub const BUF_TYPE: usize = 4;
pub const BUF_BYTESUSED: usize = 8;
pub const BUF_FLAGS: usize = 12;
pub const BUF_FIELD: usize = 16;
/// `struct timeval`: two 64-bit words on LP64.
pub const BUF_TIMESTAMP_SEC: usize = 24;
pub const BUF_TIMESTAMP_USEC: usize = 32;
pub const BUF_TIMECODE: usize = 40;
pub const BUF_TIMECODE_LEN: usize = 16;
pub const BUF_SEQUENCE: usize = 56;
pub const BUF_MEMORY: usize = 60;
/// The `m` union: `offset` (u32), `userptr` (u64), `planes` (ptr), `fd` (s32).
pub const BUF_M: usize = 64;
pub const BUF_LENGTH: usize = 72;
pub const BUF_RESERVED2: usize = 76;
pub const BUF_REQUEST_FD: usize = 80;

// ---- v4l2_plane ----------------------------------------------------------
pub const PLANE_SIZE: usize = 64;
pub const PLANE_BYTESUSED: usize = 0;
pub const PLANE_LENGTH: usize = 4;
pub const PLANE_M: usize = 8;
pub const PLANE_DATA_OFFSET: usize = 16;
pub const PLANE_RESERVED: usize = 20;
pub const PLANE_RESERVED_LEN: usize = 44;

// ---- v4l2_exportbuffer ---------------------------------------------------
pub const EXPORTBUFFER_SIZE: usize = 64;
pub const EXPBUF_TYPE: usize = 0;
pub const EXPBUF_INDEX: usize = 4;
pub const EXPBUF_PLANE: usize = 8;
pub const EXPBUF_FLAGS: usize = 12;
pub const EXPBUF_FD: usize = 16;
pub const EXPBUF_RESERVED: usize = 20;
pub const EXPBUF_RESERVED_LEN: usize = 44;

// ---- v4l2_streamparm / v4l2_captureparm ----------------------------------
pub const STREAMPARM_SIZE: usize = 204;
pub const STREAMPARM_TYPE: usize = 0;
pub const STREAMPARM_PARM: usize = 4;
pub const STREAMPARM_PARM_LEN: usize = 200;
pub const CAPTUREPARM_SIZE: usize = 40;
pub const CAPTUREPARM_CAPABILITY: usize = 0;
pub const CAPTUREPARM_CAPTUREMODE: usize = 4;
pub const CAPTUREPARM_TIMEPERFRAME_NUM: usize = 8;
pub const CAPTUREPARM_TIMEPERFRAME_DEN: usize = 12;
pub const CAPTUREPARM_EXTENDEDMODE: usize = 16;
pub const CAPTUREPARM_READBUFFERS: usize = 20;
pub const CAPTUREPARM_RESERVED: usize = 24;
pub const CAPTUREPARM_RESERVED_LEN: usize = 16;

// ---- v4l2_input ----------------------------------------------------------
pub const INPUT_SIZE: usize = 80;
pub const INPUT_INDEX: usize = 0;
pub const INPUT_NAME: usize = 4;
pub const INPUT_NAME_LEN: usize = 32;
pub const INPUT_TYPE: usize = 36;
pub const INPUT_AUDIOSET: usize = 40;
pub const INPUT_TUNER: usize = 44;
pub const INPUT_STD: usize = 48;
pub const INPUT_STATUS: usize = 56;
pub const INPUT_CAPABILITIES: usize = 60;
pub const INPUT_RESERVED: usize = 64;
pub const INPUT_RESERVED_LEN: usize = 12;

// ---- v4l2_control --------------------------------------------------------
pub const CONTROL_SIZE: usize = 8;
pub const CONTROL_ID: usize = 0;
pub const CONTROL_VALUE: usize = 4;

// ---- v4l2_queryctrl ------------------------------------------------------
pub const QUERYCTRL_SIZE: usize = 68;
pub const QUERYCTRL_ID: usize = 0;
pub const QUERYCTRL_TYPE: usize = 4;
pub const QUERYCTRL_NAME: usize = 8;
pub const QUERYCTRL_NAME_LEN: usize = 32;
pub const QUERYCTRL_MINIMUM: usize = 40;
pub const QUERYCTRL_MAXIMUM: usize = 44;
pub const QUERYCTRL_STEP: usize = 48;
pub const QUERYCTRL_DEFAULT_VALUE: usize = 52;
pub const QUERYCTRL_FLAGS: usize = 56;
pub const QUERYCTRL_RESERVED: usize = 60;
pub const QUERYCTRL_RESERVED_LEN: usize = 8;

// ---- v4l2_query_ext_ctrl -------------------------------------------------
pub const QUERY_EXT_CTRL_SIZE: usize = 232;
pub const QEC_ID: usize = 0;
pub const QEC_TYPE: usize = 4;
pub const QEC_NAME: usize = 8;
pub const QEC_NAME_LEN: usize = 32;
pub const QEC_MINIMUM: usize = 40;
pub const QEC_MAXIMUM: usize = 48;
pub const QEC_STEP: usize = 56;
pub const QEC_DEFAULT_VALUE: usize = 64;
pub const QEC_FLAGS: usize = 72;
pub const QEC_ELEM_SIZE: usize = 76;
pub const QEC_ELEMS: usize = 80;
pub const QEC_NR_OF_DIMS: usize = 84;
pub const QEC_DIMS: usize = 88;
pub const QEC_DIMS_LEN: usize = 16;
pub const QEC_RESERVED: usize = 104;
pub const QEC_RESERVED_LEN: usize = 128;

// ---- v4l2_querymenu ------------------------------------------------------
pub const QUERYMENU_SIZE: usize = 44;
pub const QUERYMENU_ID: usize = 0;
pub const QUERYMENU_INDEX: usize = 4;
/// The union: 32 name bytes, or a 64-bit signed menu value.
pub const QUERYMENU_NAME: usize = 8;
pub const QUERYMENU_NAME_LEN: usize = 32;
pub const QUERYMENU_VALUE: usize = 8;
pub const QUERYMENU_RESERVED: usize = 40;

// ---- v4l2_ext_control / v4l2_ext_controls --------------------------------
pub const EXT_CONTROL_SIZE: usize = 20;
pub const EXT_CTRL_ID: usize = 0;
pub const EXT_CTRL_SIZE_FIELD: usize = 4;
pub const EXT_CTRL_RESERVED2: usize = 8;
/// The value union: `value` (s32), `value64` (s64), or a pointer.
pub const EXT_CTRL_VALUE: usize = 12;

pub const EXT_CONTROLS_SIZE: usize = 32;
/// `ctrl_class`/`which` share the first word.
pub const EXT_CTRLS_WHICH: usize = 0;
pub const EXT_CTRLS_COUNT: usize = 4;
pub const EXT_CTRLS_ERROR_IDX: usize = 8;
pub const EXT_CTRLS_REQUEST_FD: usize = 12;
pub const EXT_CTRLS_RESERVED: usize = 16;
pub const EXT_CTRLS_CONTROLS: usize = 24;

// ---- v4l2_event / v4l2_event_subscription --------------------------------
pub const EVENT_SIZE: usize = 136;
pub const EVENT_TYPE: usize = 0;
pub const EVENT_U: usize = 8;
pub const EVENT_U_LEN: usize = 64;
pub const EVENT_PENDING: usize = 72;
pub const EVENT_SEQUENCE: usize = 76;
/// `struct timespec`: two 64-bit words on LP64.
pub const EVENT_TIMESTAMP_SEC: usize = 80;
pub const EVENT_TIMESTAMP_NSEC: usize = 88;
pub const EVENT_ID: usize = 96;
pub const EVENT_RESERVED: usize = 100;
pub const EVENT_RESERVED_LEN: usize = 32;

/// `struct v4l2_event_ctrl` inside the event union.
pub const EVENT_CTRL_CHANGES: usize = 0;
pub const EVENT_CTRL_TYPE: usize = 4;
pub const EVENT_CTRL_VALUE: usize = 8;
pub const EVENT_CTRL_FLAGS: usize = 16;
pub const EVENT_CTRL_MINIMUM: usize = 20;
pub const EVENT_CTRL_MAXIMUM: usize = 24;
pub const EVENT_CTRL_STEP: usize = 28;
pub const EVENT_CTRL_DEFAULT_VALUE: usize = 32;

/// `struct v4l2_event_frame_sync`: one frame-sequence word.
pub const EVENT_FRAME_SYNC_SEQUENCE: usize = 0;
/// `struct v4l2_event_src_change`: one changes word.
pub const EVENT_SRC_CHANGE_CHANGES: usize = 0;

pub const EVENT_SUBSCRIPTION_SIZE: usize = 32;
pub const EVSUB_TYPE: usize = 0;
pub const EVSUB_ID: usize = 4;
pub const EVSUB_FLAGS: usize = 8;
pub const EVSUB_RESERVED: usize = 12;
pub const EVSUB_RESERVED_LEN: usize = 20;

// ---- v4l2_selection / v4l2_cropcap / v4l2_crop ---------------------------
pub const SELECTION_SIZE: usize = 64;
pub const SEL_TYPE: usize = 0;
pub const SEL_TARGET: usize = 4;
pub const SEL_FLAGS: usize = 8;
pub const SEL_R_LEFT: usize = 12;
pub const SEL_R_TOP: usize = 16;
pub const SEL_R_WIDTH: usize = 20;
pub const SEL_R_HEIGHT: usize = 24;
pub const SEL_RESERVED: usize = 28;
pub const SEL_RESERVED_LEN: usize = 36;

pub const CROPCAP_SIZE: usize = 44;
pub const CROPCAP_TYPE: usize = 0;
pub const CROPCAP_BOUNDS_LEFT: usize = 4;
pub const CROPCAP_BOUNDS_TOP: usize = 8;
pub const CROPCAP_BOUNDS_WIDTH: usize = 12;
pub const CROPCAP_BOUNDS_HEIGHT: usize = 16;
pub const CROPCAP_DEFRECT_LEFT: usize = 20;
pub const CROPCAP_DEFRECT_TOP: usize = 24;
pub const CROPCAP_DEFRECT_WIDTH: usize = 28;
pub const CROPCAP_DEFRECT_HEIGHT: usize = 32;
pub const CROPCAP_PIXELASPECT_NUM: usize = 36;
pub const CROPCAP_PIXELASPECT_DEN: usize = 40;

pub const CROP_SIZE: usize = 20;
pub const CROP_TYPE: usize = 0;
pub const CROP_C_LEFT: usize = 4;
pub const CROP_C_TOP: usize = 8;
pub const CROP_C_WIDTH: usize = 12;
pub const CROP_C_HEIGHT: usize = 16;

// ---- v4l2_standard -------------------------------------------------------
pub const STANDARD_SIZE: usize = 72;
