//! V4L2 UAPI: the numbers and layouts that cross the kernel boundary.
//!
//! Module manifest:
//! - `ioctl`: `VIDIOC_*` command encodings and `_IOC` field accessors.
//! - `layout`: byte sizes and field offsets of every structure on the ABI.
//! - `flags`: buffer types, memory models, field orders, capability and
//!   buffer bit flags, colorimetry, selection targets, event types.
//! - `fourcc`: `V4L2_PIX_FMT_*` codes and the image-size arithmetic per format.
//! - `ctrl_ids`: control classes, standard control ids, types and flags.
//!
//! Nothing here decides anything. Policy — what a device answers, what a
//! command is refused for — lives in the implementation modules.

pub mod ioctl;
pub mod layout;
pub mod flags;
pub mod fourcc;
pub mod ctrl_ids;
