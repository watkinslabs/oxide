#![no_std]
extern crate alloc;

// Module manifest:
// - `uapi`: the numbers and layouts that cross the ABI.
// - `ids`: device numbers, class name, inode tag.
// - `usermem`: the caller's memory as the command surface sees it.
// - `format`: pixel formats and the `TRY_FMT` negotiation.
// - `vb2`: the buffer queue.
// - `ctrl`: the control framework.
// - `event`: the per-handle event queue.
// - `prio`: priority arbitration between handles.
// - `ops`: what a driver supplies.
// - `device`: the video device, its handles, and the registry.
// - `ioctl`: the command surface.
// - `node`: the `/dev/videoN` node — the only target-gated module.

pub mod uapi;
pub mod ids;
pub mod usermem;
pub mod format;
pub mod vb2;
pub mod ctrl;
pub mod event;
pub mod prio;
pub mod ops;
pub mod device;
pub mod ioctl;

#[cfg(target_os = "oxide-kernel")]
pub mod node;

pub use device::{register, unregister, FileHandle, Registration, VideoDevice};
pub use format::{Fract, FormatDesc, FrameSize, PixFormat};
pub use ops::{Identity, InputDesc, VideoOps};

#[cfg(test)]
mod tests;
