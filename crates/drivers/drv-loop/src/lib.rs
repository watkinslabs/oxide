#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! Loop devices: a block device whose media is a file.
//!
//! What it is for, in the order people meet it: mounting a filesystem image
//! without writing it to a disk, and giving an installer or a package a block
//! device where it expects one. `losetup` and `mount -o loop` are the two
//! callers that matter.
//!
//! Module manifest:
//! - `uapi`:    ioctl numbers, wire structs, flag bits. Numbers only.
//! - `size`:    capacity from the backing file and window; block-size rules.
//! - `config`:  what a status/configure request may change, and its refusal order.
//! - `control`: `/dev/loop-control` index decisions — add, remove, get-free.
//! - `device`:  the `BlockDevice` whose reads and writes reach a file.
//! - `registry`: which devices exist, and their published block identity.
//! - `backing`:  the `vfs::File` adapter the published devices read through.
//! - `ioctl`:    the work behind each loop ioctl, over already-resolved inputs.
//!
//! Everything except `device` is pure and hosted-tested: the whole ABI
//! contract can fail a test without a kernel, a disk or a mount.

extern crate alloc;

pub mod uapi;
pub mod size;
pub mod config;
pub mod control;
pub mod device;
pub mod registry;
pub mod backing;
pub mod ioctl;

pub use config::{flags_after_configure, flags_after_set_status, info64_from_old, old_from_info64,
                 window_changed, window_from_info, Window};
pub use control::{add, get_free, remove, Action, Entry, State};
pub use backing::FileBacking;
pub use device::{Backing, LoopDevice};
pub use registry::{device, index, init, LOOP_DRIVER};
pub use size::{backing_offset, capacity_sectors, usable_bytes, validate_block_size};
pub use uapi::*;

#[cfg(any(test, feature = "hosted"))]
pub mod testing;
