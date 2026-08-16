#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! OverlayFS: one directory tree presented from several stacked ones, with
//! writes landing in a single writable layer.
//!
//! Without it a container image cannot be run: every layered image, every
//! `podman run`, every `toolbox enter` mounts a read-only stack of layers with
//! one writable layer on top, and has no writable root at all otherwise.
//!
//! Module manifest:
//! - `uapi`:      the names and numbers written into a layer.
//! - `limits`:    bounds the mount and its records are held to.
//! - `config`:    what a mount was asked for.
//! - `params`:    the option string, and the combinations that are refused.
//! - `xattr`:     which attributes are the overlay's own.
//! - `redirect`:  where a renamed object left its lower half.
//! - `xino`:      one inode-number space across layers that each have their own.
//! - `fh`:        the record naming the lower object an upper one came from.
//! - `metacopy`:  the record marking an object whose data is still below.
//! - `whiteout`:  how a deleted lower name is recorded and recognised.
//! - `layers`:    the stack itself, and the layer each object comes from.
//! - `lookup`:    walking the layers, and the merged object that results.
//! - `copyup`:    moving an object into the writable layer, in an order that
//!                survives a crash at any point.
//! - `dirops`:    create, unlink, rename and link over a merged tree.
//! - `readdir`:   the merged directory stream, deduplicated and filtered.
//! - `inode`:     the overlay's inode operations.
//! - `file`:      opening the right layer, and the operations that follow.
//! - `mount`:     the filesystem itself, from options to a root inode.
//!
//! Everything above `layers` is a pure function of bytes and options: the
//! whole option grammar, the marker classification, the record formats and the
//! inode-number remapping fail a test with no mount and no layers. The stages
//! below it drive real inodes, which the tests supply from an in-memory layer
//! filesystem rather than from a boot.

extern crate alloc;

#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod uapi;
pub mod limits;
pub mod config;
pub mod params;
pub mod xattr;
pub mod redirect;
pub mod xino;
pub mod fh;
pub mod metacopy;
pub mod err;
pub mod marker;
pub mod origin;
pub mod whiteout;
pub mod layers;
pub mod lookup;
pub mod copyup;
pub mod readdir;
pub mod dirops;
#[cfg(test)]
#[path = "testfs.rs"]
mod testfs;

pub use config::{Config, FsyncMode, RedirectMode, UuidMode, VerityMode, XinoMode};
pub use params::{parse, verify};
pub use uapi::{Marker, OVERLAYFS_SUPER_MAGIC};
