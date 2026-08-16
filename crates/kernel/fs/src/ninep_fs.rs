// The mounted 9P filesystem — a host directory exported into this guest.
//
// Module manifest:
//   * `attr`  — server metadata to inode fields, and open flags to `.L` flags.
//   * `fs`    — the session, mount policy, inode identity map, superblock face.
//   * `inode` — `i_op`: lookup and the namespace and metadata operations.
//   * `file`  — `i_fop`: read, write, readdir, and the per-description handle.
//   * `mount` — the mount entry point: options, transport, attach.
//
// The protocol and the client live in the `ninep` crate; nothing here encodes
// a 9P message by hand.

pub mod attr;
pub mod fs;
pub mod inode;
pub mod file;
pub mod mount;

pub use fs::{NinepFs, NinepInodeData, NinepMount};
pub use mount::{mount_9p, NINEP_FS_NAME, NINEP_PARAMS};

#[cfg(test)]
mod tests;
