// FUSE (Filesystem in Userspace) — the `/dev/fuse` channel device + the `fuse`
// filesystem type + the FUSE wire protocol that forwards VFS read-path ops to a
// userspace daemon. A libfuse daemon `open`s `/dev/fuse`,
// `mount("fuse", target, "fuse", 0, "fd=N,rootmode=…")`, then serves requests
// off the channel fd.
//
// Module map:
//   * `proto`  — the byte-faithful FUSE wire codec.
//   * `conn`   — the `FuseConn` channel state machine (request queue, reply
//                matching by `unique`, blocking-caller wakeup, abort).
//   * `dev`    — the `/dev/fuse` misc char device `file_operations`.
//   * `fs`     — the mounted `fuse` filesystem + root inode + mount parsing.
//   * `fops`   — the forwarding `i_op`/`i_fop` (LOOKUP/GETATTR/OPEN/READ/READDIR…).
//   * `flush`  — FLUSH decisions: the lock-owner scramble, the skip rule, the body.
//   * `params` — the mount-parameter table fuse options are admitted against.
//
// Scope: a REAL read-only browse+read filesystem (LOOKUP, GETATTR, OPEN/OPENDIR,
// READ, READDIR, RELEASE/RELEASEDIR, FLUSH, INIT). The write/create/mutation
// family is deliberately OUT of scope and takes the VFS `Erofs` default — it is
// NOT faked as success.
//
// `ABI.md` pins the advertised Linux FUSE wire revision and its change gate.

pub mod proto;
pub mod conn;
pub mod dev;
pub mod fs;
pub mod fops;
pub mod flush;
pub mod fsync;
mod params;
mod context;

pub use context::FuseContextOps;
pub use params::{FUSE_FD_KEY, FUSE_PARAMS};

#[cfg(test)]
mod tests;

extern crate alloc;

/// `FUSE_SUPER_MAGIC` — statfs `f_type`. # C: O(1)
pub const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;
/// Block size a fuse mount reports (Linux `fuse_fill_super` default). # C: O(1)
pub const FUSE_BLKSIZE: u32 = 512;
/// `max_readahead` advertised in our `FUSE_INIT` request (128 KiB). # C: O(1)
pub const FUSE_MAX_READAHEAD: u32 = 128 * 1024;

// Wire errno values (`fuse_out_header.error`) are NEGATIVE (Linux `-errno`).
// Named so the channel abort/decode paths carry no magic numbers.

/// `-ENOTCONN` — the wire error a pending request is completed with on abort.
/// # C: O(1)
pub const FUSE_WIRE_ENOTCONN: i32 = -107;
/// `-EIO` — the fallback wire error for an unrecognised daemon errno. # C: O(1)
pub const FUSE_WIRE_EIO: i32 = -5;

/// Register the `/dev/fuse` misc char device (major 10, minor 229) into the
/// devfs tree so a daemon can `open("/dev/fuse")`. Call once at boot AFTER
/// `devfs::boot::populate_defaults` has created `/dev`. The `fuse` filesystem
/// TYPE is registered separately in the syscalls mount registry (its ctor needs
/// the daemon's fd table). # C: O(depth)
#[cfg(target_os = "oxide-kernel")]
pub fn register() {
    dev::register_chrdev().expect("FUSE character-device registration failed");
    let factory: devfs::NodeFactory = alloc::sync::Arc::new(|| dev::make_fuse_dev_inode());
    devfs::add_device_node("misc", "fuse", Some((dev::FUSE_DEV_MAJOR, dev::FUSE_DEV_MINOR)), Some(factory));
}

/// Build one FUSE filesystem from typed mount options and an opened channel.
/// Device identity was checked when the context consumed `fd=`. # C: O(1)
pub(super) fn mount_from_context(opts: fs::MountOpts, file: &vfs::File)
    -> vfs::KResult<alloc::sync::Arc<fs::FuseFs>> {
    if !dev::is_fuse_dev(file) { return Err(vfs::VfsError::Einval); }
    let conn = dev::conn_for(file);
    Ok(fs::build_fuse_fs(conn, &opts))
}
