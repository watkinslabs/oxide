// FUSE (Filesystem in Userspace) — the `/dev/fuse` channel device + the `fuse`
// filesystem type + the FUSE wire protocol that forwards VFS read-path ops to a
// userspace daemon (Linux `fs/fuse/`). A libfuse daemon `open`s `/dev/fuse`,
// `mount("fuse", target, "fuse", 0, "fd=N,rootmode=…")`, then serves requests
// off the channel fd.
//
// Module map:
//   * `proto`  — the byte-faithful `uapi/linux/fuse.h` wire codec.
//   * `conn`   — the `FuseConn` channel state machine (request queue, reply
//                matching by `unique`, blocking-caller wakeup, abort).
//   * `dev`    — the `/dev/fuse` misc char device `file_operations`.
//   * `fs`     — the mounted `fuse` filesystem + root inode + mount parsing.
//   * `fops`   — the forwarding `i_op`/`i_fop` (LOOKUP/GETATTR/OPEN/READ/READDIR…).
//
// Scope: a REAL read-only browse+read filesystem (LOOKUP, GETATTR, OPEN/OPENDIR,
// READ, READDIR, RELEASE/RELEASEDIR, FLUSH, INIT). The write/create/mutation
// family is deliberately OUT of scope and takes the VFS `Erofs` default — it is
// NOT faked as success.

pub mod proto;
pub mod conn;
pub mod dev;
pub mod fs;
pub mod fops;

#[cfg(test)]
mod tests;

extern crate alloc;

/// `FUSE_SUPER_MAGIC` (`include/uapi/linux/magic.h`) — statfs `f_type`. # C: O(1)
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
    let factory: devfs::NodeFactory = alloc::sync::Arc::new(|| dev::make_fuse_dev_inode());
    devfs::add_device_node("misc", "fuse", Some((dev::FUSE_DEV_MAJOR, dev::FUSE_DEV_MINOR)), Some(factory));
}

/// `mount("fuse", …, data)` entry — parse the `fd=N,rootmode=…,user_id=…,
/// group_id=…` option string, resolve the daemon's `/dev/fuse` channel fd (in
/// the mounting task's context), fire `FUSE_INIT`, and build the `FuseFs` +
/// root inode. The syscalls fuse-mount ctor calls this. Runs in the daemon's
/// task, so `proc_fd_file(None, fd)` reaches the daemon's own fd table.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn mount_from_data(data: &str) -> vfs::KResult<(alloc::sync::Arc<dyn vfs::fs::FileSystem>, vfs::InodeRef)> {
    let opts = fs::parse_mount_opts(data)?;
    let file = sched::proclink::proc_fd_file(None, opts.fd).ok_or(vfs::VfsError::Ebadf)?;
    if !dev::is_fuse_dev(&file) { return Err(vfs::VfsError::Einval); }
    let conn = dev::conn_for(&file);
    let ffs = fs::build_fuse_fs(conn, opts.rootmode, opts.user_id, opts.group_id);
    let root = ffs.root_inode();
    let dyn_fs: alloc::sync::Arc<dyn vfs::fs::FileSystem> = ffs;
    Ok((dyn_fs, root))
}
