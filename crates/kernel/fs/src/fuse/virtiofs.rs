// virtiofs — a FUSE superblock whose transport is a virtio queue.
//
// There is no daemon, no `/dev/fuse` descriptor and no `fd=` mount option: the
// mount names a device TAG and the connection's requests go straight into a
// descriptor chain. Everything else is the FUSE connection this crate already
// has — same `unique` allocation, same reply matching, same `ENOSYS` latches,
// same inode identity map. A second implementation here would be a second
// source of truth about what a FUSE reply means.

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::sync::Arc;

use vfs::fs::{FsParamSpec, FsParamType};
use vfs::{KResult, PollSubscribers, VfsError};

use super::conn::FuseConn;
use super::fs::{build_named_fuse_fs, FuseFs, MountOpts};
use super::iqueue::FuseTransportRef;

/// The filesystem type name a mount names.
pub const VIRTIOFS_FS_NAME: &str = "virtiofs";

/// `S_IFDIR | 0755` — the mode the root inode starts with, before the first
/// GETATTR replaces it with what the server actually reports. A `/dev/fuse`
/// mount is told this by the daemon in `rootmode=`; a virtiofs mount has no
/// such option and no daemon to ask, so it starts from the only mode a mount
/// point can usefully have and corrects it on first use.
pub const VIRTIOFS_ROOTMODE: u32 = 0o40755;

/// Options a virtiofs mount admits. Deliberately NOT the `/dev/fuse` set: there
/// is no channel descriptor, so `fd=` and `rootmode=` have nothing to name, and
/// accepting them would let a caller believe they had configured something.
pub static VIRTIOFS_PARAMS: &[FsParamSpec] = &[
    FsParamSpec::value("source", FsParamType::String),
    FsParamSpec::value("tag", FsParamType::String),
    FsParamSpec::value("max_read", FsParamType::U32),
    FsParamSpec::flag("default_permissions"),
    FsParamSpec::flag("allow_other"),
];

/// Establish a FUSE connection over `transport` and build the mount.
///
/// The transport is bound BEFORE the handshake is queued: `send_init` hands its
/// request to whatever transport is installed at that moment, and installing
/// one afterwards would leave the INIT sitting in the `/dev/fuse` pending queue
/// that no daemon is ever going to read. # C: O(1) + one round trip
pub fn mount_virtiofs(tag: &str, transport: FuseTransportRef, uid: u32, gid: u32)
    -> KResult<Arc<FuseFs>>
{
    let max_read = transport.max_message();
    let conn = FuseConn::new(Arc::new(PollSubscribers::new()));
    conn.set_transport(transport);
    let opts = MountOpts {
        rootmode: VIRTIOFS_ROOTMODE,
        user_id: uid,
        group_id: gid,
        default_permissions: false,
        allow_other: false,
        max_read,
        subtype: None,
    };
    Ok(build_named_fuse_fs(conn, &opts, VIRTIOFS_FS_NAME.to_string(),
        show_options(tag, max_read)))
}

/// Mount a virtiofs share by tag, resolving the transport through the
/// directory a driver publishes itself into. # C: O(1) + one round trip
pub fn mount_by_tag(tag: &str, uid: u32, gid: u32) -> KResult<Arc<FuseFs>> {
    // No opener at all and no device with this tag are different failures: the
    // first says this kernel cannot serve virtiofs, the second that this box
    // has no such share.
    if !fuse_transport::registry::available() { return Err(VfsError::Enodev); }
    let transport = fuse_transport::registry::open(tag).ok_or(VfsError::Enoent)?;
    mount_virtiofs(tag, transport, uid, gid)
}

/// The option tail a mount table shows for a virtiofs mount. # C: O(1)
pub fn show_options(tag: &str, max_read: u32) -> String {
    let mut s = String::from(",tag=");
    s.push_str(tag);
    s.push_str(",max_read=");
    let mut n = max_read as u64;
    if n == 0 { s.push('0'); return s; }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; }
    for b in &buf[i..] { s.push(*b as char); }
    s
}
