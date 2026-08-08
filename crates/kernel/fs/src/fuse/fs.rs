// The mounted `fuse` filesystem — `struct fuse_conn`'s VFS face. The mount
// (`mount("fuse", target, "fuse", 0, "fd=N,rootmode=…,user_id=…,group_id=…")`)
// parses the daemon's channel fd, ties this superblock to that `/dev/fuse`
// `FuseConn`, fires the mandatory `FUSE_INIT`, and builds the root inode
// (nodeid [`proto::FUSE_ROOT_ID`]). Every inode carries [`FuseInodeData`] so its
// `i_op`/`i_fop` can forward VFS ops to the channel.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::fs::FileSystem;
use vfs::timespec::NSEC_PER_SEC;
use vfs::{Inode, InodeBuilder, InodeRef, KResult, SbStatFs, SuperBlock, SuperOps,
    Timespec64, VfsError};

use super::conn::FuseConn;
use super::fops::{FuseFileOps, FuseInodeOps};
use super::proto::{self, Attr};
use super::{FUSE_BLKSIZE, FUSE_SUPER_MAGIC};

/// Backend-private state (`i_private`) on EVERY fuse inode — the shared channel
/// plus this inode's protocol `nodeid` (Linux `struct fuse_inode.nodeid`). The
/// forwarding `i_op`/`i_fop` recover it to address requests. # C: O(1)
pub struct FuseInodeData {
    /// The `/dev/fuse` channel this mount speaks over. # consumers: every op.
    pub conn: Arc<FuseConn>,
    /// This inode's FUSE `nodeid` (root == [`proto::FUSE_ROOT_ID`]).
    pub nodeid: u64,
}

/// Recover the [`FuseInodeData`] off a fuse inode's `i_private`; `Einval` if the
/// inode is not a fuse inode. # C: O(1)
pub fn fuse_data(inode: &Inode) -> KResult<&FuseInodeData> {
    inode.private::<FuseInodeData>().ok_or(VfsError::Einval)
}

/// Build an in-core inode for `nodeid` from a daemon-supplied [`Attr`], reusing a
/// live cached inode for the nodeid (identity) when present. `mode` is the full
/// `S_IF*|perm` word from the attr. # C: O(log N_nodes)
/// Daemon-supplied `fuse_attr` time pair as a [`Timespec64`]. The wire seconds
/// field is `uint64_t` but is assigned straight into a signed `time64_t`
/// (`inode_set_atime(inode, attr->atime, attr->atimensec)`), so the value is
/// REINTERPRETED as signed — a pre-1970 fuse timestamp arrives as a large
/// unsigned and must land as a negative second, not a year-2500 one. The
/// sub-second field is CLAMPED, not rejected, to the max in-range nanosecond
/// value (`NSEC_PER_SEC - 1`).
/// # C: O(1)
pub(crate) fn attr_time(sec: u64, nsec: u32) -> Timespec64 {
    Timespec64 { sec: sec as i64, nsec: nsec.min(NSEC_PER_SEC - 1) }
}

pub fn build_inode(conn: &Arc<FuseConn>, nodeid: u64, attr: &Attr) -> InodeRef {
    let atime = attr_time(attr.atime, attr.atimensec);
    let mtime = attr_time(attr.mtime, attr.mtimensec);
    let ctime = attr_time(attr.ctime, attr.ctimensec);
    if let Some(existing) = conn.cached_inode(nodeid) {
        // Refresh the volatile size/nlink so a re-lookup reflects the daemon.
        existing.set_size(attr.size);
        if attr.nlink != 0 { existing.set_nlink(attr.nlink); }
        // Linux `fuse_change_attributes_common` refreshes the times on every
        // attr refresh, not only at first build.
        let _ = existing.set_times(Some(atime), Some(mtime), ctime);
        return existing;
    }
    let ino = if attr.ino != 0 { attr.ino } else { nodeid };
    let inode = InodeBuilder::new(ino, attr.mode, Arc::new(FuseInodeOps), Arc::new(FuseFileOps))
        .size(attr.size)
        .nlink(if attr.nlink != 0 { attr.nlink } else { 1 })
        .owner(attr.uid, attr.gid)
        .rdev(attr.rdev)
        .times(atime, mtime, ctime)
        .private(Arc::new(FuseInodeData { conn: conn.clone(), nodeid }))
        .build();
    conn.cache_inode(nodeid, &inode);
    inode
}

/// `struct fuse_conn`'s `vfs::fs::FileSystem` face — the mounted instance. A
/// register-only backend: namespace mutations default to `Erofs` from the trait
/// (write path is out of scope); the read path lives on the inodes' `i_op`/
/// `i_fop`. # C: O(1)
pub struct FuseFs {
    conn: Arc<FuseConn>,
    root: InodeRef,
    options: String,
    name: String,
}

impl FuseFs {
    /// The shared channel (for tests / introspection). # C: O(1)
    pub fn conn(&self) -> &Arc<FuseConn> { &self.conn }
    /// The root inode (nodeid 1). # C: O(1)
    pub fn root_inode(&self) -> InodeRef { self.root.clone() }
}

/// `super_operations` for a mounted fuse instance. Exists for one hook:
/// `umount_begin`. Everything else matches what the generic pseudo-fs vtable
/// reported before, so `statfs(2)` on a fuse mount is unchanged.
pub struct FuseSuperOps {
    conn: Arc<FuseConn>,
    options: String,
}

impl FuseSuperOps {
    /// # C: O(1)
    pub fn new(conn: Arc<FuseConn>, options: String) -> Self { Self { conn, options } }
}

impl SuperOps for FuseSuperOps {
    /// # C: O(1)
    fn statfs(&self) -> KResult<SbStatFs> {
        Ok(SbStatFs { f_type: FUSE_SUPER_MAGIC, f_bsize: FUSE_BLKSIZE, ..Default::default() })
    }
    /// # C: O(1)
    fn show_options(&self) -> String { self.options.clone() }
    /// `s_op->umount_begin` — `umount2(MNT_FORCE)` on a fuse mount whose daemon
    /// is wedged or gone. Aborting the connection completes every queued request
    /// with `-ENOTCONN` and wakes its blocked caller, so the references pinning
    /// the mount are released and the unmount can proceed; a daemon still
    /// reading the channel gets `ENODEV`. Without this hook the mount stayed
    /// busy forever and MNT_FORCE meant nothing. # C: O(N_pending)
    fn umount_begin(&self, _sb: &SuperBlock) { self.conn.abort(); }
}

impl FileSystem for FuseFs {
    /// # C: O(1)
    fn name(&self) -> &str { &self.name }
    /// `FUSE_SUPER_MAGIC` — statfs `f_type`. # C: O(1)
    fn magic(&self) -> u64 { FUSE_SUPER_MAGIC }
    /// # C: O(1)
    fn block_size(&self) -> u32 { FUSE_BLKSIZE }
    /// Mount root = the nodeid-1 inode. # C: O(1)
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
    /// `/proc/mounts` options tail — the daemon channel is opaque. # C: O(1)
    fn show_options(&self) -> String { self.options.clone() }
    /// # C: O(1)
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> {
        Some(Arc::new(FuseSuperOps::new(self.conn.clone(), self.show_options())))
    }
}

/// Build a `FuseFs` over an already-resolved `/dev/fuse` channel `conn`. Fires
/// the mandatory `FUSE_INIT` (non-blocking — the reply is processed
/// asynchronously by the daemon's channel writes) and builds the root inode from
/// `rootmode` (the mount's `rootmode=` option, an `S_IF*|perm` word). # C: O(1)
pub fn build_fuse_fs(conn: Arc<FuseConn>, opts: &MountOpts) -> Arc<FuseFs> {
    conn.set_max_read(opts.max_read);
    conn.send_init();
    let root_attr = Attr {
        ino: proto::FUSE_ROOT_ID,
        mode: opts.rootmode,
        nlink: 2, uid: opts.user_id, gid: opts.group_id, blksize: FUSE_BLKSIZE, ..Default::default()
    };
    let root = build_inode(&conn, proto::FUSE_ROOT_ID, &root_attr);
    let name = opts.subtype.as_ref().map_or_else(
        || String::from("fuse"),
        |subtype| alloc::format!("fuse.{subtype}"),
    );
    Arc::new(FuseFs { conn, root, options: opts.show_options(), name })
}

/// Parsed FUSE mount options. # C: O(1)
pub struct MountOpts {
    pub rootmode: u32,
    pub user_id: u32,
    pub group_id: u32,
    pub default_permissions: bool,
    pub allow_other: bool,
    pub max_read: u32,
    pub subtype: Option<String>,
}

impl MountOpts {
    fn show_options(&self) -> String {
        let mut out = alloc::format!(",user_id={},group_id={}", self.user_id, self.group_id);
        if self.default_permissions { out.push_str(",default_permissions"); }
        if self.allow_other { out.push_str(",allow_other"); }
        if self.max_read != u32::MAX {
            use core::fmt::Write;
            let _ = write!(out, ",max_read={}", self.max_read);
        }
        out
    }
}

/// Encode a name as a NUL-terminated FUSE request body operand (LOOKUP /
/// path-op names are NUL-terminated on the wire). # C: O(name)
pub fn name_body(name: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(name.len() + 1);
    b.extend_from_slice(name.as_bytes());
    b.push(0);
    b
}
