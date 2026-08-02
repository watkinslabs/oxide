// The ONE place a pty endpoint inode is constructed, plus the `/dev/ptmx`
// nodes. Every endpoint gets its `PtyEndpointData` here, which is what
// `crate::identity` resolves against — a pty inode built anywhere else would
// be invisible to every ioctl and ctty path, by design.

use alloc::format;
use alloc::sync::Arc;

use vfs::{FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult, VfsError};
use vfs::{default_inode_ops, mk_mode};

use crate::ids;
use crate::identity::PtyEndpointData;
use crate::pair::{self, LockedPair};

const PTY_MASTER_MODE: u16 = 0o666;
const PTY_SLAVE_MODE: u16 = 0o620;

/// The pty `file_operations` vectors. Kernel-only: they run the job-control
/// gate and the yield-block read loop, which live in `tty::jobctl::check` /
/// `sched::live`. A host build of this crate builds the same inodes with the
/// generic vector — identity never consults `f_op`, `i_private` carries it.
#[cfg(target_os = "oxide-kernel")]
fn master_fops() -> Arc<dyn FileOps> { Arc::new(crate::fileops::PtyMasterFileOps) }
#[cfg(target_os = "oxide-kernel")]
fn slave_fops() -> Arc<dyn FileOps> { Arc::new(crate::fileops::PtySlaveFileOps) }
#[cfg(not(target_os = "oxide-kernel"))]
fn master_fops() -> Arc<dyn FileOps> { vfs::default_file_ops() }
#[cfg(not(target_os = "oxide-kernel"))]
fn slave_fops() -> Arc<dyn FileOps> { vfs::default_file_ops() }

/// Build the master-side (`/dev/ptmx`) inode for `pair`. CharDev `0o666`,
/// rdev `0x8000|pts`, `i_private` = the endpoint binding. # C: O(1)
pub fn make_master_inode(pair: Arc<LockedPair>) -> InodeRef {
    endpoint_inode(pair, true, master_fops(), PTY_MASTER_MODE, ids::PTY_MASTER_RDEV_BASE)
}

/// Build the slave-side (`/dev/pts/<n>`) inode for `pair`, with the mount's
/// mode and ownership.
///
/// Linux `devpts_pty_new`: the node is `S_IFCHR | opts->mode`, owned by
/// `opts->setuid ? opts->uid : current_fsuid()` and likewise for the group. The
/// mode used to be the hardcoded `0o620` that systemd's `-o mode=620` happens
/// to ask for, so the value looked right while nothing read the option — a
/// mount asking for anything else got 0o620 anyway, and ownership was never
/// set at all. `fsuid`/`fsgid` are passed in because the creating task is live
/// state this module deliberately does not reach for.
/// # C: O(1)
pub fn make_slave_inode(pair: Arc<LockedPair>, opts: &crate::mount_opts::PtsMountOpts,
                        fsuid: u32, fsgid: u32) -> InodeRef {
    let (uid, gid) = opts.slave_owner(fsuid, fsgid);
    endpoint_inode_owned(pair, false, slave_fops(), opts.mode, ids::PTY_SLAVE_RDEV_BASE,
        Some((uid, gid)))
}

/// Shared endpoint construction: the number, the poll queue, and the
/// `PtyEndpointData` that makes the inode resolvable, all from ONE place.
/// # C: O(1)
fn endpoint_inode(
    pair: Arc<LockedPair>,
    master: bool,
    fops: Arc<dyn FileOps>,
    mode: u16,
    rdev_base: u32,
) -> InodeRef {
    endpoint_inode_owned(pair, master, fops, mode, rdev_base, None)
}

fn endpoint_inode_owned(
    pair: Arc<LockedPair>,
    master: bool,
    fops: Arc<dyn FileOps>,
    mode: u16,
    rdev_base: u32,
    owner: Option<(u32, u32)>,
) -> InodeRef {
    let ino = if master { pair.ino_master() } else { pair.ino_slave() };
    let rdev = rdev_base | (pair.pts_num() & 0xff);
    let subs = Arc::clone(if master { pair.master_subs() } else { pair.slave_subs() });
    let data = Arc::new(PtyEndpointData::new(Arc::clone(&pair), master));
    let b = InodeBuilder::new(ino, mk_mode(FileType::CharDev, mode), default_inode_ops(), fops)
        .fsid(ids::DEVPTS_FSID).rdev(rdev)
        .poll_subs_arc(subs)
        .private(data);
    let b = match owner { Some((u, g)) => b.owner(u, g), None => b };
    b.build()
}

/// Allocate a fresh PTY pair. Registers a slave inode at `/dev/pts/<n>` and
/// returns the master inode + pts number. `ENOSPC` once the pts index space is
/// exhausted (Linux `devpts_new_index` returns `-ENOSPC` past `pty.max`) —
/// wrapping instead would give two live ptys one `st_ino`.
/// # C: O(N_devfs_entries)
pub fn allocate_pair(fsuid: u32, fsgid: u32) -> KResult<(InodeRef, u32)> {
    let opts = crate::fs::devpts_fs().opts();
    let n = pair::next_index();
    if n >= ids::MAX_PTY_PAIRS { return Err(VfsError::Enospc); }
    // `max=` is this mount's pty ceiling (Linux allocates the index with
    // `ida_alloc_max(.., opts->max - 1)`), on top of the build-time bound above.
    if !opts.index_permitted(n) { return Err(VfsError::Enospc); }
    let pair = LockedPair::new(n);
    // Linux pty default: ICANON | ECHO | ISIG. tty::Pair::new starts raw; flip
    // to cooked here so userspace sees the expected default.
    pair.with_pair(|p| p.termios = tty::pty::default_termios());
    pair::publish(n, &pair);
    let master = make_master_inode(Arc::clone(&pair));
    let slave  = make_slave_inode(pair, &opts, fsuid, fsgid);
    // Mirror the slave into BOTH: (a) the devfs registry at `/dev/pts/<n>`
    // (the legacy fallback the boot /dev/pts setup still resolves through when
    // no real devpts is mounted), and (b) THIS instance's first-class devpts
    // root under the mount-relative name `<n>` (so a `mount -t devpts` at
    // /dev/pts resolves the same slave through its own SuperBlock). D36/D37.
    devfs::register_owned(format!("/dev/pts/{}", n), Arc::clone(&slave));
    crate::fs::devpts_fs().root_dir().insert_path(&format!("{}", n), slave);
    Ok((master, n))
}

/// `file_operations` for the `/dev/ptmx` sentinel — read/write return EIO
/// (the real factory work is the open-path special-case → `allocate_pair`).
pub(crate) struct PtmxSentinelFileOps;
impl FileOps for PtmxSentinelFileOps {
    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, _i: &Inode, _o: u64, _b: &mut [u8]) -> KResult<usize> { Err(VfsError::Eio) }
    fn write(&self, _i: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// Sentinel inode for `/dev/ptmx`. Its only role is to surface a CharDev type
/// at lookup-time — the open path detects this exact device number and routes
/// to `allocate_pair`. read/write on the sentinel itself return EIO (caller
/// used the wrong fd). Stays on `devfs::DEVFS_FSID`: the `/dev/ptmx` directory
/// entry lives in devtmpfs (`/dev`), only the allocated master/slave pair
/// inodes are on the devpts fs. It carries NO `PtyEndpointData` — it is not an
/// endpoint, and every pty resolver must decline it. # C: O(1)
pub fn make_ptmx_sentinel_inode() -> InodeRef {
    InodeBuilder::new(ids::PTMX_ROOT_INO, mk_mode(FileType::CharDev, PTY_MASTER_MODE),
                      default_inode_ops(), Arc::new(PtmxSentinelFileOps))
        .fsid(devfs::DEVFS_FSID).rdev(ids::PTMX_RDEV)
        .build()
}

/// The per-instance `ptmx` node Linux materialises INSIDE the devpts mount at
/// `/dev/pts/ptmx` (D37). Stamped with `DEVPTS_FSID` (it belongs to the devpts
/// fs, unlike the `/dev/ptmx` directory entry which lives in devtmpfs). The
/// working pty factory stays the `/dev/ptmx` open-path special-case
/// (preserving current semantics, `28§5`); this node exists so the devpts root
/// is structurally complete (it stats/lists as a 0o666 chardev). # C: O(1)
pub(crate) fn make_pts_ptmx_inode() -> InodeRef {
    InodeBuilder::new(ids::PTMX_MOUNT_INO, mk_mode(FileType::CharDev, PTY_MASTER_MODE),
                      default_inode_ops(), Arc::new(PtmxSentinelFileOps))
        .fsid(ids::DEVPTS_FSID).rdev(ids::PTMX_RDEV)
        .build()
}

#[cfg(test)]
mod slave_stamp_tests {
    use super::*;
    use crate::mount_opts::PtsMountOpts;

    fn opts(data: &str) -> PtsMountOpts {
        crate::mount_opts::opts_for_mount(data, &[]).expect("valid devpts options")
    }

    /// The mount's `mode=`/`gid=` land ON the slave node. This is the whole
    /// user-visible point: `mode=620,gid=5` is what makes a terminal writable
    /// by the `tty` group and nobody else.
    #[test]
    fn a_slave_node_carries_the_mounts_mode_and_group() {
        let pair = LockedPair::new(0);
        let i = make_slave_inode(pair, &opts("gid=5,mode=620"), 1000, 1000);
        assert_eq!(i.perm(), Some(0o620));
        assert_eq!(i.gid(), Some(5), "gid= from the mount");
        assert_eq!(i.uid(), Some(1000), "uid was not given, so the opener's");
    }

    /// A mount that says nothing gets the reference's default — 0600 owned by
    /// the opener — NOT the 0o620 that used to be hardcoded here.
    #[test]
    fn an_option_less_mount_gives_an_owner_only_slave() {
        let pair = LockedPair::new(1);
        let i = make_slave_inode(pair, &PtsMountOpts::default(), 1000, 1000);
        assert_eq!(i.perm(), Some(0o600), "DEVPTS_DEFAULT_MODE, not the old hardcode");
        assert_eq!((i.uid(), i.gid()), (Some(1000), Some(1000)));
    }

    /// An explicit `uid=`/`gid=` overrides the opener entirely, including to 0.
    #[test]
    fn explicit_ownership_overrides_the_opener() {
        let pair = LockedPair::new(2);
        let i = make_slave_inode(pair, &opts("uid=0,gid=0,mode=666"), 1000, 1000);
        assert_eq!((i.uid(), i.gid()), (Some(0), Some(0)));
        assert_eq!(i.perm(), Some(0o666));
    }

    /// It is still a character device on the devpts fs id with the pty's rdev —
    /// the stamping must not disturb the node's identity.
    #[test]
    fn the_node_is_still_a_pty_char_device() {
        let pair = LockedPair::new(3);
        let i = make_slave_inode(pair, &opts("mode=620"), 0, 0);
        assert_eq!(i.file_type(), FileType::CharDev);
        assert_eq!(i.fsid(), ids::DEVPTS_FSID);
        assert_eq!(i.rdev(), ids::PTY_SLAVE_RDEV_BASE | 3);
    }
}
