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

/// Build the slave-side (`/dev/pts/<n>`) inode for `pair`. CharDev `0o620`,
/// rdev `0x8800|pts`. # C: O(1)
pub fn make_slave_inode(pair: Arc<LockedPair>) -> InodeRef {
    endpoint_inode(pair, false, slave_fops(), PTY_SLAVE_MODE, ids::PTY_SLAVE_RDEV_BASE)
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
    let ino = if master { pair.ino_master() } else { pair.ino_slave() };
    let rdev = rdev_base | (pair.pts_num() & 0xff);
    let subs = Arc::clone(if master { pair.master_subs() } else { pair.slave_subs() });
    let data = Arc::new(PtyEndpointData::new(Arc::clone(&pair), master));
    InodeBuilder::new(ino, mk_mode(FileType::CharDev, mode), default_inode_ops(), fops)
        .fsid(ids::DEVPTS_FSID).rdev(rdev)
        .poll_subs_arc(subs)
        .private(data)
        .build()
}

/// Allocate a fresh PTY pair. Registers a slave inode at `/dev/pts/<n>` and
/// returns the master inode + pts number. `ENOSPC` once the pts index space is
/// exhausted (Linux `devpts_new_index` returns `-ENOSPC` past `pty.max`) —
/// wrapping instead would give two live ptys one `st_ino`.
/// # C: O(N_devfs_entries)
pub fn allocate_pair() -> KResult<(InodeRef, u32)> {
    let n = pair::next_index();
    if n >= ids::MAX_PTY_PAIRS { return Err(VfsError::Enospc); }
    let pair = LockedPair::new(n);
    // Linux pty default: ICANON | ECHO | ISIG. tty::Pair::new starts raw; flip
    // to cooked here so userspace sees the expected default.
    pair.with_pair(|p| p.termios = tty::pty::default_termios());
    pair::publish(n, &pair);
    let master = make_master_inode(Arc::clone(&pair));
    let slave  = make_slave_inode(pair);
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
