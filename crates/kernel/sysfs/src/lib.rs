#![no_std]
#![cfg_attr(not(test), cfg(target_os = "oxide-kernel"))]
extern crate alloc;
#[cfg(test)]
extern crate std;
mod ids;

// Dynamic sysfs surface synthesised from live kernel state. v1
// scope: /sys/class/net (per-iface dir reflecting the netdev
// registry — address, mtu, operstate, type, flags, carrier, speed,
// duplex). Static /sys/kernel/* and tracefs entries still live as
// devfs key registrations; this module owns the entries whose
// content depends on runtime state.
//
// kp2: migrated off the deleted god-trait `vfs::Inode` to the concrete
// `struct Inode` + `i_op`/`i_fop` vtables. Each former `impl Inode for X`
// becomes a (ZST) ops object implementing `InodeOps` (lookup/readlink) and/or
// `FileOps` (read/write/iterate); the per-inode state moves into `i_private`
// (`XData`), and a `make_*_inode` constructor stamps mode + ops + data via
// `InodeBuilder`.

use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{default_file_ops, mk_mode, FileOps, FileType, Ino, Inode,
          InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

pub mod block;
pub mod bus;
pub mod char_class;
pub mod dmi;
pub mod drm;
pub mod input;
pub mod kernel;
pub mod kobject;
pub mod modules;
mod net_class;
pub mod net_stats;
pub mod root;
pub mod tty;
pub mod zram;

#[cfg(test)]
mod net_tests;

pub use root::{drop_cached, register, register_dir, sys_root, SYSFS_FSID};
#[cfg(test)]
pub(crate) use net_class::make_net_iface_inode;

// sysfs perm conventions (Linux): dirs r-xr-xr-x, attr files r--r--r--,
// writable attrs (`uevent`) rw-r--r--, symlinks rwxrwxrwx.
pub(crate) const DIR_PERM: u16 = 0o555;
pub(crate) const RO_PERM:  u16 = 0o444;
pub(crate) const RW_PERM:  u16 = 0o644;
pub(crate) const WO_PERM:  u16 = 0o200;
pub(crate) const LNK_PERM: u16 = 0o777;

/// Windowed copy of `body[off..]` into `buf` (the shared sysfs attr read). # C: O(n)
pub(crate) fn read_window(body: &[u8], off: u64, buf: &mut [u8]) -> usize {
    let off = off as usize;
    if off >= body.len() { return 0; }
    let avail = &body[off..];
    let n = avail.len().min(buf.len());
    buf[..n].copy_from_slice(&avail[..n]);
    n
}

/// First whitespace token of a uevent write = the action ("add"/"change"/…). # C: O(n)
pub(crate) fn uevent_action(b: &[u8]) -> &str {
    core::str::from_utf8(b).ok()
        .and_then(|s| s.split_whitespace().next())
        .filter(|a| !a.is_empty())
        .unwrap_or("change")
}

// ---- symlink leaf (fixed readlink target) ---------------------------------

/// A symlink leaf whose readlink target is a fixed byte string. Used by the
/// tty + net class dirs (`/sys/class/<class>/<if>` → canonical /sys/devices
/// path). udev/networkd readlink this to discover the bus path; subsequent
/// attribute reads go through the resolved /sys/devices/.../<attr> path which
/// the component walk follows transparently.
pub(crate) struct SymlinkData { pub target: Vec<u8> }

pub(crate) struct SymlinkOps;
impl InodeOps for SymlinkOps {
    fn readlink(&self, inode: &Inode) -> KResult<Vec<u8>> {
        let d = inode.private::<SymlinkData>().ok_or(VfsError::Einval)?;
        Ok(d.target.clone())
    }
}

/// Build a symlink inode (ino `0x5100_0080`) with a fixed readlink target. # C: O(1)
pub(crate) fn make_symlink_inode(target: Vec<u8>) -> InodeRef {
    make_symlink_inode_ino(target, ids::SYMLINK)
}

/// Build a symlink inode with an explicit inode number. # C: O(1)
pub(crate) fn make_symlink_inode_ino(target: Vec<u8>, ino: Ino) -> InodeRef {
    let size = target.len() as u64;
    InodeBuilder::new(ino, mk_mode(FileType::Symlink, LNK_PERM),
        Arc::new(SymlinkOps), default_file_ops())
        .size(size)
        .private(Arc::new(SymlinkData { target }))
        .build()
}

// ---- read-only owned-byte attribute file ----------------------------------

/// Per-inode body for a read-only sysfs attribute (Linux `attr->show` result).
pub(crate) struct BodyData { pub body: Vec<u8> }

/// `f_op` for a read-only attribute: windowed `read`, `write` → `EROFS`.
pub(crate) struct BodyFileOps;
impl FileOps for BodyFileOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<BodyData>().ok_or(VfsError::Einval)?;
        Ok(read_window(&d.body, off, buf))
    }
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

/// Build a read-only attribute inode serving `body`. Body is built at lookup
/// time so it reflects current state; read() serves windowed slices. # C: O(1)
pub fn make_body_inode(body: Vec<u8>, ino: Ino) -> InodeRef {
    let size = body.len() as u64;
    InodeBuilder::new(ino, mk_mode(FileType::Regular, RO_PERM),
        crate::kobject::attr_inode_ops(), Arc::new(BodyFileOps))
        .size(size)
        .private(Arc::new(BodyData { body }))
        .build()
}

pub(crate) struct VecFmt<'a>(pub(crate) &'a mut Vec<u8>);
impl<'a> core::fmt::Write for VecFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// Register the dynamic `/sys/class/net` directory. Called from the
/// procfs static-files init AFTER the network stack has registered
/// at least the loopback iface.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(1)
pub fn init() {
    // Mount-point dirs that other filesystems mount onto (cgroup2, bpf,
    // pstore, securityfs). They must exist as walkable dentries in sysfs's
    // own tree BEFORE those mounts attach (moved here from devfs::boot —
    // devfs can't depend on sysfs without a cycle). # C: O(1)
    register_dir("/sys/fs/cgroup");
    register_dir("/sys/fs/bpf");
    register_dir("/sys/fs/pstore");
    register_dir("/sys/kernel/security");
    // tracefs/debugfs mount points (content lives in tracefs's own roots).
    register_dir("/sys/kernel/tracing");
    register_dir("/sys/kernel/debug");
    register_dir("/sys/kernel/config");
    kernel::init();
    modules::init();
    register("/sys/class/net", net_class::make_sys_class_net_inode());
    register("/sys/devices/virtual/net", net_class::make_sys_devices_virtual_net_inode());
    #[cfg(target_os = "oxide-kernel")]
    net::netdev::set_remove_hook(net_class::invalidate_netdev_paths);
    register("/sys/class/tty", tty::make_sys_class_tty_inode());
    register("/sys/devices/virtual/tty", tty::make_sys_devices_virtual_tty_inode());
    bus::init();
    block::init();
    zram::init();
    char_class::init();
    drm::init();
    input::init();
    dmi::init();
}

/// `vfs::fs::FileSystem` impl mounted at `/sys`. Lookups consult sysfs's own
/// `kernfs::PseudoDir` tree (where /sys/kernel/*, /sys/devices/*, the dynamic
/// /sys/class/net inode live) and fall back to ENOENT.
pub struct SysfsFs;

/// Sysfs `f_type`/`s_magic`.
const SYSFS_MAGIC: u64 = 0x6265_6572;
/// `PAGE_SIZE` — sysfs statfs `f_bsize` (kernfs `s_blocksize = PAGE_SIZE`).
/// # C: O(1)
const PAGE_SIZE: u32 = hal::PAGE_SIZE_BYTES as u32;

/// `super_operations` for sysfs. sysfs is a zero-sized kernfs pseudo
/// filesystem: `statfs(2)` reports the magic + `PAGE_SIZE` block size and zero
/// block/inode counts (Linux `simple_statfs`, used by kernfs `kernfs_fill_super`).
struct SysfsSuperOps;
impl vfs::SuperOps for SysfsSuperOps {
    /// `simple_statfs`: f_type=SYSFS_MAGIC, f_bsize=PAGE_SIZE, all block/inode
    /// counts 0 (f_namelen=NAME_MAX is filled by the syscall layer). # C: O(1)
    fn statfs(&self) -> KResult<vfs::SbStatFs> {
        Ok(vfs::SbStatFs {
            f_type:  SYSFS_MAGIC,
            f_bsize: PAGE_SIZE,
            ..Default::default()
        })
    }
}

impl vfs::fs::FileSystem for SysfsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "sysfs" }
    /// Sysfs filesystem magic.
    /// # C: O(1)
    fn magic(&self) -> u64 { SYSFS_MAGIC }
    /// Sysfs superblocks carry `SB_I_NOEXEC | SB_I_NODEV`. Also the `required_iflags`
    /// `mount_too_revealing` demands of every `FS_USERNS_MOUNT_RESTRICTED`
    /// filesystem, which sysfs is. # C: O(1)
    fn s_iflags(&self) -> u64 { vfs::superblock::SB_I_USERNS_REQUIRED }
    /// Install zero-sized pseudo-fs statfs (`simple_statfs`) as this SB's `s_op`
    /// so `statfs(2)`/`df` report SYSFS_MAGIC + PAGE_SIZE, not the generic
    /// synthetic figures. # C: O(1)
    fn super_ops(&self) -> Option<Arc<dyn vfs::SuperOps>> { Some(Arc::new(SysfsSuperOps)) }
    /// Mount root = sysfs's OWN `kernfs::PseudoDir` (`SYS_ROOT`). The walk
    /// crosses into the sysfs mount and resolves `/sys/*` per-component via
    /// `PseudoDir::lookup` + the dynamic `SysClassNetOps::lookup`.
    /// # C: O(1)
    fn root(&self) -> Option<InodeRef> { sys_root().lookup_path("") }
    fn set_sb(&self, sb: alloc::sync::Weak<vfs::SuperBlock>) -> vfs::KResult<()> {
        sys_root().set_sb(sb.clone());
        root::record_super(sb);
        Ok(())
    }
}

/// Singleton accessor for the mount table.
/// # C: O(1)
pub fn instance() -> &'static dyn vfs::fs::FileSystem { &SysfsFs }
