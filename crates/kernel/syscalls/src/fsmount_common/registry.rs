#![cfg(target_os = "oxide-kernel")]

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;

use core::sync::atomic::AtomicU64;
use sync::{Spinlock, TaskList as LockClass};
use vfs::FileType;

#[path = "registry_register.rs"]
mod register;

pub(crate) static NEXT_FSCTX_INO: AtomicU64 = AtomicU64::new(0x4600_0000);

/// # C: O(1)
/// Resolve a `source=` pathname to the block device it names. Shared by
/// every filesystem that requires one.
fn resolve_block_source(
    source: &str,
    access: u32,
) -> vfs::KResult<(Arc<dyn block::BlockDevice>, Option<u64>)> {
    let vp = crate::pathresolve::resolve_path_raw(source, false)?;
    if vp.inode.file_type() != FileType::BlockDev {
        return Err(vfs::VfsError::Enotblk);
    }
    if !vfs::may_open_dev(vp.mnt_id) {
        return Err(vfs::VfsError::Eacces);
    }
    let rdev = vp.inode.rdev();
    // Linux `lookup_bdev` checks nodev but not block-inode DAC.
    // `bdev_file_open_by_dev` then checks device policy before ENXIO.
    vfs::device_permission(FileType::BlockDev, rdev, access)?;
    let disk = block::registry::by_dev(rdev).ok_or(vfs::VfsError::Enxio)?;
    Ok((disk.dev.clone(), Some(rdev as u64)))
}

const SECURITYFS_MAGIC: u64 = 0x7363_6673;
/// `SELINUX_MAGIC` — the mandatory-access-control interface at `/sys/fs/selinux`.
const SELINUXFS_MAGIC: u64 = selinuxfs::SELINUX_MAGIC;
const EFIVARFS_MAGIC: u64 = 0xde5e_81e4;
const PSTOREFS_MAGIC: u64 = 0x6165_676C;
const BPF_FS_MAGIC: u64 = 0xcafe_4a11;
/// `FUSE_CTL_SUPER_MAGIC` — the fuse CONTROL
/// filesystem mounted at `/sys/fs/fuse/connections`. Distinct from
/// `FUSE_SUPER_MAGIC` (0x65735546) by one nibble; reporting the latter makes
/// every `statfs`-based fuse probe misidentify the control mount.
const FUSE_CTL_MAGIC: u64 = 0x6573_5543;
const FUSE_SUPER_MAGIC: u64 = fs::fuse::FUSE_SUPER_MAGIC;
const MQUEUE_MAGIC: u64 = 0x1980_0202;
const EXT4_MAGIC: u64 = 0xef53;
const CGROUP2_MAGIC: u64 = cgroup::CGROUP2_SUPER_MAGIC;
const DEVTMPFS_MAGIC: u64 = vfs::uapi::TMPFS_SUPER_MAGIC;
const TMPFS_MAGIC: u64 = vfs::uapi::TMPFS_SUPER_MAGIC;
const RAMFS_MAGIC: u64 = fs::tmpfs::RAMFS_MAGIC;
const PROC_SUPER_MAGIC: u64 = 0x9fa0;
const SYSFS_MAGIC: u64 = 0x6265_6572;
const DEBUGFS_MAGIC: u64 = 0x6462_6720;
const TRACEFS_MAGIC: u64 = 0x7472_6163;
const CONFIGFS_MAGIC: u64 = 0x6265_6570;
const AUTOFS_SUPER_MAGIC: u64 = 0x0187;
const BINFMTFS_MAGIC: u64 = 0x4249_4e4d;
const SQUASHFS_MAGIC: u64 = squashfs::SQUASHFS_SUPER_MAGIC;

static FS_TYPES_REGISTERED: Spinlock<bool, LockClass> = Spinlock::new(false);

/// # C: O(N) once.
pub fn ensure_filesystems_registered() {
    let mut done = FS_TYPES_REGISTERED.lock();
    if *done { return; }
    register::register_filesystems();
    *done = true;
}

/// Which types publish a parameter table, and why the rest do not.
///
/// A table is a promise about a filesystem's WHOLE option surface, enforced on
/// both entry points: `mount(2)` now builds an `FsContext` and admits its
/// comma-separated blob through the same verdict `fsconfig(2)` applies, so a
/// key absent from the table fails the real mount, not merely the probe.
///
/// A table lists what the reference accepts, in full, INCLUDING a name that is
/// answered somewhere other than the mount. Omitting a name would make a mount
/// the reference accepts fail outright, which is worse than listing it; where a
/// listed name is answered elsewhere, the registration below says where.
///
/// `Some(&[])` is a real declaration and not a default: the VFS admits every
/// key against it, finds none, and reports the parameter unknown — exactly what
/// the reference does for a type whose context operations carry no
/// `parse_param` at all. `proc`, `sysfs`, `configfs`, `securityfs`, `fusectl`,
/// `mqueue` and `binfmt_misc` are those types.
///
/// Every registered type now publishes a table, so an option no filesystem here
/// implements fails the mount instead of being accepted and dropped.
///
/// `pstore` publishes a table and is still the most permissive type here,
/// because its reference parse SWALLOWS every negative answer — an unknown
/// key, a value that is not a number, a bare word where a number belongs. The
/// table is what makes a valid `kmsg_bytes=` reach the capture; the leniency
/// is enforced by pstore's own admission, not by omitting the table.
/// The calling task's cgroup-namespace root path, for `nsdelegate`.
///
/// The cgroup crate is a leaf with no `sched`/`nscg` dependency (the same
/// reason its signal and freeze hooks are installed rather than called), so the
/// live lookup lives here and the DECISION it feeds — is this cgroup inside
/// that root — lives in the cgroup crate where it is hosted-tested.
/// # C: O(1)
fn cgroup_ns_root_of_caller() -> Option<alloc::string::String> {
    let cur = sched::live::current()?;
    let ns = cur.namespace_owner(namespace_identity::NamespaceKind::Cgroup)?;
    Some(nscg::cgroup_ns::root_of(&ns))
}

/// Is the caller mounting from the initial user namespace?
///
/// Stands for `capable(CAP_SYS_ADMIN)` at the point overlayfs asks it: the
/// mount permission check has already run, so what is left to decide is
/// whether this caller may write the private markers into the `trusted.`
/// namespace, and only a mount from the initial namespace may.
/// # C: O(1)
fn in_initial_user_ns() -> bool {
    let initial = namespace_identity::initial(namespace_identity::NamespaceKind::User);
    match sched::live::current()
        .and_then(|t| t.namespace_owner(namespace_identity::NamespaceKind::User)) {
        Some(ns) => namespace_identity::NamespaceRef::ptr_eq(&ns, &initial),
        // No task: an in-kernel mount, which runs with full privilege.
        None => true,
    }
}

/// The caller's filesystem identity — the id a 9P mount attaches under, and
/// therefore the identity the SERVER checks every operation on this mount
/// against. Not the real uid: `setfsuid(2)` exists precisely so a service can
/// act on a filesystem as somebody else, and attaching as the real uid would
/// ignore that. An in-kernel mount has no task and attaches as root.
/// # C: O(1)
fn caller_fsuid() -> u32 { caller_fsids().0 }

/// The caller's filesystem uid and gid together, for a mount that reports both
/// to its server. # C: O(1)
fn caller_fsids() -> (u32, u32) {
    use core::sync::atomic::Ordering;
    match sched::live::current() {
        Some(t) => (t.security.creds.fsuid.load(Ordering::Acquire), t.security.creds.fsgid.load(Ordering::Acquire)),
        None => (0, 0),
    }
}
