// Which filesystem the root device is mounted as, and mounting it.
//
// Linux's `mount_block_root` walks a candidate list and mounts the root as the
// first type that accepts the device; `rootfstype=` narrows and orders that
// list. The ORDER is decided in `cmdline::root_fstype`, which is ungated and
// hosted-tested. This module owns only the attempt: open the device as each
// candidate in turn and hand back the filesystem that opened, so the boot
// mount graph can graft it at `/` through the same `register_typed` every
// other mount uses.
//
// ext4 keeps its extra step. Its free-function root API (`ext4::rootfs`) is
// what the journal commit timer, the frame store and the quota hooks reach
// through, so the ext4 candidate publishes that singleton as well as returning
// the VFS filesystem. A squashfs root publishes nothing: it is immutable, so
// there is no journal to commit and no writable state to reach.

use alloc::string::String;
use alloc::sync::Arc;

use crate::kmain::entry::step;

/// The mounted root: the filesystem to graft at `/` and the registered type
/// name to graft it under.
pub struct MountedRoot {
    pub fs: Arc<dyn vfs::fs::FileSystem>,
    pub fstype: &'static str,
}

/// The filesystem holding a volatile root's upper and work directories, kept
/// for the life of the kernel. The overlay's layer stack holds inodes of this
/// filesystem, not the filesystem itself, and the root is never unmounted.
#[cfg(target_os = "oxide-kernel")]
static ROOT_UPPER: sync::Spinlock<Option<Arc<fs::tmpfs::TmpfsFs>>, sync::TaskList> =
    sync::Spinlock::new(None);

/// Root filesystem types this kernel can mount a block root as.
const EXT4: &[u8] = b"ext4";
const SQUASHFS: &[u8] = b"squashfs";

/// Mode of a volatile root's upper and work directories. They are the overlay's
/// private roots, not paths anything else walks, so they carry the directory
/// mode a filesystem root carries.
#[cfg(target_os = "oxide-kernel")]
const UPPER_MODE: u32 = 0o755;

/// Mount `dev` as the first candidate type that accepts it.
///
/// Candidates come from `rootfstype=` when the boot line carries one and from
/// `cmdline::root_fstype::DEFAULT_CANDIDATES` otherwise. A candidate this
/// kernel does not know is skipped rather than fatal, so a boot line naming a
/// type alongside one we have still boots.
///
/// # SAFETY: caller is the boot path post-allocator-up, before any other CPU
/// can observe the root.
/// # C: O(candidates x mount cost)
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn mount_root_device(spec: &[u8], dev: Arc<dyn block::BlockDevice>) -> Option<MountedRoot> {
    let line = crate::boot_cmdline::get();
    let buf;
    let candidates: &[&[u8]] = match cmdline::root_fstype::root_fstypes_in(line) {
        Some((list, n)) => { buf = list; &buf[..n] }
        None => cmdline::root_fstype::DEFAULT_CANDIDATES,
    };
    for ty in candidates {
        // SAFETY: forwarded boot-entry contract — each attempt runs before the
        // root is published, so a candidate that fails leaves nothing visible.
        let Some(root) = (unsafe { try_mount_as(ty, spec, &dev) }) else { continue };
        return Some(match cmdline::root_fstype::root_overlay_in(line) {
            Some(cmdline::root_fstype::RootOverlay::Tmpfs) =>
                step("rootovl::volatile", || volatile_over(&root)).unwrap_or(root),
            None => root,
        });
    }
    None
}

/// Compose an in-memory writable layer over the mounted root.
///
/// An immutable root carries no writable `/etc` or `/var`, which an init
/// system needs before it starts anything, so a live image pairs the image
/// with a tmpfs and mounts the overlay of the two. Linux does this in the
/// initramfs; there is none here, so the boot path does it.
///
/// A composition that fails leaves the root as it was rather than failing the
/// boot: an image mounted read-only reaches a shell, and an unbootable kernel
/// does not.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
fn volatile_over(root: &MountedRoot) -> Option<MountedRoot> {
    let lower = vfs::fs::FileSystem::root(&*root.fs)?;
    let upper_fs = fs::tmpfs::TmpfsFs::new(String::from("rootovl"));
    let base = upper_fs.root_inode();
    let ctx = vfs::inode_ops::CreateCtx::root();
    let upper = base.i_op().mkdir(&base, "upper", UPPER_MODE, &ctx).ok()?;
    let work = base.i_op().mkdir(&base, "work", UPPER_MODE, &ctx).ok()?;
    let ovl = overlayfs::volatile_over(lower, upper, work).ok()?;
    *ROOT_UPPER.lock() = Some(upper_fs);
    Some(MountedRoot { fs: ovl, fstype: overlayfs::FS_NAME })
}

/// One candidate attempt. `None` when this kernel has no such root filesystem
/// or the device does not carry one.
/// # SAFETY: see [`mount_root_device`].
/// # C: O(mount cost)
#[cfg(target_os = "oxide-kernel")]
unsafe fn try_mount_as(ty: &[u8], spec: &[u8], dev: &Arc<dyn block::BlockDevice>) -> Option<MountedRoot> {
    match ty {
        EXT4 => {
            // SAFETY: forwarded boot-entry contract, which is what the ext4
            // root publisher requires: single CPU, nothing has seen ROOT.
            let opened = step("ext4::rootfs::init_from_dev",
                || unsafe { ext4::rootfs::init_from_dev(dev.clone()) });
            match opened {
                Ok(()) => Some(MountedRoot { fs: Arc::new(ext4::rootfs::Ext4RootfsFs), fstype: "ext4" }),
                Err(_) => None,
            }
        }
        SQUASHFS => {
            let source = core::str::from_utf8(spec).unwrap_or("root");
            match step("squashfs::SquashFs::open", || squashfs::SquashFs::open(dev.clone(), source)) {
                Ok(fs) => Some(MountedRoot { fs, fstype: "squashfs" }),
                Err(_) => None,
            }
        }
        _ => None,
    }
}
