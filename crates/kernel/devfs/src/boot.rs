//! Boot-time devfs population + the synthetic directory inode. The
//! built-in pseudo-devices (null/zero/full/kmsg/random + the std fd
//! symlinks) and the directory overlay live here; the console/tty nodes
//! self-register from the `console` crate (docs/56 self-registration).
use alloc::sync::Arc;
use vfs::{FileType, InodeRef};
use crate::register;
use core::sync::atomic::{AtomicPtr, Ordering};
/// Directory-overlay hook: emits real on-disk children (the rootfs) under a
/// prefix, so synthetic /dev dirs overlay ext4 without devfs depending on a
/// filesystem driver (would cycle devfs->ext4->block->cgroup->devfs). The
/// kernel installs an ext4 adapter at boot (docs/56).
static DIR_OVERLAY: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
type OverlayFn = fn(&[u8], &mut dyn FnMut(&[u8], FileType));
/// Install the rootfs directory-overlay adapter. Boot, once.
/// # C: O(1)
pub fn set_dir_overlay(f: OverlayFn) { DIR_OVERLAY.store(f as *mut (), Ordering::Release); }
/// Emit on-disk ext4 children under `prefix` via the installed adapter.
/// Called by `DevDir::readdir` to merge real entries with synthetic ones.
/// # C: O(N ext4 children)
pub(crate) fn dir_overlay(prefix: &[u8], emit: &mut dyn FnMut(&[u8], FileType)) {
    let p = DIR_OVERLAY.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: p was stored from an OverlayFn via set_dir_overlay.
    let f: OverlayFn = unsafe { core::mem::transmute(p) };
    f(prefix, emit);
}


/// Register the built-in pseudo-device nodes + the synthetic directory
/// overlay. Boot, once (idempotent — re-registration overwrites).
/// # C: O(N nodes)
pub fn populate_defaults() {
    // /sys/fs/cgroup is the cgroupfs mount point — it has no registered leaves,
    // so create the dir chain explicitly or the mount can't be walked to.
    crate::register_dir("/sys/fs/cgroup");
    crate::register_dir("/sys/fs/bpf");
    crate::register_dir("/sys/fs/pstore");
    crate::register_dir("/sys/kernel/security");
    // /dev/shm is the POSIX-shm tmpfs mount point (devtmpfs ships it); create
    // the underlay dir so the boot tmpfs mount resolves its mountpoint dentry
    // (the mount engine takes the walked dentry, no path-string resolve).
    crate::register_dir("/dev/shm");
    register("/dev/null",    Arc::new(crate::misc::NullInode)   as InodeRef);
    register("/dev/kmsg",    Arc::new(crate::misc::KmsgInode)   as InodeRef);
    register("/dev/zero",    Arc::new(crate::misc::ZeroInode)   as InodeRef);
    register("/dev/full",    Arc::new(crate::misc::FullInode)   as InodeRef);
    let rand: InodeRef = Arc::new(crate::misc::RandomInode);
    register("/dev/random",  Arc::clone(&rand));
    register("/dev/urandom", rand);
    let sym = |target: &'static [u8], ino: u64| -> InodeRef {
        Arc::new(crate::misc::SymlinkInode { target, ino }) as InodeRef
    };
    register("/dev/stdin",  sym(b"/proc/self/fd/0", 0x2000_0010));
    register("/dev/stdout", sym(b"/proc/self/fd/1", 0x2000_0011));
    register("/dev/stderr", sym(b"/proc/self/fd/2", 0x2000_0012));
    register("/dev/fd",     sym(b"/proc/self/fd",   0x2000_0013));
    // Intermediate directories (/, /dev, /sys, /sys/devices/system/cpu/cpu0,
    // …) are now auto-created as real `tree::DevDir`s as their leaf children
    // register — no synthetic prefix-scan inodes needed. The CPU topology
    // dirs (/sys/devices/system/cpu/cpuN/online) materialize when sysfs
    // registers the cpu leaves; readdir enumerates the real BTreeMap.
}
