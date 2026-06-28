//! Boot-time devfs population + the synthetic directory inode. The
//! built-in pseudo-devices (null/zero/full/kmsg/random + the std fd
//! symlinks) and the directory overlay live here; the console/tty nodes
//! self-register from the `console` crate (docs/56 self-registration).
use alloc::sync::Arc;
use vfs::{FileType, InodeRef};
use crate::register;
/// Directory-overlay hook (the ext4 rootfs merge under `/dev` + `/etc`) now
/// lives in `kernfs`; `PseudoDir::readdir` consults it directly. This thin
/// re-export keeps the kmain boot wiring (`devfs::boot::set_dir_overlay`)
/// unchanged. # C: O(1)
pub fn set_dir_overlay(f: fn(&[u8], &mut dyn FnMut(&[u8], FileType))) {
    kernfs::set_dir_overlay(f);
}


/// Register the built-in pseudo-device nodes + the synthetic directory
/// overlay. Boot, once (idempotent — re-registration overwrites).
/// # C: O(N nodes)
pub fn populate_defaults() {
    // The `/sys/*` mount-point dirs (cgroup/bpf/pstore/security/tracing/debug)
    // are created in sysfs's OWN tree by `sysfs::init` (D1c) — devfs no longer
    // writes into the `/sys` subtree.
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
