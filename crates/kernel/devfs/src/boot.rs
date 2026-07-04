//! Boot-time devfs population + the synthetic directory inode. The
//! built-in pseudo-devices (null/zero/full/kmsg/random + the std fd
//! symlinks) live here; the console/tty nodes self-register from the
//! `console` crate (docs/56 self-registration). D19: `/etc` no longer
//! overlays the rootfs — its 7 runtime-synthetic files now ship as real
//! rootfs ext4 files (`tools/xtask/src/rootfs_etc.rs`), so devfs owns
//! `/dev` only and the directory-overlay machinery is gone.
use alloc::sync::Arc;
use vfs::InodeRef;
use crate::register;

/// Self-register a pseudo character device through `drv::try_device_add` (D27):
/// pushes a `drv::Device` (bus/dev_class `class`, addr/devname `name`) into the
/// device registry and fires the devtmpfs hook → `/dev/<name>` minted from the
/// `factory` (preserving the exact bespoke inode). `dt` is the `(major, minor)`
/// metadata. Repeated boot/test population leaves the already-registered model
/// device in place instead of publishing a duplicate bus identity.
/// # C: O(N_devices)
fn add_pseudo_dev(class: &'static str, name: &str, dt: (u32, u32), factory: drv::NodeFactory) -> drv::KResult<()> {
    use alloc::string::String;
    match drv::try_device_add(Arc::new(
        drv::Device::new(class, String::from(name), 0, 0, 0)
            .with_devnode(class, String::from(name), Some(dt))
            .with_node_factory(factory))) {
        Ok(_) => Ok(()),
        Err(drv::Error::Busy) => {
            if drv::devices().iter().any(|d| {
                d.bus == class
                    && d.addr == name
                    && d.dev_class == class
                    && d.devname.as_deref() == Some(name)
                    && d.dev_t == Some(dt)
                    && d.node_factory.is_some()
            }) {
                Ok(())
            } else {
                Err(drv::Error::Busy)
            }
        }
        Err(e) => Err(e),
    }
}

/// Register the built-in pseudo-device nodes + the synthetic directory
/// overlay. Boot, once (idempotent — re-registration overwrites).
/// # C: O(N nodes)
pub fn try_populate_defaults() -> drv::KResult<()> {
    // The `/sys/*` mount-point dirs (cgroup/bpf/pstore/security/tracing/debug)
    // are created in sysfs's OWN tree by `sysfs::init` (D1c) — devfs no longer
    // writes into the `/sys` subtree.
    // /dev/shm is the POSIX-shm tmpfs mount point (devtmpfs ships it); create
    // the underlay dir so the boot tmpfs mount resolves its mountpoint dentry
    // (the mount engine takes the walked dentry, no path-string resolve).
    crate::register_dir("/dev/shm");
    // /dev/mqueue + /dev/pts mount-point underlay dirs (POSIX mqueue + devpts).
    // D17: with the ext4 overlay-union off, these mount-point dirs must be real
    // devfs dirs (the empty rootfs `/dev` never provided them anyway). /dev/pts
    // is also register_dir'd by `devpts::init`; idempotent. /dev/shm above.
    crate::register_dir("/dev/mqueue");
    crate::register_dir("/dev/pts");
    // device-model Stage C (D27): built-in pseudo char devices self-register
    // through `drv::try_device_add` so ONE registration drives the device model +
    // /dev. `node_factory` mints the bespoke inode with the correct fops/rdev.
    // bus "mem"/"misc" is ignored by pci/virtio sysfs synthesis. dev_t is the
    // standard mem major/minor metadata. Linux exposes random as 1:8 and
    // urandom as 1:9, so publish separate device identities even though both
    // use the same random file implementation.
    add_pseudo_dev("mem", "null", (1, 3),  Arc::new(|| crate::misc::make_null_inode()))?;
    add_pseudo_dev("mem", "kmsg", (1, 11), Arc::new(|| crate::misc::make_kmsg_inode()))?;
    add_pseudo_dev("mem", "zero", (1, 5),  Arc::new(|| crate::misc::make_zero_inode()))?;
    add_pseudo_dev("mem", "full", (1, 7),  Arc::new(|| crate::misc::make_full_inode()))?;
    add_pseudo_dev("mem", "random",  (1, 8), Arc::new(|| crate::misc::make_random_inode()))?;
    add_pseudo_dev("mem", "urandom", (1, 9), Arc::new(|| crate::misc::make_urandom_inode()))?;
    add_pseudo_dev("misc", "autofs", (10, 235), Arc::new(|| crate::misc::make_autofs_inode()))?;
    let sym = |target: &'static [u8], ino: u64| -> InodeRef {
        crate::misc::make_symlink_inode(target, ino)
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
    Ok(())
}

/// Register the built-in pseudo-device nodes for the boot path. Pseudo-device
/// conflicts are fatal at boot, but tests and staged init can use the fallible
/// form above to prove rollback/error behavior.
/// # C: O(N nodes)
pub fn populate_defaults() {
    if let Err(e) = try_populate_defaults() {
        panic!("devfs pseudo device registration failed: {:?}", e);
    }
}
