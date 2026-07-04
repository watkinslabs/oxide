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

/// Self-register a mem-class pseudo-device through `drv::device_add` (D27):
/// pushes a `drv::Device` (bus/dev_class "mem", addr/devname `name`) into the
/// device registry and fires the devtmpfs hook → `/dev/<name>` minted from the
/// `factory` (preserving the exact bespoke inode). `dt` is the `(major, minor)`
/// metadata. # C: O(1) amortised
fn add_mem_dev(name: &str, dt: (u32, u32), factory: drv::NodeFactory) {
    use alloc::string::String;
    drv::device_add(Arc::new(
        drv::Device::new("mem", String::from(name), 0, 0, 0)
            .with_devnode("mem", String::from(name), Some(dt))
            .with_node_factory(factory)));
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
    // /dev/mqueue + /dev/pts mount-point underlay dirs (POSIX mqueue + devpts).
    // D17: with the ext4 overlay-union off, these mount-point dirs must be real
    // devfs dirs (the empty rootfs `/dev` never provided them anyway). /dev/pts
    // is also register_dir'd by `devpts::init`; idempotent. /dev/shm above.
    crate::register_dir("/dev/mqueue");
    crate::register_dir("/dev/pts");
    // /dev/hugepages mount-point underlay (hugetlbfs; `dev-hugepages.mount`).
    // Without it, systemd's PER-SERVICE sandbox bind of `/dev/hugepages` failed
    // ENOENT → EXIT_NAMESPACE(226/265) → systemd multi-second retries on EVERY
    // sandboxed unit (upowerd/udisksd/accounts-daemon/logind/…) → boot crawled
    // to minutes and gdm timed out before rendering the greeter.
    crate::register_dir("/dev/hugepages");
    // device-model Stage C (D27): the standard mem char devices self-register
    // through `drv::device_add` (dev_class "mem") so ONE registration drives the
    // device model + /dev. `node_factory` mints the EXACT bespoke inode each used
    // before (same ino, fops, rdev) — byte-identical /dev. bus "mem" is ignored
    // by the pci/virtio /sys synthesis (no spurious /sys entry). dev_t is the
    // standard mem major/minor metadata. NOTE: /dev/urandom keeps the shared
    // /dev/random inode (rdev 1:8) as before; Linux assigns urandom 1:9 — that
    // pre-existing quirk is preserved here (conservative: identical /dev), not
    // "fixed", to avoid changing a node's identity in this migration.
    add_mem_dev("null", (1, 3),  Arc::new(|| crate::misc::make_null_inode()));
    add_mem_dev("kmsg", (1, 11), Arc::new(|| crate::misc::make_kmsg_inode()));
    add_mem_dev("zero", (1, 5),  Arc::new(|| crate::misc::make_zero_inode()));
    add_mem_dev("full", (1, 7),  Arc::new(|| crate::misc::make_full_inode()));
    let rand = crate::misc::make_random_inode();
    let rand2 = Arc::clone(&rand);
    add_mem_dev("random",  (1, 8), Arc::new(move || Arc::clone(&rand)));
    add_mem_dev("urandom", (1, 8), Arc::new(move || Arc::clone(&rand2)));
    // /dev/autofs (misc 10:235) keeps its direct registration: it is not a mem
    // device and is handled with the misc class elsewhere.
    register("/dev/autofs",  crate::misc::make_autofs_inode());
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
}
