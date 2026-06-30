//! Boot-time devfs population + the synthetic directory inode. The
//! built-in pseudo-devices (null/zero/full/kmsg/random + the std fd
//! symlinks) and the directory overlay live here; the console/tty nodes
//! self-register from the `console` crate (docs/56 self-registration).
use alloc::sync::Arc;
use vfs::{FileType, InodeRef, StaticFileInode};
use crate::register;
/// Directory-overlay hook (the ext4 rootfs merge under `/dev` + `/etc`) now
/// lives in `kernfs`; `PseudoDir::readdir` consults it directly. This thin
/// re-export keeps the kmain boot wiring (`devfs::boot::set_dir_overlay`)
/// unchanged. # C: O(1)
pub fn set_dir_overlay(f: fn(&[u8], &mut dyn FnMut(&[u8], FileType))) {
    kernfs::set_dir_overlay(f);
}


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

/// Generate a 32-hex-char `/etc/machine-id` body (16 random bytes), leaked
/// `'static` (lives for the kernel lifetime, like the boot UUIDs). # C: O(1)
fn machine_id_line() -> &'static [u8] {
    fn nib(n: u8) -> u8 { match n & 0x0f { v @ 0..=9 => b'0' + v, v => b'a' + (v - 10) } }
    let mut s = alloc::vec::Vec::with_capacity(33);
    for word in [crate::misc::lcg_next(), crate::misc::lcg_next()] {
        for b in word.to_le_bytes() { s.push(nib(b >> 4)); s.push(nib(b)); }
    }
    s.push(b'\n');
    alloc::boxed::Box::leak(s.into_boxed_slice())
}

/// Register the kernel/runtime-synthetic `/etc/*` overlay nodes into devfs's
/// own ns-0 tree. devfs owns `/etc` as an ext4-overlay subtree in the SAME
/// ns-keyed tree as `/dev` (root `overlay = true`), so userspace `/etc/*`
/// resolution merges synthetic + on-disk rootfs entries (the `/etc` writes used
/// to live in procfs `register_static_files`, D1d).
///
/// D23: only entries with NO real rootfs backing remain synthetic here.
/// Everything the rootfs image now ships as a real file — `os-release`,
/// `hostname`, `passwd`, `group`, `shadow`, `shells`, `profile`, `issue`,
/// `motd`, `hosts`, `nsswitch.conf`, `ld.so.cache` (built by
/// `tools/xtask/src/rootfs{,_etc}.rs`) — is intentionally NOT registered: a
/// kernel synthetic copy would incorrectly shadow the real distro/profile file
/// (the original `os-release` rationale, generalized to the whole set; e.g. the
/// synthetic `passwd` with only `root` masked the real multi-user `passwd`, and
/// an empty `ld.so.cache` masked the real one). The remaining entries are
/// genuinely kernel/runtime-provided with no on-disk source: `machine-id`
/// (random, like the boot UUIDs), `resolv.conf`/`localtime` (empty placeholders
/// rewritten at runtime by dhcpcd/tzdata), the static `services`/`protocols`
/// reference tables, and `ld.so.conf`/`timezone`. Boot, once, at the same phase
/// `populate_defaults` runs. # C: O(N nodes)
pub fn register_etc_overlay() {
    register("/etc/machine-id", StaticFileInode::new(machine_id_line()) as InodeRef);
    register("/etc/resolv.conf", StaticFileInode::new(b"") as InodeRef);
    register("/etc/localtime", StaticFileInode::new(b"") as InodeRef);
    register("/etc/services", StaticFileInode::new(
        b"ssh\t\t22/tcp\nssh\t\t22/udp\nhttp\t\t80/tcp\nhttp\t\t80/udp\n\
https\t\t443/tcp\nhttps\t\t443/udp\ndomain\t\t53/tcp\ndomain\t\t53/udp\n") as InodeRef);
    register("/etc/protocols", StaticFileInode::new(
        b"ip\t0\tIP\nicmp\t1\tICMP\ntcp\t6\tTCP\nudp\t17\tUDP\n") as InodeRef);
    register("/etc/ld.so.conf",
        StaticFileInode::new(b"include /etc/ld.so.conf.d/*.conf\n") as InodeRef);
    register("/etc/timezone", StaticFileInode::new(b"UTC\n") as InodeRef);
}
