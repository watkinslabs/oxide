#![no_std]
#![cfg_attr(not(test), cfg(target_os = "oxide-kernel"))]
extern crate alloc;
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

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{default_file_ops, default_inode_ops, mk_mode, DirContext, FileOps, FileType, Ino, Inode,
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
pub mod net_stats;
pub mod root;
pub mod tty;
pub mod zram;

#[cfg(test)]
mod net_tests;

pub use root::{drop_cached, register, register_dir, sys_root, SYSFS_FSID};

const ARPHRD_LOOPBACK: u16 = 772;
const ARPHRD_ETHER:    u16 =   1;

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

#[cfg(target_os = "oxide-kernel")]
fn snapshot_net_devs() -> Vec<(net::NetIfaceId, String, Arc<dyn net::NetDev>)> {
    let stack = net::sock::stack();
    stack.ifaces.snapshot_in_ns(0).into_iter().filter_map(|snap| {
        stack.ifaces.lookup_in_ns(snap.id, 0).map(|dev| (snap.id, snap.name, dev))
    }).collect()
}

#[cfg(not(target_os = "oxide-kernel"))]
fn snapshot_net_devs() -> Vec<(net::NetIfaceId, String, Arc<dyn net::NetDev>)> {
    Vec::new()
}

#[cfg(target_os = "oxide-kernel")]
fn lookup_net_ifindex(name: &str) -> u32 {
    net::sock::stack().ifaces.lookup_name(name).map(|(id, _)| id.raw()).unwrap_or(0)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn lookup_net_ifindex(_name: &str) -> u32 {
    0
}

#[cfg(target_os = "oxide-kernel")]
fn invalidate_netdev_paths(name: &str) {
    for path in ["/sys/class/net/", "/sys/devices/virtual/net/"] {
        let full = alloc::format!("{}{}", path, name);
        drop_cached(&full);
    }
}

// ---- /sys/class/net (directory of symlinks) -------------------------------

/// `/sys/class/net` directory. `iterate` enumerates
/// `net::sock::stack().ifaces` and emits each entry as a symlink per
/// docs/19§2 invariant 2 (`/sys/class/<class>/<name>` → `/sys/devices/
/// .../<name>`). `lookup(name)` returns a symlink whose readlink target is the
/// canonical devices path; the real attribute set lives under
/// `/sys/devices/virtual/net/<name>` and is served by the iface dir.
struct SysClassNetOps;
impl InodeOps for SysClassNetOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let snap = snapshot_net_devs();
        for (_, current, _) in snap.iter() {
            if current == name {
                let mut target = String::from("../../devices/virtual/net/");
                target.push_str(name);
                return Ok(make_symlink_inode(target.into_bytes()));
            }
        }
        Err(VfsError::Enoent)
    }
}
impl FileOps for SysClassNetOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let snap = snapshot_net_devs();
        let mut idx = ctx.pos as usize;
        while idx < snap.len() {
            let next = idx as u64 + 1;
            let name = &snap[idx].1;
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Symlink, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_sys_class_net_inode() -> InodeRef {
    InodeBuilder::new(ids::ROOT, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysClassNetOps), Arc::new(SysClassNetOps)).build()
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

// ---- /sys/devices/virtual/net (directory of iface dirs) -------------------

/// `/sys/devices/virtual/net` directory. Same iterate/lookup as the class dir
/// but returns the actual iface directory (the canonical home for per-iface
/// attributes).
struct SysDevicesVirtualNetOps;
impl InodeOps for SysDevicesVirtualNetOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let snap = snapshot_net_devs();
        for (_, current, dev) in snap.iter() {
            if current == name {
                return Ok(make_net_iface_inode(String::from(name), Arc::clone(dev)));
            }
        }
        Err(VfsError::Enoent)
    }
}
impl FileOps for SysDevicesVirtualNetOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let snap = snapshot_net_devs();
        let mut idx = ctx.pos as usize;
        while idx < snap.len() {
            let next = idx as u64 + 1;
            let name = &snap[idx].1;
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Directory, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_sys_devices_virtual_net_inode() -> InodeRef {
    InodeBuilder::new(ids::CLASS, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysDevicesVirtualNetOps), Arc::new(SysDevicesVirtualNetOps)).build()
}

// ---- /sys/class/net/<if> (per-iface attribute dir) ------------------------

/// Per-iface state (Linux `net_device` backref). # C: n/a
pub(crate) struct NetIfaceData {
    pub name: String,
    pub dev:  Arc<dyn net::NetDev>,
}

fn arphrd(name: &str) -> u16 {
    // No NetDev::kind() in v1 — infer from name. `lo` → loopback;
    // everything else (eth*, en*) treats as ARPHRD_ETHER.
    if name == "lo" { ARPHRD_LOOPBACK } else { ARPHRD_ETHER }
}

fn iface_body(d: &NetIfaceData, leaf: &str) -> Option<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(32);
    let hw = arphrd(&d.name);
    match leaf {
        "address" => {
            let m = d.dev.mac().0;
            let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut buf),
                format_args!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                    m[0], m[1], m[2], m[3], m[4], m[5]));
        }
        "broadcast" => {
            buf.extend_from_slice(b"ff:ff:ff:ff:ff:ff\n");
        }
        "mtu" => {
            let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut buf),
                format_args!("{}\n", d.dev.mtu()));
        }
        "operstate" => {
            // Linux: "up" / "down" / "unknown". Loopback reports
            // "unknown" (no carrier abstraction); real ifaces "up".
            buf.extend_from_slice(if hw == ARPHRD_LOOPBACK {
                b"unknown\n" } else { b"up\n" });
        }
        "type" => {
            let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut buf),
                format_args!("{}\n", hw));
        }
        "flags" => {
            // IFF_UP|IFF_BROADCAST|IFF_RUNNING|IFF_MULTICAST = 0x1003 for ether,
            // IFF_UP|IFF_LOOPBACK|IFF_RUNNING                = 0x49   for lo.
            buf.extend_from_slice(if hw == ARPHRD_LOOPBACK {
                b"0x49\n" } else { b"0x1003\n" });
        }
        "carrier" => {
            buf.extend_from_slice(b"1\n");
        }
        "speed" => {
            // Loopback returns -1 per Linux; ether reports 10000.
            buf.extend_from_slice(if hw == ARPHRD_LOOPBACK {
                b"-1\n" } else { b"10000\n" });
        }
        "duplex" => {
            buf.extend_from_slice(if hw == ARPHRD_LOOPBACK {
                b"unknown\n" } else { b"full\n" });
        }
        "ifindex" => {
            let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut buf),
                format_args!("{}\n", lookup_net_ifindex(&d.name)));
        }
        "tx_queue_len" => buf.extend_from_slice(b"1000\n"),
        "addr_len"     => buf.extend_from_slice(b"6\n"),
        "name_assign_type" => buf.extend_from_slice(b"4\n"),
        "dev_id"       => buf.extend_from_slice(b"0x0\n"),
        _ => return None,
    }
    Some(buf)
}

use kobject::{Attribute, AttrGroup, SysfsOps};

/// The `/sys/class/net/<if>` default attribute group (Linux `net_class_attrs`).
/// Read-only attributes plus the writable `uevent` trigger; `statistics` is a
/// subdirectory added separately (not a leaf attribute). # C: n/a
const NET_IFACE_ATTRS: &[Attribute] = &[
    Attribute { name: "address",          mode: RO_PERM },
    Attribute { name: "broadcast",        mode: RO_PERM },
    Attribute { name: "mtu",              mode: RO_PERM },
    Attribute { name: "operstate",        mode: RO_PERM },
    Attribute { name: "type",             mode: RO_PERM },
    Attribute { name: "flags",            mode: RO_PERM },
    Attribute { name: "carrier",          mode: RO_PERM },
    Attribute { name: "speed",            mode: RO_PERM },
    Attribute { name: "duplex",           mode: RO_PERM },
    Attribute { name: "ifindex",          mode: RO_PERM },
    Attribute { name: "tx_queue_len",     mode: RO_PERM },
    Attribute { name: "addr_len",         mode: RO_PERM },
    Attribute { name: "name_assign_type", mode: RO_PERM },
    Attribute { name: "dev_id",           mode: RO_PERM },
    Attribute { name: "uevent",           mode: RW_PERM },
];
static NET_IFACE_GROUP: AttrGroup = AttrGroup { attrs: NET_IFACE_ATTRS };

/// `sysfs_ops` for a net-iface kobject: `show` renders each attribute (the
/// `uevent` env or a `net_device` field via `iface_body`); `store` consumes a
/// `udevadm trigger` write to `uevent` by re-emitting the kobject uevent.
impl SysfsOps for NetIfaceData {
    fn show(&self, attr: &str) -> KResult<Vec<u8>> {
        if attr == "uevent" {
            let mut body: Vec<u8> = Vec::new();
            // A physical/ethernet NIC emits no DEVTYPE (only virtual net devices
            // — bridge/vlan/bond — carry one). The old empty `DEVTYPE=` was a
            // malformed non-Linux env entry.
            let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut body),
                format_args!("INTERFACE={}\nIFINDEX={}\n", self.name,
                    lookup_net_ifindex(&self.name)));
            return Ok(body);
        }
        iface_body(self, attr).ok_or(VfsError::Enoent)
    }
    fn store(&self, attr: &str, buf: &[u8]) -> KResult<usize> {
        if attr == "uevent" {
            let devpath = alloc::format!("/devices/virtual/net/{}", self.name);
            // No DEVTYPE for a physical/ethernet NIC (Linux emits it only for
            // virtual net devices). Emitting an empty `DEVTYPE=` was malformed.
            let iface = alloc::format!("INTERFACE={}", self.name);
            let ifindex = alloc::format!("IFINDEX={}", lookup_net_ifindex(&self.name));
            ::netlink::emit_uevent_with_env(
                uevent_action(buf), &devpath, "net", &[&iface, &ifindex]);
            return Ok(buf.len());
        }
        Err(VfsError::Erofs)
    }
}

struct NetIfaceOps;
impl NetIfaceOps {
    /// A fresh `sysfs_ops` handle for this iface kobject (the attribute file's
    /// backref). # C: O(1)
    fn ops(d: &NetIfaceData) -> Arc<dyn SysfsOps> {
        Arc::new(NetIfaceData { name: d.name.clone(), dev: Arc::clone(&d.dev) })
    }
}
impl InodeOps for NetIfaceOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<NetIfaceData>().ok_or(VfsError::Einval)?;
        // `statistics` is a subdirectory, not a leaf attribute file.
        if name == "statistics" {
            return Ok(net_stats::make_net_stats_inode(d.name.clone(), Arc::clone(&d.dev)));
        }
        // `subsystem` symlink → /sys/class/net (Linux `net_class`). udev/sd-device
        // read its basename to classify the device as SUBSYSTEM=net; without it
        // `udevadm trigger` never writes the iface's `uevent`, so udevd never
        // processes the interface and NetworkManager leaves it unmanaged (no DHCP).
        if name == "subsystem" {
            return Ok(crate::make_symlink_inode(b"../../../../class/net".to_vec()));
        }
        let attr = NET_IFACE_GROUP.find(name).ok_or(VfsError::Enoent)?;
        let ino: Ino = if name == "uevent" { ids::UEVENT } else { ids::ATTR };
        Ok(kobject::make_attr_inode(attr, NetIfaceOps::ops(d), ino))
    }
}
impl FileOps for NetIfaceOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let mut idx = ctx.pos as usize;
        // The default attribute group, then `statistics` (a subdir) as the
        // final entry. Offset space = group.len() attrs followed by the dir.
        let nfiles = NET_IFACE_GROUP.attrs.len();
        while idx < nfiles {
            let next = idx as u64 + 1;
            let name = NET_IFACE_GROUP.attrs[idx].name;
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Regular, next) { return Ok(()); }
            idx += 1;
        }
        if idx == nfiles {
            let next = idx as u64 + 1;
            let ino = inode.lookup("statistics").map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit("statistics", ino, FileType::Directory, next) { return Ok(()); }
        }
        if idx == nfiles + 1 {
            let next = idx as u64 + 1;
            let ino = inode.lookup("subsystem").map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit("subsystem", ino, FileType::Symlink, next) { return Ok(()); }
        }
        Ok(())
    }
}
/// Build a `/sys/class/net/<if>` (and `/sys/devices/virtual/net/<if>`) dir
/// inode synthesising per-iface attributes. # C: O(1)
pub(crate) fn make_net_iface_inode(name: String, dev: Arc<dyn net::NetDev>) -> InodeRef {
    InodeBuilder::new(ids::KOBJ_ROOT, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(NetIfaceOps), Arc::new(NetIfaceOps))
        .private(Arc::new(NetIfaceData { name, dev }))
        .build()
}

// ---- read-only owned-byte attribute file ----------------------------------

/// Per-inode body for a read-only sysfs attribute (Linux `attr->show` result).
pub(crate) struct BodyData { pub body: Vec<u8> }

/// `f_op` for a read-only attribute: windowed `read`, `write` → `EROFS`.
pub(crate) struct BodyFileOps;
impl FileOps for BodyFileOps {
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
        default_inode_ops(), Arc::new(BodyFileOps))
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
    register("/sys/class/net", make_sys_class_net_inode());
    register("/sys/devices/virtual/net", make_sys_devices_virtual_net_inode());
    #[cfg(target_os = "oxide-kernel")]
    net::netdev::set_remove_hook(invalidate_netdev_paths);
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

/// SYSFS_MAGIC (linux/magic.h) — sysfs `f_type`/`s_magic`.
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
    /// SYSFS_MAGIC (linux/magic.h).
    /// # C: O(1)
    fn magic(&self) -> u64 { SYSFS_MAGIC }
    /// Install zero-sized pseudo-fs statfs (`simple_statfs`) as this SB's `s_op`
    /// so `statfs(2)`/`df` report SYSFS_MAGIC + PAGE_SIZE, not the generic
    /// synthetic figures. # C: O(1)
    fn super_ops(&self) -> Option<Arc<dyn vfs::SuperOps>> { Some(Arc::new(SysfsSuperOps)) }
    /// Mount root = sysfs's OWN `kernfs::PseudoDir` (`SYS_ROOT`). The walk
    /// crosses into the sysfs mount and resolves `/sys/*` per-component via
    /// `PseudoDir::lookup` + the dynamic `SysClassNetOps::lookup`.
    /// # C: O(1)
    fn root(&self) -> Option<InodeRef> { sys_root().lookup_path("") }
    fn set_sb(&self, sb: alloc::sync::Weak<vfs::SuperBlock>) -> vfs::KResult<()> { sys_root().set_sb(sb); Ok(()) }
}

/// Singleton accessor for the mount table.
/// # C: O(1)
pub fn instance() -> &'static dyn vfs::fs::FileSystem { &SysfsFs }
