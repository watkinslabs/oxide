#![no_std]
#![cfg(target_os = "oxide-kernel")]
extern crate alloc;

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
pub mod kobject;
pub mod net_stats;
pub mod root;

pub use root::{register, register_dir, sys_root, SYSFS_FSID};

const ARPHRD_LOOPBACK: u16 = 772;
const ARPHRD_ETHER:    u16 =   1;

#[cfg(target_arch = "aarch64")]
const SERIAL_TTY_MAJOR: u32 = 204;
#[cfg(not(target_arch = "aarch64"))]
const SERIAL_TTY_MAJOR: u32 = 4;

// sysfs perm conventions (Linux): dirs r-xr-xr-x, attr files r--r--r--,
// writable attrs (`uevent`) rw-r--r--, symlinks rwxrwxrwx.
pub(crate) const DIR_PERM: u16 = 0o555;
pub(crate) const RO_PERM:  u16 = 0o444;
pub(crate) const RW_PERM:  u16 = 0o644;
pub(crate) const LNK_PERM: u16 = 0o777;

const TTY_DEVICES: &[(&str, u32, u32)] = &[
    ("console", 5, 1),
    ("tty",     5, 0),
    ("tty0",    4, 0),
    ("ttyS0",   SERIAL_TTY_MAJOR, 64),
];

fn tty_dev(name: &str) -> Option<(u32, u32)> {
    TTY_DEVICES.iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, maj, min)| (*maj, *min))
}

fn emit_tty_uevent(action: &str, name: &str, major: u32, minor: u32) {
    let devpath = alloc::format!("/devices/virtual/tty/{}", name);
    let devname = alloc::format!("DEVNAME={}", name);
    let maj = alloc::format!("MAJOR={}", major);
    let min = alloc::format!("MINOR={}", minor);
    ::netlink::emit_uevent_with_env(action, &devpath, "tty", &[&devname, &maj, &min]);
}

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
fn uevent_action(b: &[u8]) -> &str {
    core::str::from_utf8(b).ok()
        .and_then(|s| s.split_whitespace().next())
        .filter(|a| !a.is_empty())
        .unwrap_or("change")
}

// ---- /sys/class/tty (directory of symlinks) -------------------------------

/// `/sys/class/tty` directory. Entries are symlinks to the canonical virtual
/// tty device directories, matching Linux's class-device layout.
struct SysClassTtyOps;
impl InodeOps for SysClassTtyOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        if tty_dev(name).is_none() { return Err(VfsError::Enoent); }
        let mut target = String::from("../../devices/virtual/tty/");
        target.push_str(name);
        Ok(make_symlink_inode(target.into_bytes()))
    }
}
impl FileOps for SysClassTtyOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let mut idx = ctx.pos as usize;
        while idx < TTY_DEVICES.len() {
            let next = idx as u64 + 1;
            let name = TTY_DEVICES[idx].0;
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Symlink, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_sys_class_tty_inode() -> InodeRef {
    InodeBuilder::new(0x5101_0001, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysClassTtyOps), Arc::new(SysClassTtyOps)).build()
}

// ---- /sys/devices/virtual/tty (directory of device dirs) ------------------

/// `/sys/devices/virtual/tty` directory.
struct SysDevicesVirtualTtyOps;
impl InodeOps for SysDevicesVirtualTtyOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let (major, minor) = tty_dev(name).ok_or(VfsError::Enoent)?;
        Ok(make_tty_device_inode(String::from(name), major, minor))
    }
}
impl FileOps for SysDevicesVirtualTtyOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let mut idx = ctx.pos as usize;
        while idx < TTY_DEVICES.len() {
            let next = idx as u64 + 1;
            let name = TTY_DEVICES[idx].0;
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Directory, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_sys_devices_virtual_tty_inode() -> InodeRef {
    InodeBuilder::new(0x5101_0002, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysDevicesVirtualTtyOps), Arc::new(SysDevicesVirtualTtyOps)).build()
}

// ---- /sys/devices/virtual/tty/<name> (per-device dir) ---------------------

struct TtyDeviceData { name: String, major: u32, minor: u32 }

struct TtyDeviceOps;
impl InodeOps for TtyDeviceOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<TtyDeviceData>().ok_or(VfsError::Einval)?;
        match name {
            "dev" => {
                let body = alloc::format!("{}:{}\n", d.major, d.minor).into_bytes();
                Ok(make_body_inode(body, 0x5101_2000 + d.minor as Ino))
            }
            "uevent" => Ok(make_tty_uevent_inode(d.name.clone(), d.major, d.minor)),
            _ => Err(VfsError::Enoent),
        }
    }
}
impl FileOps for TtyDeviceOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        const ENTRIES: &[&str] = &["dev", "uevent"];
        let mut idx = ctx.pos as usize;
        while idx < ENTRIES.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(ENTRIES[idx]).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(ENTRIES[idx], ino, FileType::Regular, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_tty_device_inode(name: String, major: u32, minor: u32) -> InodeRef {
    InodeBuilder::new(0x5101_1000 + minor as Ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(TtyDeviceOps), Arc::new(TtyDeviceOps))
        .private(Arc::new(TtyDeviceData { name, major, minor }))
        .build()
}

// ---- /sys/devices/virtual/tty/<name>/uevent (rw attr) ---------------------

struct TtyUeventData { name: String, major: u32, minor: u32 }

struct TtyUeventFileOps;
impl FileOps for TtyUeventFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<TtyUeventData>().ok_or(VfsError::Einval)?;
        let body = alloc::format!(
            "MAJOR={}\nMINOR={}\nDEVNAME={}\n", d.major, d.minor, d.name).into_bytes();
        Ok(read_window(&body, off, buf))
    }
    fn write(&self, inode: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
        let d = inode.private::<TtyUeventData>().ok_or(VfsError::Einval)?;
        emit_tty_uevent(uevent_action(b), &d.name, d.major, d.minor);
        Ok(b.len())
    }
}
fn make_tty_uevent_inode(name: String, major: u32, minor: u32) -> InodeRef {
    InodeBuilder::new(0x5101_3000 + minor as Ino, mk_mode(FileType::Regular, RW_PERM),
        default_inode_ops(), Arc::new(TtyUeventFileOps))
        .private(Arc::new(TtyUeventData { name, major, minor }))
        .build()
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
        let snap = net::sock::stack().ifaces.snapshot_devs();
        for (_, dev) in snap.iter() {
            if dev.name() == name {
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
        let snap = net::sock::stack().ifaces.snapshot_devs();
        let mut idx = ctx.pos as usize;
        while idx < snap.len() {
            let next = idx as u64 + 1;
            let name = snap[idx].1.name();
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Symlink, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_sys_class_net_inode() -> InodeRef {
    InodeBuilder::new(0x5100_0001, mk_mode(FileType::Directory, DIR_PERM),
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
    make_symlink_inode_ino(target, 0x5100_0080)
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
        let snap = net::sock::stack().ifaces.snapshot_devs();
        for (_, dev) in snap.iter() {
            if dev.name() == name {
                return Ok(make_net_iface_inode(String::from(name), Arc::clone(dev)));
            }
        }
        Err(VfsError::Enoent)
    }
}
impl FileOps for SysDevicesVirtualNetOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let snap = net::sock::stack().ifaces.snapshot_devs();
        let mut idx = ctx.pos as usize;
        while idx < snap.len() {
            let next = idx as u64 + 1;
            let name = snap[idx].1.name();
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Directory, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_sys_devices_virtual_net_inode() -> InodeRef {
    InodeBuilder::new(0x5100_0002, mk_mode(FileType::Directory, DIR_PERM),
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
            let id = net::sock::stack().ifaces.lookup_name(&d.name)
                .map(|(id, _)| id.raw()).unwrap_or(0);
            let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut buf),
                format_args!("{}\n", id));
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
    fn show(&self, attr: &str) -> Option<Vec<u8>> {
        if attr == "uevent" {
            let mut body: Vec<u8> = Vec::new();
            let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut body),
                format_args!("DEVTYPE=\nINTERFACE={}\nIFINDEX={}\n", self.name,
                    net::sock::stack().ifaces.lookup_name(&self.name).map(|(id, _)| id.raw()).unwrap_or(0)));
            return Some(body);
        }
        iface_body(self, attr)
    }
    fn store(&self, attr: &str, buf: &[u8]) -> KResult<usize> {
        if attr == "uevent" {
            let devpath = alloc::format!("/devices/virtual/net/{}", self.name);
            ::netlink::emit_uevent(uevent_action(buf), &devpath, "net");
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
        let attr = NET_IFACE_GROUP.find(name).ok_or(VfsError::Enoent)?;
        let ino: Ino = if name == "uevent" { 0x5100_3000 } else { 0x5100_2000 };
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
        Ok(())
    }
}
/// Build a `/sys/class/net/<if>` (and `/sys/devices/virtual/net/<if>`) dir
/// inode synthesising per-iface attributes. # C: O(1)
pub(crate) fn make_net_iface_inode(name: String, dev: Arc<dyn net::NetDev>) -> InodeRef {
    InodeBuilder::new(0x5100_1000, mk_mode(FileType::Directory, DIR_PERM),
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
    register("/sys/class/net", make_sys_class_net_inode());
    register("/sys/devices/virtual/net", make_sys_devices_virtual_net_inode());
    register("/sys/class/tty", make_sys_class_tty_inode());
    register("/sys/devices/virtual/tty", make_sys_devices_virtual_tty_inode());
    bus::init();
    block::init();
}

/// `vfs::fs::FileSystem` impl mounted at `/sys`. Lookups consult sysfs's own
/// `kernfs::PseudoDir` tree (where /sys/kernel/*, /sys/devices/*, the dynamic
/// /sys/class/net inode live) and fall back to ENOENT.
pub struct SysfsFs;

impl vfs::fs::FileSystem for SysfsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "sysfs" }
    /// SYSFS_MAGIC (linux/magic.h).
    /// # C: O(1)
    fn magic(&self) -> u64 { 0x6265_6572 }
    /// Mount root = sysfs's OWN `kernfs::PseudoDir` (`SYS_ROOT`). The walk
    /// crosses into the sysfs mount and resolves `/sys/*` per-component via
    /// `PseudoDir::lookup` + the dynamic `SysClassNetOps::lookup`.
    /// # C: O(1)
    fn root(&self) -> Option<InodeRef> { sys_root().lookup_path("") }
}

/// Singleton accessor for the mount table.
/// # C: O(1)
pub fn instance() -> &'static dyn vfs::fs::FileSystem { &SysfsFs }
