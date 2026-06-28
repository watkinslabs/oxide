#![no_std]
#![cfg(target_os = "oxide-kernel")]
extern crate alloc;

// Dynamic sysfs surface synthesised from live kernel state. v1
// scope: /sys/class/net (per-iface dir reflecting the netdev
// registry — address, mtu, operstate, type, flags, carrier, speed,
// duplex). Static /sys/kernel/* and tracefs entries still live as
// devfs key registrations; this module owns the entries whose
// content depends on runtime state.

use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

pub mod block;
pub mod bus;
pub mod net_stats;
pub mod root;

pub use root::{register, register_dir, sys_root, SYSFS_FSID};

const ARPHRD_LOOPBACK: u16 = 772;
const ARPHRD_ETHER:    u16 =   1;

#[cfg(target_arch = "aarch64")]
const SERIAL_TTY_MAJOR: u32 = 204;
#[cfg(not(target_arch = "aarch64"))]
const SERIAL_TTY_MAJOR: u32 = 4;

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

/// `/sys/class/tty` directory. Entries are symlinks to the canonical virtual
/// tty device directories, matching Linux's class-device layout.
pub struct SysClassTtyInode;

impl Inode for SysClassTtyInode {
    fn ino(&self) -> Ino { 0x5101_0001 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        if tty_dev(name).is_none() { return Err(VfsError::Enoent); }
        let mut target = alloc::string::String::from("../../devices/virtual/tty/");
        target.push_str(name);
        Ok(Arc::new(SysClassNetSymlinkInode { target: target.into_bytes() }) as InodeRef)
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, &str, FileType) -> bool) -> KResult<u64> {
        let mut idx = off as usize;
        while idx < TTY_DEVICES.len() {
            let next = idx as u64 + 1;
            if !f(next, TTY_DEVICES[idx].0, FileType::Symlink) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// `/sys/devices/virtual/tty` directory.
pub struct SysDevicesVirtualTtyInode;

impl Inode for SysDevicesVirtualTtyInode {
    fn ino(&self) -> Ino { 0x5101_0002 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        let (major, minor) = tty_dev(name).ok_or(VfsError::Enoent)?;
        Ok(Arc::new(SysTtyDeviceInode {
            name: alloc::string::String::from(name),
            major,
            minor,
        }) as InodeRef)
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, &str, FileType) -> bool) -> KResult<u64> {
        let mut idx = off as usize;
        while idx < TTY_DEVICES.len() {
            let next = idx as u64 + 1;
            if !f(next, TTY_DEVICES[idx].0, FileType::Directory) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

struct SysTtyDeviceInode {
    name: alloc::string::String,
    major: u32,
    minor: u32,
}

impl Inode for SysTtyDeviceInode {
    fn ino(&self) -> Ino { 0x5101_1000 + self.minor as Ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        match name {
            "dev" => {
                let body = alloc::format!("{}:{}\n", self.major, self.minor).into_bytes();
                Ok(Arc::new(BodyInode::new(body, 0x5101_2000 + self.minor as Ino)) as InodeRef)
            }
            "uevent" => Ok(Arc::new(TtyUeventInode {
                name: self.name.clone(),
                major: self.major,
                minor: self.minor,
            }) as InodeRef),
            _ => Err(VfsError::Enoent),
        }
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, &str, FileType) -> bool) -> KResult<u64> {
        const ENTRIES: &[&str] = &["dev", "uevent"];
        let mut idx = off as usize;
        while idx < ENTRIES.len() {
            let next = idx as u64 + 1;
            if !f(next, ENTRIES[idx], FileType::Regular) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

struct TtyUeventInode {
    name: alloc::string::String,
    major: u32,
    minor: u32,
}

impl Inode for TtyUeventInode {
    fn ino(&self) -> Ino { 0x5101_3000 + self.minor as Ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = alloc::format!(
            "MAJOR={}\nMINOR={}\nDEVNAME={}\n",
            self.major, self.minor, self.name
        ).into_bytes();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _o: u64, b: &[u8]) -> KResult<usize> {
        let action = core::str::from_utf8(b).ok()
            .and_then(|s| s.split_whitespace().next())
            .filter(|a| !a.is_empty())
            .unwrap_or("change");
        emit_tty_uevent(action, &self.name, self.major, self.minor);
        Ok(b.len())
    }
}

/// `/sys/class/net` directory. `readdir` enumerates
/// `net::sock::stack().ifaces` and emits each entry as a symlink per
/// docs/19§2 invariant 2 (`/sys/class/<class>/<name>` → `/sys/devices/
/// .../<name>`). `lookup(name)` returns a `SysClassNetSymlinkInode`
/// whose readlink target is the canonical devices path; the real
/// attribute set lives under `/sys/devices/virtual/net/<name>` and is
/// served by `SysDevicesVirtualNetInode`.
pub struct SysClassNetInode;

impl Inode for SysClassNetInode {
    fn ino(&self) -> Ino { 0x5100_0001 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        let snap = net::sock::stack().ifaces.snapshot_devs();
        for (_, dev) in snap.iter() {
            if dev.name() == name {
                let mut target = alloc::string::String::from("../../devices/virtual/net/");
                target.push_str(name);
                return Ok(Arc::new(SysClassNetSymlinkInode {
                    target: target.into_bytes(),
                }) as InodeRef);
            }
        }
        Err(VfsError::Enoent)
    }
    fn readdir(
        &self,
        off: u64,
        f: &mut dyn FnMut(u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        let snap = net::sock::stack().ifaces.snapshot_devs();
        let mut idx = off as usize;
        while idx < snap.len() {
            let next = idx as u64 + 1;
            if !f(next, snap[idx].1.name(), FileType::Symlink) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// `/sys/class/net/<if>` symlink — readlink target is the canonical
/// /sys/devices path that holds the attribute set. udev/networkd
/// readlink this to discover the bus path; subsequent attribute
/// reads go through the resolved /sys/devices/.../<attr> path which
/// SysfsFs follows transparently (component-walk follows the link).
pub struct SysClassNetSymlinkInode {
    pub target: alloc::vec::Vec<u8>,
}

impl Inode for SysClassNetSymlinkInode {
    fn ino(&self) -> Ino { 0x5100_0080 }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { self.target.len() as u64 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> KResult<alloc::vec::Vec<u8>> { Ok(self.target.clone()) }
}

/// `/sys/devices/virtual/net` directory. Same readdir/lookup as
/// SysClassNetInode but returns the actual SysClassNetIfaceInode
/// directory (the canonical home for per-iface attributes).
pub struct SysDevicesVirtualNetInode;

impl Inode for SysDevicesVirtualNetInode {
    fn ino(&self) -> Ino { 0x5100_0002 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        let snap = net::sock::stack().ifaces.snapshot_devs();
        for (_, dev) in snap.iter() {
            if dev.name() == name {
                return Ok(Arc::new(SysClassNetIfaceInode {
                    name: alloc::string::String::from(name),
                    dev:  Arc::clone(dev),
                }) as InodeRef);
            }
        }
        Err(VfsError::Enoent)
    }
    fn readdir(
        &self,
        off: u64,
        f: &mut dyn FnMut(u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        let snap = net::sock::stack().ifaces.snapshot_devs();
        let mut idx = off as usize;
        while idx < snap.len() {
            let next = idx as u64 + 1;
            if !f(next, snap[idx].1.name(), FileType::Directory) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// `/sys/class/net/<if>` directory. Synthesises per-iface attributes
/// that ip/iproute2/networkd/udev probe.
pub struct SysClassNetIfaceInode {
    pub name: alloc::string::String,
    pub dev:  Arc<dyn net::NetDev>,
}

impl SysClassNetIfaceInode {
    fn arphrd(&self) -> u16 {
        // No NetDev::kind() in v1 — infer from name. `lo` → loopback;
        // everything else (eth*, en*) treats as ARPHRD_ETHER.
        if self.name == "lo" { ARPHRD_LOOPBACK } else { ARPHRD_ETHER }
    }

    fn body(&self, leaf: &str) -> Option<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::with_capacity(32);
        match leaf {
            "address" => {
                let m = self.dev.mac().0;
                let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut buf),
                    format_args!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                        m[0], m[1], m[2], m[3], m[4], m[5]));
            }
            "broadcast" => {
                buf.extend_from_slice(b"ff:ff:ff:ff:ff:ff\n");
            }
            "mtu" => {
                let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut buf),
                    format_args!("{}\n", self.dev.mtu()));
            }
            "operstate" => {
                // Linux: "up" / "down" / "unknown". Loopback reports
                // "unknown" (no carrier abstraction); real ifaces "up".
                buf.extend_from_slice(if self.arphrd() == ARPHRD_LOOPBACK {
                    b"unknown\n" } else { b"up\n" });
            }
            "type" => {
                let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut buf),
                    format_args!("{}\n", self.arphrd()));
            }
            "flags" => {
                // IFF_UP|IFF_BROADCAST|IFF_RUNNING|IFF_MULTICAST = 0x1003 for ether,
                // IFF_UP|IFF_LOOPBACK|IFF_RUNNING                = 0x49   for lo.
                buf.extend_from_slice(if self.arphrd() == ARPHRD_LOOPBACK {
                    b"0x49\n" } else { b"0x1003\n" });
            }
            "carrier" => {
                buf.extend_from_slice(b"1\n");
            }
            "speed" => {
                // Loopback returns -1 per Linux; ether reports 10000.
                buf.extend_from_slice(if self.arphrd() == ARPHRD_LOOPBACK {
                    b"-1\n" } else { b"10000\n" });
            }
            "duplex" => {
                buf.extend_from_slice(if self.arphrd() == ARPHRD_LOOPBACK {
                    b"unknown\n" } else { b"full\n" });
            }
            "ifindex" => {
                let id = net::sock::stack().ifaces.lookup_name(&self.name)
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
}

const IFACE_ENTRIES: &[&str] = &[
    "address", "broadcast", "mtu", "operstate", "type", "flags",
    "carrier", "speed", "duplex", "ifindex", "tx_queue_len",
    "addr_len", "name_assign_type", "dev_id", "uevent",
];

/// `/sys/class/net/<if>/uevent` — read returns the device's uevent env;
/// write of an action ("add"/"change"/"remove") broadcasts a kobject
/// uevent on NETLINK_KOBJECT_UEVENT (the `udevadm trigger` path → udev).
struct UeventTriggerInode { name: alloc::string::String }

impl Inode for UeventTriggerInode {
    fn ino(&self) -> Ino { 0x5100_3000 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        // uevent read yields the device's env vars (one per line).
        let mut body: Vec<u8> = Vec::new();
        let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut body),
            format_args!("DEVTYPE=\nINTERFACE={}\nIFINDEX={}\n", self.name,
                net::sock::stack().ifaces.lookup_name(&self.name).map(|(id, _)| id.raw()).unwrap_or(0)));
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _o: u64, b: &[u8]) -> KResult<usize> {
        // First whitespace-delimited token is the action ("add"/"change"/…).
        let action = core::str::from_utf8(b).ok()
            .and_then(|s| s.split_whitespace().next())
            .filter(|a| !a.is_empty())
            .unwrap_or("change");
        let devpath = alloc::format!("/devices/virtual/net/{}", self.name);
        ::netlink::emit_uevent(action, &devpath, "net");
        Ok(b.len())
    }
}

impl Inode for SysClassNetIfaceInode {
    fn ino(&self) -> Ino { 0x5100_1000 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        // The `uevent` node is writable: `udevadm trigger` (and udev
        // coldplug) write "add"/"change" to re-emit the device's uevent.
        if name == "uevent" {
            return Ok(Arc::new(UeventTriggerInode { name: self.name.clone() }) as InodeRef);
        }
        // `statistics` is a subdirectory, not a leaf attribute file.
        if name == "statistics" {
            return Ok(Arc::new(net_stats::SysNetStatsInode {
                name: self.name.clone(),
                dev:  Arc::clone(&self.dev),
            }) as InodeRef);
        }
        if !IFACE_ENTRIES.contains(&name) { return Err(VfsError::Enoent); }
        let body = self.body(name).unwrap_or_default();
        Ok(Arc::new(BodyInode { body, ino: 0x5100_2000 }) as InodeRef)
    }
    fn readdir(
        &self,
        off: u64,
        f: &mut dyn FnMut(u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        let mut idx = off as usize;
        // `statistics` (a subdir) is emitted as the final entry, after
        // the regular attribute files. Treat the offset space as
        // IFACE_ENTRIES.len() files followed by the one stats dir.
        let nfiles = IFACE_ENTRIES.len();
        while idx < nfiles {
            let next = idx as u64 + 1;
            if !f(next, IFACE_ENTRIES[idx], FileType::Regular) { return Ok(next); }
            idx += 1;
        }
        if idx == nfiles {
            let next = idx as u64 + 1;
            if !f(next, "statistics", FileType::Directory) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// Owned-byte regular-file inode. Body is built at lookup time so
/// it reflects current iface state; read() serves windowed slices.
pub struct BodyInode { body: Vec<u8>, ino: Ino }

impl BodyInode {
    /// Build a read-only attribute inode serving `body`. # C: O(1)
    pub fn new(body: Vec<u8>, ino: Ino) -> Self { Self { body, ino } }
}

impl Inode for BodyInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { self.body.len() as u64 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let off = off as usize;
        if off >= self.body.len() { return Ok(0); }
        let avail = &self.body[off..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
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
    register("/sys/class/net",
        Arc::new(SysClassNetInode) as InodeRef);
    register("/sys/devices/virtual/net",
        Arc::new(SysDevicesVirtualNetInode) as InodeRef);
    register("/sys/class/tty",
        Arc::new(SysClassTtyInode) as InodeRef);
    register("/sys/devices/virtual/tty",
        Arc::new(SysDevicesVirtualTtyInode) as InodeRef);
    bus::init();
    block::init();
}

/// `vfs::fs::FileSystem` impl mounted at `/sys`. Lookups consult the
/// devfs key registry (where /sys/kernel/*, /sys/devices/*, the
/// dynamic /sys/class/net inode live) and fall back to ENOENT.
/// Static-prefix dir inodes (PrefixDirInode in devfs::init) are also
/// registered there, so readdir of /sys works the same way.
pub struct SysfsFs;

impl vfs::fs::FileSystem for SysfsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "sysfs" }
    /// SYSFS_MAGIC (linux/magic.h).
    /// # C: O(1)
    fn magic(&self) -> u64 { 0x6265_6572 }
    /// Mount root = sysfs's OWN `kernfs::PseudoDir` (`SYS_ROOT`). The walk
    /// crosses into the sysfs mount and resolves `/sys/*` per-component via
    /// `PseudoDir::lookup` + the dynamic `SysClassNetInode::lookup`.
    /// # C: O(1)
    fn root(&self) -> Option<InodeRef> { Some(sys_root() as InodeRef) }
}

/// Singleton accessor for the mount table.
/// # C: O(1)
pub fn instance() -> &'static dyn vfs::fs::FileSystem { &SysfsFs }
