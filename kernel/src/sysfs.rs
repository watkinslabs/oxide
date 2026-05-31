// Dynamic sysfs surface synthesised from live kernel state. v1
// scope: /sys/class/net (per-iface dir reflecting the netdev
// registry — address, mtu, operstate, type, flags, carrier, speed,
// duplex). Static /sys/kernel/* and tracefs entries still live as
// devfs key registrations; this module owns the entries whose
// content depends on runtime state.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

const ARPHRD_LOOPBACK: u16 = 772;
const ARPHRD_ETHER:    u16 =   1;

/// `/sys/class/net` directory. `readdir` enumerates `net::sock::stack().ifaces`;
/// `lookup(name)` yields a per-iface `SysClassNetIfaceInode`.
pub struct SysClassNetInode;

impl Inode for SysClassNetInode {
    fn ino(&self) -> Ino { 0x5100_0001 }
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
    "addr_len", "name_assign_type", "dev_id",
];

impl Inode for SysClassNetIfaceInode {
    fn ino(&self) -> Ino { 0x5100_1000 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
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
        while idx < IFACE_ENTRIES.len() {
            let next = idx as u64 + 1;
            if !f(next, IFACE_ENTRIES[idx], FileType::Regular) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// Owned-byte regular-file inode. Body is built at lookup time so
/// it reflects current iface state; read() serves windowed slices.
struct BodyInode { body: Vec<u8>, ino: Ino }

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

struct VecFmt<'a>(&'a mut Vec<u8>);
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
    crate::devfs::register("/sys/class/net", Arc::new(SysClassNetInode) as InodeRef);
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
    /// Try the path-keyed devfs entry first (static /sys/kernel/*,
    /// /sys/devices/system/cpu/*, the SysClassNetInode at /sys/class/net,
    /// …). On miss, peel one component at a time and ask the ancestor
    /// inode to `lookup(child)` — that's how the dynamic per-iface inodes
    /// under /sys/class/net resolve.
    /// # C: O(N_devfs_entries × N_path_components)
    fn lookup(&self, path: &str) -> Option<InodeRef> {
        if let Some(i) = crate::devfs::lookup(path) { return Some(i); }
        let mut tail: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
        let mut cur = path;
        while let Some(idx) = cur.rfind('/') {
            if idx == 0 { return None; }
            let (parent, child) = cur.split_at(idx);
            tail.push(&child[1..]);
            if let Some(parent_inode) = crate::devfs::lookup(parent) {
                let mut node = parent_inode;
                for name in tail.iter().rev() {
                    node = node.lookup(name).ok()?;
                }
                return Some(node);
            }
            cur = parent;
        }
        None
    }
}

/// Singleton accessor for the mount table.
/// # C: O(1)
pub fn instance() -> &'static dyn vfs::fs::FileSystem { &SysfsFs }
