// `/sys/class/net/<if>/statistics/` — per-iface running counters,
// served live from the iface's `net::NetDev::stats()`. Linux exposes
// each counter as its own decimal (newline-terminated) attribute file
// under the `statistics` subdirectory. iproute2/ethtool/networkd read
// these; the field names + ordering come from `net::STAT_FIELDS`
// (which mirrors `net/core/net-sysfs.c`). Per-field value mapping +
// the "unbacked field → 0" rule live in `net::NetStats::field` and are
// host-tested there.

use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

use crate::{BodyInode, VecFmt};

/// `/sys/class/net/<if>/statistics` directory. Holds the per-counter
/// attribute files; `readdir` lists `net::STAT_FIELDS`, `lookup(name)`
/// builds a live `BodyInode` from the iface's `NetDev::stats()`.
pub struct SysNetStatsInode {
    pub name: String,
    pub dev:  Arc<dyn net::NetDev>,
}

impl Inode for SysNetStatsInode {
    fn ino(&self) -> Ino { 0x5100_4000 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        let v = self.dev.stats().field(name).ok_or(VfsError::Enoent)?;
        let mut buf: Vec<u8> = Vec::with_capacity(20);
        let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut buf),
            format_args!("{}\n", v));
        Ok(Arc::new(BodyInode::new(buf, 0x5100_4001)) as InodeRef)
    }
    fn readdir(
        &self,
        off: u64,
        f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        let fields = net::STAT_FIELDS;
        let mut idx = off as usize;
        while idx < fields.len() {
            let next = idx as u64 + 1;
            let ino = self.lookup(fields[idx]).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, fields[idx], FileType::Regular) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}
