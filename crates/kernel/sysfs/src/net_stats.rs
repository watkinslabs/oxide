// `/sys/class/net/<if>/statistics/` — per-iface running counters,
// served live from the iface's `net::NetDev::stats()`. Linux exposes
// each counter as its own decimal (newline-terminated) attribute file
// under the `statistics` subdirectory. iproute2/ethtool/networkd read
// these; the field names + ordering come from `net::STAT_FIELDS`
// (which mirrors `net/core/net-sysfs.c`). Per-field value mapping +
// the "unbacked field → 0" rule live in `net::NetStats::field` and are
// host-tested there.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use crate::{make_body_inode, VecFmt, DIR_PERM};

/// Per-inode state for the `statistics` dir (Linux `net_device` backref). # C: n/a
struct NetStatsData {
    name: String,
    dev:  Arc<dyn net::NetDev>,
}

/// `/sys/class/net/<if>/statistics` directory. Holds the per-counter
/// attribute files; `iterate` lists `net::STAT_FIELDS`, `lookup(name)`
/// builds a live `BodyInode` from the iface's `NetDev::stats()`.
struct NetStatsOps;
impl InodeOps for NetStatsOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<NetStatsData>().ok_or(VfsError::Einval)?;
        let v = d.dev.stats().field(name).ok_or(VfsError::Enoent)?;
        let mut buf: Vec<u8> = Vec::with_capacity(20);
        let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut buf),
            format_args!("{}\n", v));
        Ok(make_body_inode(buf, crate::ids::NET_STATS_ATTR))
    }
}
impl FileOps for NetStatsOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let fields = net::STAT_FIELDS;
        let mut idx = ctx.pos as usize;
        while idx < fields.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(fields[idx]).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(fields[idx], ino, FileType::Regular, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}

/// Build the `/sys/class/net/<if>/statistics` dir inode (ino `0x5100_4000`).
/// # C: O(1)
pub fn make_net_stats_inode(name: String, dev: Arc<dyn net::NetDev>) -> InodeRef {
    InodeBuilder::new(crate::ids::NET_STATS_DIR, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(NetStatsOps), Arc::new(NetStatsOps))
        .private(Arc::new(NetStatsData { name, dev }))
        .build()
}
