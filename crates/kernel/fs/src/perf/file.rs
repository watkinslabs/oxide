// perf-event pseudo-inode + `f_op` — Linux `kernel/events/core.c`
// `perf_fops` (`perf_read`, `__perf_read`, `perf_poll`).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use vfs::{FileOps, Inode, InodeBuilder, InodeRef, KResult, default_inode_ops, mk_mode, VfsError};

use super::counter::{format_group, format_one, read_size, MemberRead};
use super::event::PerfEvent;
use super::uapi::fmt;

/// Inode-number tag distinguishing perf fds from the other anon-inode families.
pub const INO_TAG:     vfs::Ino = 0x5045_5246_0000_0000;
pub const INO_ID_MASK: vfs::Ino = 0xFFFF_FFFF;

static NEXT_PERF_INO: AtomicU64 = AtomicU64::new(1);

/// Build the anon inode backing one `perf_event_open` fd. # C: O(1)
pub fn make_perf_event_inode(ev: Arc<PerfEvent>) -> InodeRef {
    let ino = INO_TAG | (NEXT_PERF_INO.fetch_add(1, Ordering::Relaxed) & INO_ID_MASK);
    InodeBuilder::new(ino, mk_mode(vfs::FileType::Regular, 0),
        default_inode_ops(), Arc::new(PerfFileOps))
        .private(ev)
        .build()
}

/// The `Arc<PerfEvent>` behind a perf fd, if this inode is one. # C: O(1)
pub fn event_of(inode: &InodeRef) -> Option<Arc<PerfEvent>> {
    inode.i_private().clone().downcast::<PerfEvent>().ok()
}

/// True when `inode` is a perf-event fd (`is_perf_file()`). # C: O(1)
pub fn is_perf_inode(inode: &InodeRef) -> bool { inode.ino() & !INO_ID_MASK == INO_TAG }

struct PerfFileOps;

impl FileOps for PerfFileOps {
    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    /// `perf_read` → `__perf_read`: the payload is fully determined by
    /// `attr.read_format`, and a buffer smaller than `event->read_size` is
    /// `-ENOSPC` (not a short read).
    fn read(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let ev = match inode.private::<PerfEvent>() { Some(e) => e, None => return Err(VfsError::Einval) };
        let rf = ev.attr.read_format;
        let want = read_size(rf, ev.nr_siblings());
        if buf.len() < want { return Err(VfsError::Enospc); }
        let bytes = if rf & fmt::GROUP != 0 {
            let members = ev.group_members();
            let (_, enabled, running) = members[0].read_value();
            let vals: alloc::vec::Vec<MemberRead> = members.iter()
                .map(|m| MemberRead { count: m.read_value().0, id: m.id, lost: 0 })
                .collect();
            format_group(rf, &vals, enabled, running)
        } else {
            let (count, enabled, running) = ev.read_value();
            format_one(rf, MemberRead { count, id: ev.id, lost: 0 }, enabled, running)
        };
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }

    /// `perf_fops` has no `.write`; the VFS reports `-EINVAL` for a write to a
    /// file whose operations omit it.
    fn write(&self, _inode: &Inode, _off: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Einval) }
}
