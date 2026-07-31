// perf-event pseudo-inode + `f_op` — Linux `kernel/events/core.c`
// `perf_fops` (`perf_read`, `__perf_read`, `perf_poll`).

use alloc::sync::Arc;

use vfs::{FileOps, Inode, InodeBuilder, InodeRef, KResult, default_inode_ops, mk_mode, VfsError};

use super::counter::{format_group, format_one, read_size, MemberRead};
use super::event::PerfEvent;
use super::uapi::fmt;

/// perf's reserved inode-number range, owned by `vfs::pseudo_ino`.
static NEXT_PERF_INO: vfs::pseudo_ino::RegionAllocator
    = vfs::pseudo_ino::RegionAllocator::new(&vfs::pseudo_ino::PERF);

/// Build the anon inode backing one `perf_event_open` fd. # C: O(1)
pub fn make_perf_event_inode(ev: Arc<PerfEvent>) -> InodeRef {
    let ino = NEXT_PERF_INO.alloc();
    InodeBuilder::new(ino, mk_mode(vfs::FileType::Regular, 0),
        default_inode_ops(), Arc::new(PerfFileOps))
        .private(ev)
        .build()
}

/// The `Arc<PerfEvent>` behind a perf fd, if this inode is one. # C: O(1)
pub fn event_of(inode: &InodeRef) -> Option<Arc<PerfEvent>> {
    inode.i_private().clone().downcast::<PerfEvent>().ok()
}

/// True when `inode` is a perf-event fd — Linux `is_perf_file()`, a comparison
/// against the one `perf_fops`. The inode NUMBER cannot stand in for that:
/// numbers are only reserved per owner, never proof of who minted one, and the
/// gate sat two lines below an `event_of` that already answered from state.
/// A foreign inode reusing a perf number would have had its unrelated private
/// word taken for a `PerfEvent` by the ioctl handler this gate admits to.
/// # C: O(1)
pub fn is_perf_inode(inode: &InodeRef) -> bool { event_of(inode).is_some() }

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
