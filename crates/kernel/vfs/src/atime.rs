// `touch_atime` / `file_accessed` — the
// PLUMBING half of the access-time contract. The DECISION half lives in
// [`crate::inode_times`] (`atime_needs_update` / `relatime_need_update`); this
// module snapshots a live inode + mount into an `AtimeCtx`, applies the
// write-access gate, and stamps the timestamp through `i_op->update_time`.
//
// Every function here is UNGATED so the ladder is hosted-testable.

use crate::inode::{is_noatime, Inode, InodeRef};
use crate::inode_times::{atime_needs_update, current_time, realtime_now_ns, AtimeCtx};
use crate::mount::{mount_by_id, MNT_RDONLY};
use crate::timespec::Timespec64;
use crate::types::{FileType, OpenFlags};
use crate::S_ATIME;

/// `mnt->mnt_flags` for a `f_path.mnt` id. An anon/internal description
/// (`mnt_id == 0`: pipe, socket, memfd, eventfd, an inode reached before its
/// mount exists) has no vfsmount; Linux's internal `kern_mount` vfsmounts carry
/// `mnt_flags == 0`, i.e. STRICTATIME — every access stamps. Returning 0 keeps
/// that identity instead of inventing a policy. # C: O(log N) mount lookup
pub fn mnt_flags_for(mnt_id: u64) -> u64 {
    if mnt_id == 0 { return 0; }
    mount_by_id(mnt_id).map(|m| m.flags()).unwrap_or(0)
}

/// Snapshot the live inode + its superblock into the pure policy input.
/// # C: O(1)
pub fn atime_ctx(mnt_flags: u64, inode: &Inode) -> AtimeCtx {
    AtimeCtx {
        mnt_flags,
        sb_flags: inode.i_sb().map(|sb| sb.s_flags()).unwrap_or(0),
        inode_noatime: is_noatime(inode),
        is_dir: matches!(inode.file_type(), FileType::Directory),
        atime: inode.atime().unwrap_or(Timespec64::ZERO),
        mtime: inode.mtime().unwrap_or(Timespec64::ZERO),
        ctime: inode.ctime().unwrap_or(Timespec64::ZERO),
    }
}

/// Full `touch_atime` predicate: the `atime_needs_update` ladder PLUS the
/// write-access gate Linux spells as `mnt_get_write_access(mnt)` — a per-mount
/// read-only bind never advances atime even when the superblock is writable
/// (`MNT_RDONLY` is disjoint from `SB_RDONLY`, which the ladder already covers).
///
/// `S_IMMUTABLE` is deliberately NOT a gate: immutability forbids content and
/// metadata MUTATION by a caller, and Linux's `touch_atime` carries no
/// `IS_IMMUTABLE` test — an immutable file's atime still advances on read.
/// # C: O(1)
pub fn touch_atime_needed(c: &AtimeCtx, now: Timespec64) -> bool {
    if !atime_needs_update(c, now) { return false; }
    c.mnt_flags & MNT_RDONLY == 0
}

/// `touch_atime(&path)` — advance `i_atime` to the current
/// wall clock when the mount/superblock/inode policy allows it, then persist
/// through `i_op->update_time(S_ATIME)` so a backend that owns on-disk inodes
/// (ext4) writes it out. A no-op before the wall clock is installed (early
/// boot), which is why a boot-time read cannot stamp atime to the epoch.
///
/// Recorded through [`crate::writeback::inode_update_time`], so a `lazytime`
/// mount defers the on-disk write (`I_DIRTY_TIME`, paid at the next forcing
/// point) while every other mount persists immediately. atime is the timestamp
/// lazytime exists for: a read-mostly workload otherwise pays a metadata write
/// per file per relatime interval. # C: O(1) [+ one backend inode write]
pub fn touch_atime(mnt_id: u64, inode: &InodeRef) {
    let raw = realtime_now_ns();
    if raw == 0 { return; }
    let now = current_time(inode, raw);
    let c = atime_ctx(mnt_flags_for(mnt_id), inode);
    if !touch_atime_needed(&c, now) { return; }
    let _ = crate::writeback::inode_update_time(inode, now, S_ATIME, raw);
}

/// True for the file types whose read path Linux runs `file_accessed` on.
/// Regular files and block devices reach it through `filemap_read`; FIFOs and
/// pipes through `pipe_read`; directories through `iterate_dir`. Sockets
/// (`sock_read_iter`) and character devices (`tty_read`, `read_mem`, …) carry
/// no generic read helper and never stamp atime — oxide routes both through the
/// same [`crate::File::read`], so the set has to be named here. # C: O(1)
pub fn file_type_tracks_atime(ft: FileType) -> bool {
    matches!(ft, FileType::Regular | FileType::BlockDev | FileType::Fifo | FileType::Directory)
}

/// `file_accessed(file)` — `touch_atime` on the
/// description's `f_path`, skipped for an `O_NOATIME` open. # C: O(1) + backend
pub fn file_accessed(file: &crate::File) {
    if file.flags().contains(OpenFlags::O_NOATIME) { return; }
    if !file_type_tracks_atime(file.inode().file_type()) { return; }
    touch_atime(file.mnt_id(), file.inode());
}
