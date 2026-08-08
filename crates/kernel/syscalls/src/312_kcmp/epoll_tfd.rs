// `KCMP_EPOLL_TFD` — Linux `kcmp_epoll_target` plus
// `get_epoll_tfile_raw_ptr` / `ep_find_tfd`.
//
// Compares the open file description behind `task1`'s fd `idx1` against the
// file an epoll instance owned by `task2` watches. `idx2` points at a user
// `struct kcmp_epoll_slot`, not at an fd.

use alloc::sync::Arc;

use syscall::errno::Errno;
use crate::kcmp_abi::ptr_cmp;
use crate::misc::misc_common::errno;

/// `struct kcmp_epoll_slot`: three `__u32`.
const KCMP_EPOLL_SLOT_BYTES: u64 = 12;
const SLOT_OFF_EFD:  usize = 0;
const SLOT_OFF_TFD:  usize = 4;
const SLOT_OFF_TOFF: usize = 8;

/// Linux `ep_find_tfd`: the `toff`-th interest in `ep` whose watched fd number
/// is `tfd`. `toff` disambiguates the duplicates an epoll may hold for one fd
/// number. # C: O(N_entries)
fn find_tfd(ep: &::fs::epoll::EpollData, tfd: i32, toff: u64) -> Option<Arc<vfs::File>> {
    let mut seen: u64 = 0;
    for item in ep.entries.lock().iter() {
        if item.fd != tfd { continue; }
        if seen == toff { return item.file.upgrade(); }
        seen += 1;
    }
    None
}

/// `kcmp(pid1, pid2, KCMP_EPOLL_TFD, fd, &slot)`.
///
/// Errno ladder is Linux's: EFAULT for an unreadable slot, EBADF when either
/// descriptor is unallocated, EINVAL when `slot.efd` is not an epoll, ENOENT
/// when the epoll watches nothing at `(tfd, toff)`.
/// # C: O(N_entries)
pub fn compare(t1: &sched::Task, t2: &sched::Task, idx1: u64, idx2: u64) -> i64 {
    if let Err(rv) = crate::userbuf::validate_user_buf_readable(idx2, KCMP_EPOLL_SLOT_BYTES, 1) {
        return rv;
    }
    let mut slot = [0u8; KCMP_EPOLL_SLOT_BYTES as usize];
    if uaccess::copy_from_user(&mut slot, idx2).is_err() { return errno(Errno::Efault); }
    let rd = |off: usize| u32::from_ne_bytes([slot[off], slot[off + 1], slot[off + 2], slot[off + 3]]);
    let efd  = rd(SLOT_OFF_EFD) as i32;
    let tfd  = rd(SLOT_OFF_TFD) as i32;
    let toff = rd(SLOT_OFF_TOFF) as u64;

    // Both fd lookups pin the owning table against a concurrent exit-time
    // `replace_fd_table(None)` on a foreign task.
    let filp = match t1.clone_fd_table().and_then(|t| t.get(idx1 as i32).ok()) {
        Some(f) => f, None => return errno(Errno::Ebadf),
    };
    let epfile = match t2.clone_fd_table().and_then(|t| t.get(efd).ok()) {
        Some(f) => f, None => return errno(Errno::Ebadf),
    };
    let ep = match epfile.inode().private::<::fs::epoll::EpollData>() {
        Some(ep) => ep, None => return errno(Errno::Einval),
    };
    match find_tfd(ep, tfd, toff) {
        Some(target) => ptr_cmp(Arc::as_ptr(&filp) as usize, Arc::as_ptr(&target) as usize),
        None => errno(Errno::Enoent),
    }
}
