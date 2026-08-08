// The two watch-queue ioctls, and the user-memory marshalling the filter one
// needs. Decision logic lives in `queue` and `filter`; this is copy-in only.

use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::File;

use super::filter::Filter;
use super::registry;
use super::uapi::*;

/// `f_op->unlocked_ioctl` for a pipe, for the two commands a watch queue owns.
///
/// `None` means "not one of ours" — the caller carries on with the rest of the
/// pipe's ioctls. A command that IS one of ours on a pipe that is not a
/// notification pipe is ENODEV: the command exists, this pipe has nothing for
/// it to act on. # C: O(filters)
pub fn handle_ioctl(file: &File, req: u64, arg: u64) -> Option<i64> {
    match req {
        IOC_WATCH_QUEUE_SET_SIZE => Some(set_size(file, arg)),
        IOC_WATCH_QUEUE_SET_FILTER => Some(set_filter(file, arg)),
        _ => None,
    }
}

fn set_size(file: &File, arg: u64) -> i64 {
    let Some(q) = registry::queue_of(file.inode()) else { return neg(Errno::Enodev) };
    // The argument is an `int`, so a value with the sign bit set is not a
    // depth at all and is refused by the depth rule rather than wrapping into
    // an enormous allocation.
    let nr = arg as u32 as i32;
    if nr < 0 { return neg(Errno::Einval); }
    let pages = match super::queue::admit_set_size(nr as usize, q.is_sized()) {
        Ok(p) => p,
        Err(e) => return neg(e),
    };
    // The depth is memory, and it is the pipe's owner who pays for it: the
    // reservation is charged against that account before the depth exists, so
    // a user cannot hold more notification memory than pipe pages.
    if let Err(e) = crate::pipe::charge_pipe_pages(file.inode(), pages as i64) {
        // The charge refuses with EPERM (over a per-user limit) and nothing
        // else on a pipe that reached this command at all.
        return neg(match e { vfs::VfsError::Einval => Errno::Einval, _ => Errno::Eperm });
    }
    q.commit_size(pages);
    0
}

fn set_filter(file: &File, arg: u64) -> i64 {
    let Some(q) = registry::queue_of(file.inode()) else { return neg(Errno::Enodev) };
    // A NULL pointer removes the filter, which is the only way back to
    // "deliver everything" once one is installed.
    if arg == 0 { q.set_filter(None); return 0; }
    let header = match read_user(arg, WATCH_FILTER_HEADER_SIZE) { Ok(v) => v, Err(rv) => return rv };
    let nr = u32::from_ne_bytes([header[WATCH_FILTER_NR_OFFSET], header[WATCH_FILTER_NR_OFFSET + 1],
        header[WATCH_FILTER_NR_OFFSET + 2], header[WATCH_FILTER_NR_OFFSET + 3]]);
    // The count is vetted BEFORE the rule array is copied, so an absurd count
    // is rejected rather than attempted.
    if nr == 0 || nr > WATCH_FILTER_MAX { return neg(Errno::Einval); }
    let rules_len = nr as usize * WATCH_TYPE_FILTER_SIZE;
    let rules = match read_user(arg + WATCH_FILTER_HEADER_SIZE as u64, rules_len) {
        Ok(v) => v, Err(rv) => return rv,
    };
    match Filter::parse(&header, &rules, nr) {
        Ok(f) => { q.set_filter(Some(f)); 0 }
        Err(e) => neg(e),
    }
}

fn read_user(p: u64, len: usize) -> Result<Vec<u8>, i64> {
    crate::userbuf::validate_user_buf(p, len as u64, 1)?;
    let mut out = alloc::vec![0u8; len];
    // SAFETY: the exact user byte range was validated readable just above; the destination is a kernel-owned Vec.
    unsafe { for i in 0..len { out[i] = core::ptr::read_unaligned((p + i as u64) as *const u8); } }
    Ok(out)
}

fn neg(e: Errno) -> i64 { -(e.as_i32() as i64) }
