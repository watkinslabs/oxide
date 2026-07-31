//! `TFD_IOC_SET_TICKS` — inject an expiration count into a live timerfd so a
//! checkpointed process resumes with the ticks it had not yet read.

use syscall::errno::Errno;
use vfs::{Inode, VfsError};

use super::model::TimerfdData;

/// `_IOW('T', 0, __u64)`. # C: O(1)
pub(super) const TFD_IOC_SET_TICKS: u64 = 0x4008_5400;

/// Route a timerfd ioctl. `None` = not a timerfd, so the caller keeps
/// searching; a timerfd that does not know `req` is ENOTTY, never a fallthrough
/// to some other backend's numbering.
/// # C: O(1)
pub fn handle_timerfd_ioctl(inode: &Inode, req: u64, arg: u64) -> Option<i64> {
    let d = inode.private::<TimerfdData>()?;
    let error = |errno: Errno| -(errno.as_i32() as i64);
    if req != TFD_IOC_SET_TICKS { return Some(error(Errno::Enotty)); }
    let mut bytes = [0u8; core::mem::size_of::<u64>()];
    if uaccess::copy_from_user(&mut bytes, arg).is_err() { return Some(error(Errno::Efault)); }
    let ticks = u64::from_ne_bytes(bytes);
    // A zero injection is rejected: it would mean "armed but with nothing to
    // read", which no expiration can produce.
    if ticks == 0 { return Some(error(Errno::Einval)); }
    let outcome = { d.state.lock().set_ticks(ticks) };
    match outcome {
        Ok(()) => {
            d.read_waiters.wake_all();
            d.poll_subscribers.notify_mask(vfs::POLL_IN);
            Some(0)
        }
        Err(VfsError::Ecanceled) => Some(error(Errno::Ecanceled)),
        Err(e) => Some(-(e as i64)),
    }
}
