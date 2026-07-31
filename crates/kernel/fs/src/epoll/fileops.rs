// `i_fop` for an epoll inode: release, nested-poll readiness, the fdinfo
// interest dump, and the busy-poll parameter ioctls.

use alloc::sync::Arc;
use alloc::vec::Vec;
use vfs::{File, FileOps, Inode, KResult, VfsError};

use super::{epoll_data_of_inode, EpItem, EpollData, EPOLLS};

/// `i_fop` for an epoll inode. # C: O(1)
pub(super) struct EpollFileOps;

impl FileOps for EpollFileOps {
    fn read(&self, _inode: &Inode, _o: u64, _b: &mut [u8]) -> KResult<usize> { Err(VfsError::Einval) }
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }

    /// An epoll file has a readiness operation, so it may be nested inside
    /// another epoll. # C: O(1)
    fn can_poll(&self, _file: &File) -> bool { true }

    /// Linux `eventpoll_release_file`: closing an epoll fd removes every
    /// interest, unregisters callbacks from watched wait queues, drops the
    /// pinned file descriptions and returns the watch charges.
    /// # C: O(N_entries)
    fn on_release_file(&self, file: &File) {
        let Some(ep) = epoll_data_of_inode(file.inode()) else { return; };
        let drained: Vec<Arc<EpItem>> = {
            let mut list = ep.entries.lock();
            list.drain(..).collect()
        };
        for e in drained.iter() { EpItem::detach(e); }
        {
            let mut g = EPOLLS.lock();
            if let Some(slot) = g.get_mut(ep.id as usize) { *slot = None; }
        }
        #[cfg(target_os = "oxide-kernel")]
        ep.waiters.wake_all();
        drop(drained);
    }

    /// A nested epoll fd is readable while its ready list contains an active,
    /// currently-ready item. # C: O(N_ready)
    fn poll(&self, inode: &Inode) -> u32 {
        let d = match inode.private::<EpollData>() { Some(d) => d, None => return 0 };
        let ready = d.ready.lock().clone();
        for item in ready {
            let state = item.state.lock();
            if state.active && state.armed { return vfs::POLL_IN; }
        }
        0
    }

    /// `ep_show_fdinfo`: one line per interest, in interest-list order, naming
    /// the watched descriptor, its stored event mask (which always carries
    /// `EPOLLERR|EPOLLHUP`), the caller's opaque data word, the description's
    /// file position and the watched inode's identity. CRIU and `lsof` read
    /// this to recover which descriptors an event loop is waiting on.
    /// # C: O(N_entries)
    fn fdinfo_extra(&self, inode: &Inode, out: &mut Vec<u8>) {
        let Some(d) = inode.private::<EpollData>() else { return; };
        let entries = d.entries.lock().clone();
        for item in entries {
            let (events, data, active) = {
                let state = item.state.lock();
                (state.events, state.data, state.active)
            };
            if !active { continue; }
            let Some(f) = item.file.upgrade() else { continue; };
            let _ = core::fmt::Write::write_fmt(&mut VecFmt(out), format_args!(
                "tfd: {:8} events: {:8x} data: {:16x}  pos:{} ino:{:x} sdev:{:x}\n",
                item.fd, events, data, f.pos(), f.inode().ino(),
                f.inode().i_sb().map(|sb| sb.s_dev).unwrap_or(0),
            ));
        }
    }
}

struct VecFmt<'a>(&'a mut Vec<u8>);
impl<'a> core::fmt::Write for VecFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// `EPIOCSPARAMS` — `_IOW(EPOLL_IOC_TYPE, 0x01, struct epoll_params)`.
pub const EPIOCSPARAMS: u64 = 0x4008_8A01;
/// `EPIOCGPARAMS` — `_IOR(EPOLL_IOC_TYPE, 0x02, struct epoll_params)`.
pub const EPIOCGPARAMS: u64 = 0x8008_8A02;

const BUDGET_OFF: u64 = 4;
const PREFER_OFF: u64 = 6;
const PAD_OFF: u64 = 7;

/// `ep_eventpoll_ioctl` on an epoll file. `None` when `file` is not an epoll
/// file, so the caller keeps walking its own dispatch; every command reaching
/// an epoll file that is not one of the two busy-poll parameter commands is
/// `EINVAL`, not `ENOTTY`.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn handle_epoll_ioctl(file: &Arc<File>, req: u64, arg: u64) -> Option<i64> {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    use super::policy::{validate_epoll_params, EPOLL_PARAMS_BYTES};
    let ep = super::epoll_inode_of(file)?;
    let einval = -(Errno::Einval.as_i32() as i64);
    match req {
        EPIOCSPARAMS => {
            if let Err(rv) = crate::userbuf::validate_user_buf(arg, EPOLL_PARAMS_BYTES, 1) { return Some(rv); }
            // SAFETY: arg validated readable for one struct epoll_params.
            let (usecs, budget, prefer, pad) = unsafe {
                (core::ptr::read_unaligned(arg as *const u32),
                 core::ptr::read_unaligned((arg + BUDGET_OFF) as *const u16),
                 core::ptr::read_unaligned((arg + PREFER_OFF) as *const u8),
                 core::ptr::read_unaligned((arg + PAD_OFF) as *const u8))
            };
            let cap = sched::current().map(|c| c.has_cap(sched::cap::NET_ADMIN)).unwrap_or(false);
            if let Err(e) = validate_epoll_params(usecs, budget, prefer, pad, cap) {
                return Some(-(e.as_i32() as i64));
            }
            ep.busy_poll_usecs.store(usecs, Ordering::Relaxed);
            ep.busy_poll_budget.store(budget as u32, Ordering::Relaxed);
            ep.prefer_busy_poll.store(prefer as u32, Ordering::Relaxed);
            Some(0)
        }
        EPIOCGPARAMS => {
            if let Err(rv) = crate::userbuf::validate_user_buf_writable(arg, EPOLL_PARAMS_BYTES, 1) { return Some(rv); }
            // SAFETY: arg validated writable for one struct epoll_params.
            unsafe {
                core::ptr::write_unaligned(arg as *mut u32, ep.busy_poll_usecs.load(Ordering::Relaxed));
                core::ptr::write_unaligned((arg + BUDGET_OFF) as *mut u16, ep.busy_poll_budget.load(Ordering::Relaxed) as u16);
                core::ptr::write_unaligned((arg + PREFER_OFF) as *mut u8, ep.prefer_busy_poll.load(Ordering::Relaxed) as u8);
                core::ptr::write_unaligned((arg + PAD_OFF) as *mut u8, 0u8);
            }
            Some(0)
        }
        _ => Some(einval),
    }
}
