//! Timerfd file operations and expiration consumption.

use alloc::vec::Vec;

use vfs::{FileOps, Inode, KResult, VfsError};

use super::model::{TimerfdData, monotonic_ns};
use super::state::TimerfdState;

/// Timerfd inode file operations. # C: O(1)
pub(super) struct TimerfdFileOps;

impl FileOps for TimerfdFileOps {
    /// Report POLLIN only when expiration or cancellation is observable.
    /// # C: O(1)
    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn poll(&self, inode: &Inode) -> u32 {
        let d = match inode.private::<TimerfdData>() { Some(d) => d, None => return 0 };
        let mut state = d.state.lock();
        let now_mono = monotonic_ns();
        let now_real = vfs::inode_times::realtime_now_ns();
        state.refresh_expirations(now_mono, now_real);
        if state.cancel_pending { return vfs::POLL_IN; }
        if state.ticks != 0 { return vfs::POLL_IN; }
        let expiry = state.projected_expiry(now_mono, now_real);
        if expiry != 0 && now_mono >= expiry {
            #[cfg(any(feature = "debug-desktop", feature = "debug-mutter-timer-verbose"))]
            super::debug::event(b"ready", d.id, d.clockid, 0, expiry, now_mono);
            vfs::POLL_IN
        } else { 0 }
    }

    /// Return the projected host-monotonic wake deadline. # C: O(1)
    fn poll_deadline_ns(&self, file: &vfs::File) -> Option<u64> {
        let d = file.inode().private::<TimerfdData>()?;
        let expiry = d.state.lock().projected_expiry(
            monotonic_ns(),
            vfs::inode_times::realtime_now_ns(),
        );
        if expiry == 0 { None } else { Some(expiry) }
    }

    /// Consume one timerfd expiration record, blocking when unready. # C: O(1)
    fn read(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < 8 { return Err(VfsError::Einval); }
        let d = match inode.private::<TimerfdData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        loop {
            let now_mono = monotonic_ns();
            let now_real = vfs::inode_times::realtime_now_ns();
            let mut state = d.state.lock();
            match timerfd_take_expirations(&mut state, now_mono, now_real, buf) {
                Ok(Some(n)) => {
                    drop(state);
                    d.poll_subscribers.notify_mask(vfs::POLL_IN);
                    return Ok(n);
                }
                Err(e) => {
                    drop(state);
                    return Err(e);
                }
                Ok(None) => {}
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                // A deliverable signal ends the wait; the read is restarted
                // rather than reported as EINTR, so an SA_RESTART handler
                // resumes it transparently.
                if sched::live::sigpend::deliverable_signals_self() != 0 {
                    drop(state);
                    return Err(VfsError::Erestartsys);
                }
                let deadline = state.projected_expiry(now_mono, now_real);
                // SAFETY: process context; this timerfd's deadline scanner wakes the parked reader.
                unsafe { d.read_waiters.park_interruptible_with_deadline(deadline); }
                drop(state);
                // SAFETY: reader published Sleeping through its wait list and holds no locks.
                unsafe { sched::live::schedule::schedule(); }
            }
            #[cfg(not(target_os = "oxide-kernel"))] {
                drop(state);
                return Err(VfsError::Eagain);
            }
        }
    }

    /// Consume one timerfd expiration record without blocking. # C: O(1)
    fn read_nonblock(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < 8 { return Err(VfsError::Einval); }
        let d = inode.private::<TimerfdData>().ok_or(VfsError::Einval)?;
        let now_mono = monotonic_ns();
        let now_real = vfs::inode_times::realtime_now_ns();
        let mut state = d.state.lock();
        match timerfd_take_expirations(&mut state, now_mono, now_real, buf)? {
            Some(n) => {
                drop(state);
                d.poll_subscribers.notify_mask(vfs::POLL_IN);
                Ok(n)
            }
            None => Err(VfsError::Eagain),
        }
    }

    /// Timerfds are not writable. # C: O(1)
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> {
        Err(VfsError::Einval)
    }

    /// `show_fdinfo`. # C: O(1)
    fn fdinfo_extra(&self, inode: &Inode, out: &mut Vec<u8>) {
        let Some(d) = inode.private::<TimerfdData>() else { return };
        let now_mono = monotonic_ns();
        let now_real = vfs::inode_times::realtime_now_ns();
        let (ticks, flags, spec) = {
            let mut state = d.state.lock();
            let spec = state.snapshot(now_mono, now_real);
            (state.ticks, state.settime_flags, spec)
        };
        super::fdinfo::render(out, d.clockid, ticks, flags, spec);
    }
}

/// Copy the next accumulated expiration count to a native u64 record.
/// # C: O(1)
pub(super) fn timerfd_take_expirations(
    state: &mut TimerfdState,
    now_mono: u64,
    now_real: u64,
    buf: &mut [u8],
) -> KResult<Option<usize>> {
    let Some(ticks) = state.take_expirations(now_mono, now_real)? else {
        return Ok(None);
    };
    buf[..8].copy_from_slice(&ticks.to_ne_bytes());
    Ok(Some(8))
}
