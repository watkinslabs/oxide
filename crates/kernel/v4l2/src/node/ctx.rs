//! The command context inside the kernel: the clock, the wait, the caller's
//! memory, and the wake-up.

use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::device::VideoDevice;
use crate::ioctl::Ctx;
use crate::usermem::UserMem;

/// The calling process's address space.
pub struct KernelUser;

impl UserMem for KernelUser {
    /// # C: O(dst.len)
    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), Errno> {
        uaccess::copy_from_user(dst, addr)
    }
    /// # C: O(src.len)
    fn write(&self, addr: u64, src: &[u8]) -> Result<(), Errno> {
        uaccess::copy_to_user(addr, src)
    }
}

/// The kernel's command context.
pub struct KernelCtx {
    nonblocking: bool,
    user: KernelUser,
}

impl KernelCtx {
    /// Context for one command on a file whose blocking mode is `nonblocking`.
    /// # C: O(1)
    pub fn new(nonblocking: bool) -> KernelCtx { KernelCtx { nonblocking, user: KernelUser } }
}

/// Does the caller carry an unblocked pending signal? A blocking dequeue that
/// ignores this is unkillable: nothing else ends the sleep when the camera has
/// stopped producing frames.
/// # C: O(1)
fn signal_pending() -> bool {
    use core::sync::atomic::Ordering;
    match sched::live::current() {
        Some(task) => task.pending_signals() & !task.sigmask.load(Ordering::Acquire) != 0,
        None => false,
    }
}

impl Ctx for KernelCtx {
    /// # C: O(1)
    fn now(&self) -> (u64, u64) {
        let ns = timekeeper::monotonic_ns();
        (ns / 1_000_000_000, ns % 1_000_000_000)
    }
    /// # C: O(1)
    fn nonblocking(&self) -> bool { self.nonblocking }

    /// Park until a buffer completes, the stream stops, or a signal arrives.
    ///
    /// The predicate is re-tested by the caller, not here: a wake-up does not
    /// prove a buffer arrived, and it is the admission ladder that turns "the
    /// stream stopped while you waited" into the error the caller must get.
    /// # C: O(1), sleeps
    fn wait_for_buffer(&self, device: &Arc<VideoDevice>) -> Result<(), Errno> {
        if signal_pending() { return Err(Errno::Eintr); }
        let waiters = super::publish::waiters(device);
        // SAFETY: syscall process context inside VIDIOC_DQBUF with no device
        // lock held across the park; the wait list outlives the device because
        // it is owned by the same registration.
        unsafe { waiters.prepare_to_wait_interruptible(); }
        let ready = {
            let state = device.state.lock();
            !state.queue.done.is_empty() || !state.queue.streaming || state.queue.error
                || state.queue.last_buffer_dequeued
        };
        if ready || signal_pending() {
            waiters.cancel_current_park();
            return if signal_pending() { Err(Errno::Eintr) } else { Ok(()) };
        }
        // SAFETY: the wait list marked the running task sleeping and every
        // lock taken above has been released.
        unsafe { sched::live::schedule::schedule(); }
        if signal_pending() { return Err(Errno::Eintr); }
        Ok(())
    }

    /// # C: O(1)
    fn user(&self) -> &dyn UserMem { &self.user }

    /// # C: O(handles)
    fn wake(&self, device: &Arc<VideoDevice>) { super::publish::wake(device); }
}
