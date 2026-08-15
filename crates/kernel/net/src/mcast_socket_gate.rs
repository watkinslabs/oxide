use crate::netdev::{NetError, NetResult};

const OPS_CLOSED: usize = 1usize << (usize::BITS - 1);
const OPS_ACTIVE: usize = !OPS_CLOSED;

pub(crate) struct SocketMcastGate {
    state: core::sync::atomic::AtomicUsize,
    #[cfg(target_os = "oxide-kernel")]
    wait: sched::live::WaitList,
}

pub(crate) struct SocketMcastLease<'a> {
    state: &'a core::sync::atomic::AtomicUsize,
    #[cfg(target_os = "oxide-kernel")]
    wait: &'a sched::live::WaitList,
}

impl SocketMcastGate {
    pub(crate) const fn new() -> Self {
        Self {
            state: core::sync::atomic::AtomicUsize::new(0),
            #[cfg(target_os = "oxide-kernel")]
            wait: sched::live::WaitList::new(),
        }
    }

    pub(crate) fn enter(&self, released: &core::sync::atomic::AtomicBool)
        -> NetResult<SocketMcastLease<'_>> {
        use core::sync::atomic::Ordering;
        loop {
            let current = self.state.load(Ordering::Acquire);
            if current & OPS_CLOSED != 0 || released.load(Ordering::Acquire) {
                return Err(NetError::Einval);
            }
            if current & OPS_ACTIVE == OPS_ACTIVE { return Err(NetError::Einval); }
            if self.state.compare_exchange_weak(current, current + 1, Ordering::AcqRel,
                Ordering::Acquire).is_ok() {
                return Ok(SocketMcastLease {
                    state: &self.state,
                    #[cfg(target_os = "oxide-kernel")]
                    wait: &self.wait,
                });
            }
            sync::spin_relax::relax();
        }
    }

    pub(crate) fn close_wait(&self) {
        use core::sync::atomic::Ordering;
        self.state.fetch_or(OPS_CLOSED, Ordering::AcqRel);
        if self.state.load(Ordering::Acquire) == OPS_CLOSED { return; }
        #[cfg(target_os = "oxide-kernel")]
        if !sched::preempt::in_interrupt() {
            // The network-close path is process context. Use a canonical
            // predicate wait: lease drop publishes the count then wakes.
            // SAFETY: close from VFS file release has no socket operation lock
            // held and is in schedulable process context (checked above).
            let _ = unsafe {
                sched::live::wait_event_uninterruptible(&self.wait,
                    || self.state.load(Ordering::Acquire) == OPS_CLOSED)
            };
            return;
        }
        // A last `Arc<InetSocket>` can presently fall out of AF_PACKET RX
        // softirq. A live lease holds a borrow from a separate strong Arc, so
        // this branch is an invariant backstop, not a valid wait context. It
        // must nevertheless use the one shared relax step while that broader
        // lifetime mismatch remains.
        while self.state.load(Ordering::Acquire) != OPS_CLOSED {
            sync::spin_relax::relax();
        }
    }
}

impl Drop for SocketMcastLease<'_> {
    fn drop(&mut self) {
        use core::sync::atomic::Ordering;
        #[cfg(target_os = "oxide-kernel")]
        {
            let before = self.state.fetch_sub(1, Ordering::Release);
            if before == OPS_CLOSED + 1 { self.wait.wake_all(); }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        self.state.fetch_sub(1, Ordering::Release);
    }
}
