use crate::netdev::{NetError, NetResult};

const OPS_CLOSED: usize = 1usize << (usize::BITS - 1);
const OPS_ACTIVE: usize = !OPS_CLOSED;

pub(crate) struct SocketMcastGate { state: core::sync::atomic::AtomicUsize }

pub(crate) struct SocketMcastLease<'a> { state: &'a core::sync::atomic::AtomicUsize }

impl SocketMcastGate {
    pub(crate) const fn new() -> Self {
        Self { state: core::sync::atomic::AtomicUsize::new(0) }
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
                Ordering::Acquire).is_ok() { return Ok(SocketMcastLease { state: &self.state }); }
        }
    }

    pub(crate) fn close_wait(&self) {
        use core::sync::atomic::Ordering;
        self.state.fetch_or(OPS_CLOSED, Ordering::AcqRel);
        while self.state.load(Ordering::Acquire) != OPS_CLOSED {
            #[cfg(target_os = "oxide-kernel")]
            {
                // SAFETY: final socket release runs in schedulable process context.
                unsafe { sched::live::tick_yield(); }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            core::hint::spin_loop();
        }
    }
}

impl Drop for SocketMcastLease<'_> {
    fn drop(&mut self) {
        self.state.fetch_sub(1, core::sync::atomic::Ordering::Release);
    }
}
