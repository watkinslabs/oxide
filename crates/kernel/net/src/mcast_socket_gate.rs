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
            // B1409: `InetSocket::release_file()` can now run from softirq
            // (`packet.rs::deliver()`'s Weak-upgraded temp clone dropping the
            // last ref). `tick_yield()` calls `schedule()` and is documented
            // process/kthread-only (`# Ctx: process|kthread; preempt-off;
            // IRQs-on`) — a softirq/hard-IRQ caller must never reach it, so
            // fall back to a bare spin exactly like the hosted/non-kernel
            // path already does below. An in-flight lease implies a live
            // `Arc<InetSocket>` elsewhere, which by construction cannot
            // overlap this socket's OWN last-ref Drop; this is defense in
            // depth, not the expected case.
            #[cfg(target_os = "oxide-kernel")]
            if sched::preempt::in_interrupt() { core::hint::spin_loop(); continue; }
            #[cfg(target_os = "oxide-kernel")]
            {
                // SAFETY: final socket release runs in schedulable process context (checked above).
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
