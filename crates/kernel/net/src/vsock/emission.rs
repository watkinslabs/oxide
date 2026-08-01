use core::sync::atomic::Ordering;
use sync::{Guard, Socket as SockLockClass};

use super::{tx_for, VsockConn, VsockState, VIRTIO_VSOCK_OP_CREDIT_UPDATE};

pub(crate) struct EmissionGuard<'a> {
    conn: &'a VsockConn,
    guard: Option<Guard<'a, (), SockLockClass>>,
}

/// Drain deferred credit work while the caller owns `emit`. # C: O(callbacks)
fn flush_credit_update(c: &VsockConn) {
    while c.credit_update_pending.swap(false, Ordering::AcqRel) {
        let header = {
            let tx = c.tx.lock();
            let state = c.st.lock();
            if *state == VsockState::Closed { continue; }
            c.make_hdr_with_credit(&tx.credit, VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0, 0)
        };
        let _ = tx_for(c.owner, &header, &[]);
    }
}

fn finish_credit_updates<'a>(c: &'a VsockConn, mut guard: Guard<'a, (), SockLockClass>) {
    loop {
        flush_credit_update(c);
        #[cfg(test)]
        if c.inject_tail_credit.swap(false, Ordering::AcqRel) { send_credit_update(c); }
        drop(guard);
        if !c.credit_update_pending.load(Ordering::Acquire) { return; }
        let Some(next) = c.emit.try_lock() else { return; };
        guard = next;
    }
}

/// Arm one tail-window credit update on THIS connection. # C: O(1)
#[cfg(test)]
pub(crate) fn inject_tail_credit_for_test(c: &VsockConn) {
    c.inject_tail_credit.store(true, Ordering::Release);
}

impl Drop for EmissionGuard<'_> {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            finish_credit_updates(self.conn, guard);
        }
    }
}

/// Serialize one connection emission with tail-safe deferred work. # C: O(callbacks)
pub(crate) fn lock_emission(c: &VsockConn) -> EmissionGuard<'_> {
    EmissionGuard { conn: c, guard: Some(c.emit.lock()) }
}

/// Publish or defer one credit update without re-entering `emit`. # C: O(callbacks)
pub(super) fn send_credit_update(c: &VsockConn) {
    c.credit_update_pending.store(true, Ordering::Release);
    let Some(guard) = c.emit.try_lock() else { return; };
    finish_credit_updates(c, guard);
}
