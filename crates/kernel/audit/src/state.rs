// The single live audit system: configuration, consumer registration, the
// record queues and the rate limiter, under one lock.
//
// One lock rather than one per field, because every decision on the emit path
// reads several of them together — a record admitted against a rate limit that
// changed between the two reads would be accounted to neither window.

extern crate alloc;

use sync::{Spinlock, Tracepoint as AuditLockClass};

use crate::config::Config;
use crate::consumer::Consumer;
use crate::queue::Backlog;
use crate::ratelimit::RateState;

/// Everything the audit system owns.
pub struct AuditState {
    pub cfg: Config,
    pub consumer: Consumer,
    pub backlog: Backlog,
    pub rate: RateState,
    /// When the "records were lost" warning was last emitted.
    pub last_lost_msg_ms: u64,
}

impl AuditState {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            cfg: Config::new(),
            consumer: Consumer { pid: 0, port_id: 0, route: 0 },
            backlog: Backlog::new(),
            rate: RateState { messages: 0, last_check_ms: 0 },
            last_lost_msg_ms: 0,
        }
    }
}

static AUDIT: Spinlock<AuditState, AuditLockClass> = Spinlock::new(AuditState::new());

/// Run `f` against the live audit system.
/// # C: O(f)
pub fn with<R>(f: impl FnOnce(&mut AuditState) -> R) -> R { f(&mut AUDIT.lock()) }

/// Whether audit is switched on. Producers that the reference gates on this
/// read it before building a record body at all, so a disabled system costs
/// nothing beyond one lock acquisition.
/// # C: O(1)
pub fn enabled() -> bool { with(|s| s.cfg.enabled != crate::uapi::AUDIT_OFF) }

/// How the transport delivers one record. Returns `false` when the consumer
/// could not take it, which puts it back on the hold queue.
pub type Sender = fn(route: u64, port_id: u32, ty: u16, text: &[u8]) -> bool;

static SENDER: Spinlock<Option<Sender>, AuditLockClass> = Spinlock::new(None);

/// Install the transport that carries records to the registered consumer.
/// Idempotent, so the transport can register on its first use rather than
/// needing a boot-order slot of its own.
/// # C: O(1)
pub fn set_sender(f: Sender) { *SENDER.lock() = Some(f); }

/// Hand every deliverable record to the transport.
///
/// The state lock is dropped before the transport runs: delivery reaches a
/// socket's receive queue, and holding the audit lock across that would put
/// the whole audit system behind one consumer's buffer. A record the transport
/// refuses goes back on the hold queue rather than being lost, so a consumer
/// whose buffer is momentarily full does not create a hole in its own log.
/// # C: O(N_queued)
pub fn flush() {
    let Some(send) = *SENDER.lock() else { return };
    loop {
        let Some((route, port_id, r)) = with(|s| {
            if !s.consumer.registered() { return None; }
            let (route, port_id) = (s.consumer.route, s.consumer.port_id);
            s.backlog.pop().map(|r| (route, port_id, r))
        }) else { return };
        if send(route, port_id, r.ty, &r.text) { continue; }
        with(|s| {
            let limit = s.cfg.backlog_limit;
            if !s.backlog.hold(r, limit) { s.cfg.count_lost(); }
        });
        return;
    }
}

#[cfg(test)]
#[path = "tests/state.rs"]
mod tests;
