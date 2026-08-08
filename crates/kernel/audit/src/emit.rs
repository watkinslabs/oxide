// The one way a record enters the audit system.
//
// Order matters and is the whole contract: rate limit first, then backlog
// admission, then queueing. A record refused at either step is COUNTED, never
// silently dropped — the lost counter is what tells a consumer its log has a
// hole, so an uncounted drop is worse than no log at all.
//
// The decision runs against a borrowed [`AuditState`], so the hosted suite
// drives it on its own instance rather than the live one.

use crate::clock;
use crate::queue::backlog_admits;
use crate::ratelimit::{lost_print_check, rate_check};
use crate::uapi::AUDIT_FAIL_PANIC;
use crate::record::{self, Record};
use crate::state::{self, AuditState};

/// Why a record did not reach a queue.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The per-second ceiling refused it.
    RateLimited,
    /// The backlog is at its limit.
    BacklogFull,
    /// Audit is switched off and this producer only logs while it is on.
    Disabled,
}

/// Where an admitted record went.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Admitted {
    /// Queued for the registered consumer.
    Queued,
    /// Parked until a consumer registers.
    Held,
}

/// Admit one already-stamped record into `s`.
/// # C: O(1)
pub fn admit(s: &mut AuditState, r: Record, now_ms: u64) -> Result<Admitted, Refusal> {
    if !rate_check(&mut s.rate, s.cfg.rate_limit, now_ms) {
        note_lost(s, now_ms);
        return Err(Refusal::RateLimited);
    }
    let limit = s.cfg.backlog_limit;
    let (queued, held) = (s.backlog.len(), s.backlog.hold_len());
    if s.consumer.registered() {
        if !backlog_admits(queued, limit) { note_lost(s, now_ms); return Err(Refusal::BacklogFull); }
        s.backlog.push(r, limit);
        Ok(Admitted::Queued)
    } else {
        if !backlog_admits(held, limit) { note_lost(s, now_ms); return Err(Refusal::BacklogFull); }
        s.backlog.hold(r, limit);
        Ok(Admitted::Held)
    }
}

/// Account one dropped record, and warn about it at most once a second.
///
/// The counter is the durable half — userspace reads it and learns its log has
/// a hole. The console warning is the half that reaches an operator with no
/// consumer running at all, and is throttled because the reaction to a flood
/// must not itself be a flood.
/// # C: O(1)
fn note_lost(s: &mut AuditState, now_ms: u64) {
    s.cfg.count_lost();
    let always = s.cfg.failure == AUDIT_FAIL_PANIC;
    let print = lost_print_check(&mut s.last_lost_msg_ms, s.cfg.rate_limit, always, now_ms);
    #[cfg(feature = "debug-audit")]
    if print {
        klog::write_raw(b"[AUDIT] lost=");
        klog::write_dec_u64(s.cfg.lost as u64);
        klog::write_raw(b" rate_limit=");
        klog::write_dec_u64(s.cfg.rate_limit as u64);
        klog::write_raw(b" backlog_limit=");
        klog::write_dec_u64(s.cfg.backlog_limit as u64);
        klog::write_raw(b"\n");
    }
    #[cfg(not(feature = "debug-audit"))]
    let _ = print;
}

/// Build and queue one record on the live audit system.
///
/// Callers on a denial path ignore the result: there is nothing useful a
/// denied access can do about a full audit queue, and the counter has already
/// recorded the loss.
/// # C: O(body len)
pub fn log(ty: u16, body: &[u8]) -> Result<Admitted, Refusal> {
    let now_ms = clock::now_ms();
    let r = record::build(ty, clock::realtime_ns(), record::next_serial(), body);
    let out = state::with(|s| {
        let out = admit(s, r, now_ms);
        hal::kassert!(!fatal_loss(s.cfg.failure, &out),
                      "audit record lost under the panic failure mode");
        out
    });
    // Delivered here rather than by a drain loop the consumer drives: a record
    // that only moves when the consumer next speaks would sit in the queue for
    // as long as the system is quiet, which is exactly when it matters.
    if out == Ok(Admitted::Queued) { state::flush(); }
    out
}

/// Build and queue a record only while audit is switched on. Producers whose
/// reference gate is the enable state use this; the ones that log regardless
/// use [`log`].
/// # C: O(body len)
pub fn log_if_enabled(ty: u16, body: &[u8]) -> Result<Admitted, Refusal> {
    if !state::enabled() { return Err(Refusal::Disabled); }
    log(ty, body)
}

/// Whether losing this record must stop the system.
///
/// `AUDIT_FAIL_PANIC` is an operator asking for a machine that halts rather
/// than one that keeps running unaudited; honouring it is the whole reason the
/// failure mode is configurable, and the other two modes never halt.
/// # C: O(1)
pub fn fatal_loss(failure: u32, out: &Result<Admitted, Refusal>) -> bool {
    out.is_err() && failure == AUDIT_FAIL_PANIC
}

#[cfg(test)]
#[path = "tests/emit.rs"]
mod tests;
