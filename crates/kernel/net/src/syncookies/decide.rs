// When a cookie is sent instead of a request being queued, and how long a
// listener stays willing to believe one. Pure decisions over the sysctl value
// and two clock readings; no target gate.
//
// `net.ipv4.tcp_syncookies` has three states, not two:
//   0 — never. A SYN arriving on a full queue is dropped, which is what makes
//       an exhausted SYN queue refuse connections the peer is entitled to.
//   1 — fall back. The queue is used until it is full; only then does a SYN
//       get a cookie instead of a slot. This is the default.
//   2 — always. The SYN queue is never consulted at all, so no per-request
//       state is ever held. Testing knob upstream, and the only mode in which
//       the queue's own capacity stops mattering.
//
// The willingness to *believe* a cookie is separate from the willingness to
// send one, and deliberately narrower: a listener accepts a cookie only while
// its queue overflowed recently. Without that, every listener in the system
// would spend a hash on every stray acknowledgement it ever receives, and an
// off-path attacker would get an unlimited oracle against the secret. Mode 2
// stamps the overflow itself, since its queue never overflows.

/// `net.ipv4.tcp_syncookies` values.
pub const OFF: i64 = 0;
pub const WHEN_FULL: i64 = 1;
pub const ALWAYS: i64 = 2;

/// The minute the cookie counter advances on.
pub const SYNCOOKIE_PERIOD_NS: u64 = 60_000_000_000;

/// How long after an overflow a listener still believes cookies: the same
/// two-minute span [`super::cookie::MAX_SYNCOOKIE_AGE`] bounds a cookie's own
/// life by.
pub const SYNCOOKIE_VALID_NS: u64 =
    SYNCOOKIE_PERIOD_NS * super::cookie::MAX_SYNCOOKIE_AGE as u64;

/// How often the overflow stamp is rewritten. Rewriting it on every cookie
/// would dirty a shared line once per SYN of a flood, which is the one moment
/// that costs most.
pub const OVERFLOW_STAMP_PERIOD_NS: u64 = 1_000_000_000;

/// A listener that has never overflowed. The reference reads a jiffies field
/// whose zero is a real time and works around the ambiguity with a biased
/// window; a monotonic nanosecond count has no such spare value, so "never" is
/// named explicitly instead.
pub const NEVER: u64 = u64::MAX;

/// What to do with one arriving SYN.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Admit {
    /// Hold a request in the SYN queue and answer from it.
    Queue,
    /// Answer with a cookie and hold nothing.
    Cookie,
    /// Refuse; the peer retransmits its SYN.
    Drop,
}

/// The three-state decision. `syn_queue_full` is only consulted in the modes
/// that care, so a caller may pass whatever it knows when the mode is
/// [`ALWAYS`]. # C: O(1)
pub fn admit(mode: i64, syn_queue_full: bool) -> Admit {
    if mode == ALWAYS { return Admit::Cookie; }
    if !syn_queue_full { return Admit::Queue; }
    if mode == OFF { Admit::Drop } else { Admit::Cookie }
}

/// The minute counter a cookie minted now carries. # C: O(1)
pub const fn cookie_time(now_ns: u64) -> u32 { (now_ns / SYNCOOKIE_PERIOD_NS) as u32 }

/// Whether the overflow stamp needs rewriting. # C: O(1)
pub const fn restamp_overflow(last_ns: u64, now_ns: u64) -> bool {
    last_ns == NEVER || now_ns < last_ns || now_ns > last_ns + OVERFLOW_STAMP_PERIOD_NS
}

/// Whether this listener has NOT overflowed recently enough to believe a
/// cookie. The lower edge is slack by one stamp period because a concurrent
/// overflow may write the stamp after the clock was read. # C: O(1)
pub const fn no_recent_overflow(last_ns: u64, now_ns: u64) -> bool {
    if last_ns == NEVER { return true; }
    now_ns < last_ns.saturating_sub(OVERFLOW_STAMP_PERIOD_NS)
        || now_ns > last_ns + SYNCOOKIE_VALID_NS
}
