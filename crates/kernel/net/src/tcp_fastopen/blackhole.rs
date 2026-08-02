// Blackhole detection: the namespace-wide pause on active fast open.
//
// Some middleboxes drop a SYN that carries data, or drop the server's reply to
// one, while passing an ordinary SYN untouched. A client that keeps trying
// fast open across such a path turns every connection into a retransmit
// timeout. The defence is to notice the pattern and stop offering fast open
// for a while — for the whole namespace, not one destination, because the
// offending box is on a path many destinations share.
//
// The pause is deliberately blunt and deliberately self-lengthening: each
// recurrence doubles it, up to sixty-four times the configured base, and a
// fast open that succeeds with data flowing over a real interface clears the
// count back to zero. `net.ipv4.tcp_fastopen_blackhole_timeout_sec` is the
// base; zero turns the whole mechanism off, which is the compiled default.
//
// The pause never costs a connection. It only ever downgrades a fast open to
// an ordinary handshake (`super::client`).
//
// No target gate: the arithmetic decides how long a host stops fast-opening,
// so it lives where `cargo test` compiles it (`docs/53§4`).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Nanoseconds in the second the sysctl counts in.
const NS_PER_SEC: u64 = 1_000_000_000;

/// The pause doubles per recurrence up to this shift, so the longest pause is
/// sixty-four times the configured base.
const MAX_DOUBLINGS: u32 = 6;

/// Consecutive retransmit timeouts on a fast open before the path is called a
/// blackhole. The third one is the trigger, so the count that reaches the
/// decision is two.
const TIMEOUTS_TO_BLACKHOLE: u32 = 2;

/// What the pause says about one active open.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Pause {
    /// No pause: either the mechanism is off or nothing has failed here.
    Off,
    /// Inside the pause. This open does not fast open.
    Held,
    /// The pause has run out. This open fast opens, and is marked so that a
    /// successful data exchange on it clears the recurrence count — the
    /// count is only trustworthy evidence while it is still being confirmed.
    Expired,
}

/// How long the pause lasts after `times` recurrences. # C: O(1)
pub fn pause_ns(timeout_sec: i64, times: u32) -> u64 {
    if timeout_sec <= 0 || times == 0 { return 0; }
    let base = (timeout_sec as u64).saturating_mul(NS_PER_SEC);
    base.saturating_mul(1u64 << core::cmp::min(times - 1, MAX_DOUBLINGS))
}

/// Whether an active open falls inside the pause. # C: O(1)
pub fn pause_at(timeout_sec: i64, times: u32, stamp_ns: u64, now_ns: u64) -> Pause {
    if timeout_sec <= 0 || times == 0 { return Pause::Off; }
    if now_ns.wrapping_sub(stamp_ns) < pause_ns(timeout_sec, times) { Pause::Held }
    else { Pause::Expired }
}

/// Whether one fast-open connection's retransmit history names the path a
/// blackhole. `expired` is whether the connection has run out of retransmit
/// budget altogether; short of that it takes the third consecutive timeout.
/// A connection that never fast-opened proves nothing about the path.
/// # C: O(1)
pub fn detect(syn_fastopen: bool, syn_data: bool, syn_data_acked: bool,
              timeouts: u32, expired: bool) -> bool
{
    if !(syn_fastopen || syn_data || syn_data_acked) { return false; }
    timeouts == TIMEOUTS_TO_BLACKHOLE || (timeouts < TIMEOUTS_TO_BLACKHOLE && expired)
}

/// A namespace's pause on active fast open.
#[derive(Default)]
pub struct Blackhole {
    /// How many times a blackhole has been detected here without an
    /// intervening success. Zero means no pause is running.
    times: AtomicU32,
    /// When the most recent detection was recorded.
    stamp_ns: AtomicU64,
}

impl Blackhole {
    /// # C: O(1)
    pub const fn new() -> Self { Self { times: AtomicU32::new(0), stamp_ns: AtomicU64::new(0) } }

    /// Record one detection, lengthening the pause. A zero timeout turns the
    /// mechanism off entirely: nothing is recorded, so nothing has to be
    /// unwound when an administrator turns it back on. # C: O(1)
    pub fn disable(&self, timeout_sec: i64, now_ns: u64) {
        if timeout_sec <= 0 { return; }
        self.stamp_ns.store(now_ns, Ordering::Release);
        self.times.fetch_add(1, Ordering::AcqRel);
    }

    /// # C: O(1)
    pub fn pause(&self, timeout_sec: i64, now_ns: u64) -> Pause {
        pause_at(timeout_sec, self.times.load(Ordering::Acquire),
            self.stamp_ns.load(Ordering::Acquire), now_ns)
    }

    /// A fast open succeeded with data flowing: the path is not blackholed
    /// after all. # C: O(1)
    pub fn reset(&self) { self.times.store(0, Ordering::Release); }

    /// # C: O(1)
    pub fn times(&self) -> u32 { self.times.load(Ordering::Acquire) }
}

#[cfg(test)]
#[path = "blackhole_tests.rs"]
mod tests;
