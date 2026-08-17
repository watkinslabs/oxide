//! The live counter, what changes it, and the decision each site consults.
//!
//! A rate of zero is off, and off is the only state that costs nothing: the
//! decision reads one word and returns before touching the counter, so a mount
//! that never asked for injected failures pays a load and a branch at each
//! site and nothing else.
//!
//! The rate is a PERIOD, not a probability: every `rate`-th consultation
//! across all armed sites fails. One shared counter is what makes the failures
//! interleave the way a real allocator's do rather than clustering per site.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::errno::Errno;

use super::types::{Fault, Timeout, ALL_TYPES, FAULT_MAX, TIMEOUT_MAX};

/// The widest rate the interface admits. The value crosses a signed boundary
/// on the way in, so anything above it is a caller error rather than a
/// saturating clamp.
const MAX_RATE: u32 = i32::MAX as u32;

/// What a mount asked for, carried beside the rest of the option set.
///
/// `None` is "the mount did not name this", which is not the same as naming
/// zero: a remount that names neither leaves whatever the mount is already
/// running with, and one that names `fault_injection=0` turns it off.
///
/// The rate is signed because the interface that carries it is: a negative
/// value is accepted by the parser and refused by the builder, so it reaches
/// a mount that runs with injection off rather than a mount that fails.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Cfg {
    pub rate: Option<i32>,
    pub types: Option<u32>,
}

impl Cfg {
    /// Whether this mount asked for injection at all. # C: O(1)
    pub fn asked(&self) -> bool { self.rate.is_some() || self.types.is_some() }
}

/// Which fields a build call is allowed to touch.
///
/// The knobs are written one at a time and each write carries only its own
/// field, so a mask rather than a whole record is what crosses the boundary —
/// otherwise setting the rate would silently reset the type.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Which(pub u32);

impl Which {
    pub const RATE: Which = Which(1);
    pub const TYPE: Which = Which(2);
    pub const TIMEOUT: Which = Which(4);
    /// Reset everything, including the counters.
    pub const ALL: Which = Which(8);

    /// # C: O(1)
    pub fn has(self, other: Which) -> bool { self.0 & other.0 != 0 }
}

/// The live state one mount injects against.
#[derive(Debug)]
pub struct Info {
    rate: AtomicU32,
    types: AtomicU32,
    timeout: AtomicU32,
    /// Consultations since the last injected failure, shared across sites.
    ops: AtomicU32,
    /// How many failures each site has been given, for a report.
    count: [AtomicU32; FAULT_MAX as usize],
}

impl Default for Info {
    fn default() -> Self { Self::new() }
}

impl Info {
    /// A mount that has not asked for anything. # C: O(FAULT_MAX)
    pub fn new() -> Self {
        Self {
            rate: AtomicU32::new(0),
            types: AtomicU32::new(0),
            timeout: AtomicU32::new(0),
            ops: AtomicU32::new(0),
            count: core::array::from_fn(|_| AtomicU32::new(0)),
        }
    }

    /// Every `rate`-th consultation fails; zero is off. # C: O(1)
    pub fn rate(&self) -> u32 { self.rate.load(Ordering::Relaxed) }

    /// Which sites are armed. # C: O(1)
    pub fn types(&self) -> u32 { self.types.load(Ordering::Relaxed) }

    /// How a lock asked to time out does so. # C: O(1)
    pub fn timeout(&self) -> Timeout {
        Timeout::from_index(self.timeout.load(Ordering::Relaxed)).unwrap_or(Timeout::None)
    }

    /// Failures given to one site since the counters were reset. # C: O(1)
    pub fn count(&self, f: Fault) -> u32 { self.count[f as usize].load(Ordering::Relaxed) }

    /// Whether `f` is armed. # C: O(1)
    pub fn armed(&self, f: Fault) -> bool { self.types() & f.bit() != 0 }
}

/// Change the fields `which` names.
///
/// A rejected value changes nothing, which is what lets a caller write a knob
/// and read back either the new value or the old one, never a half-applied
/// pair.
/// # C: O(FAULT_MAX) resetting, O(1) otherwise
pub fn build(info: &Info, rate: u32, ty: u32, which: Which) -> Result<(), Errno> {
    if which.has(Which::ALL) {
        info.rate.store(0, Ordering::Relaxed);
        info.types.store(0, Ordering::Relaxed);
        info.timeout.store(0, Ordering::Relaxed);
        info.ops.store(0, Ordering::Relaxed);
        for c in &info.count { c.store(0, Ordering::Relaxed); }
        return Ok(());
    }
    // Validated before anything is stored: a call naming two fields, one of
    // them out of range, must leave both alone.
    if which.has(Which::RATE) && rate > MAX_RATE { return Err(Errno::Einval); }
    if which.has(Which::TYPE) && ty > ALL_TYPES { return Err(Errno::Einval); }
    if which.has(Which::TIMEOUT) && ty >= TIMEOUT_MAX { return Err(Errno::Einval); }

    if which.has(Which::RATE) {
        info.ops.store(0, Ordering::Relaxed);
        info.rate.store(rate, Ordering::Relaxed);
    }
    if which.has(Which::TYPE) { info.types.store(ty, Ordering::Relaxed); }
    if which.has(Which::TIMEOUT) { info.timeout.store(ty, Ordering::Relaxed); }
    Ok(())
}

/// Apply what one mount asked for to a fresh state.
///
/// Only the fields the mount named are touched, so a mount that asked for a
/// rate and no site list arms nothing and injects nothing — the same as the
/// mount that asked for neither, and deliberately so: naming a rate alone is
/// how a test turns the machinery on before choosing what to break.
///
/// A field the builder refuses is DROPPED rather than failing the mount. That
/// is the contract the mount interface has: the two values are range-checked
/// where they are stored, not where they are spelled, and a value past the end
/// of either range produces a mount that runs with that field unset. Refusing
/// the mount instead would break every caller relying on it.
/// # C: O(1)
pub fn apply(info: &Info, cfg: &Cfg) {
    // A negative rate needs no test of its own here: every negative value
    // widens to one above the interface's ceiling, so the builder's own range
    // check is what refuses it. A second guard would be a second place the
    // same rule lives, and the two could drift.
    if let Some(rate) = cfg.rate { let _ = build(info, rate as u32, 0, Which::RATE); }
    if let Some(ty) = cfg.types { let _ = build(info, 0, ty, Which::TYPE); }
}

/// Whether this consultation of `f` fails.
///
/// # C: O(1)
pub fn time_to_inject(info: &Info, f: Fault) -> bool {
    let rate = info.rate.load(Ordering::Relaxed);
    if rate == 0 { return false; }
    if info.types.load(Ordering::Relaxed) & f.bit() == 0 { return false; }
    let seen = info.ops.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    if seen < rate { return false; }
    info.ops.store(0, Ordering::Relaxed);
    info.count[f as usize].fetch_add(1, Ordering::Relaxed);
    true
}
