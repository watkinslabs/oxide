//! The decision a filesystem actually enforces: does this allocation fit?
//!
//! Four rules, and each one is a place a plausible-looking implementation
//! gets it wrong:
//!
//! - **Zero is unlimited, not zero.** A limit of zero means the identity is
//!   unconstrained on that axis. Treating it as a limit of nothing denies
//!   every write by an identity that has a record at all.
//! - **A soft limit is not a hard one.** Crossing it is allowed; what it
//!   starts is a clock. Denying at the soft limit denies writes the quota
//!   deliberately permits.
//! - **The clock is stored, not implied.** The first crossing sets an
//!   absolute expiry from the file's grace; only once that time is reached
//!   does the soft limit deny. A caller that forgets to persist the returned
//!   expiry restarts the grace on every allocation, so it never expires.
//! - **Some callers are exempt from the hard limits and none from the
//!   clock.** The privileged caller's allocation goes through, and it still
//!   starts the grace that a later unprivileged one is measured against.
//!
//! A reservation is stricter than an allocation: it may not cross the soft
//! limit at all, because the space it promises would have to come from the
//! grace of a caller who has not asked for it yet.

use super::dqblk::Dqblk;

/// What the caller may do about one allocation.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// It fits.
    Allow,
    /// It fits, and it is the first crossing of the soft limit: the caller
    /// must store this absolute expiry in the record, or the grace never
    /// starts running.
    AllowStartingGrace(u64),
    /// It does not fit.
    Deny,
}

impl Verdict {
    /// Whether the allocation proceeds. # C: O(1)
    pub fn allowed(self) -> bool { !matches!(self, Verdict::Deny) }
}

/// What the caller is, and what the file says, at the moment of the decision.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Ask {
    /// Now, in the same scale the record's expiries are in.
    pub now: u64,
    /// Seconds of grace this file grants after a soft limit is first crossed.
    pub grace: u64,
    /// Whether the caller may exceed a hard limit. Privileged callers may,
    /// which is what keeps a full volume recoverable.
    pub exempt: bool,
    /// Whether this mount enforces limits at all. Usage is tracked even when
    /// it does not, so the record still has to be updated.
    pub enforced: bool,
    /// Whether this is a real allocation rather than a reservation.
    pub allocating: bool,
}

/// Whether adding `delta` bytes of space fits.
///
/// Measured against what the identity occupies AND what it has been promised:
/// a promise that is not counted can be handed to two callers, and the second
/// one to take it up puts the identity past a limit both were told they fit
/// under. # C: O(1)
pub fn space(d: &Dqblk, delta: u64, ask: &Ask) -> Verdict {
    if !ask.enforced { return Verdict::Allow; }
    let total = total_space(d).saturating_add(delta);
    decide(d.bhardlimit, d.bsoftlimit, total, d.btime, ask)
}

/// Space an identity holds: what it occupies plus what it is promised.
/// # C: O(1)
pub fn total_space(d: &Dqblk) -> u64 { d.curspace.saturating_add(d.rsvspace) }

/// Whether adding `delta` inodes fits.
///
/// An inode is never reserved ahead of its allocation, so the reservation
/// rule does not apply here. # C: O(1)
pub fn inodes(d: &Dqblk, delta: u64, ask: &Ask) -> Verdict {
    if !ask.enforced { return Verdict::Allow; }
    let total = d.curinodes.saturating_add(delta);
    let ask = Ask { allocating: true, ..*ask };
    decide(d.ihardlimit, d.isoftlimit, total, d.itime, &ask)
}

/// The one rule both axes follow.
fn decide(hard: u64, soft: u64, total: u64, expiry: u64, ask: &Ask) -> Verdict {
    if hard != 0 && total > hard && !ask.exempt { return Verdict::Deny; }
    if soft != 0 && total > soft {
        if expiry != 0 {
            // The grace is running. It denies only once it has run out.
            if ask.now >= expiry && !ask.exempt { return Verdict::Deny; }
            return Verdict::Allow;
        }
        // First crossing. A reservation may not take grace it has not used.
        if !ask.allocating { return Verdict::Deny; }
        return Verdict::AllowStartingGrace(ask.now.saturating_add(ask.grace));
    }
    Verdict::Allow
}

/// Apply a verdict to a record, so the caller has one place that both decides
/// and accounts.
///
/// Usage moves whether or not limits are enforced; that is the difference
/// between a mount that tracks and a mount that enforces, and a filesystem
/// that only updates on the enforcing path hands the next mount a record that
/// disagrees with the volume.
/// # C: O(1)
pub fn apply_space(d: &mut Dqblk, delta: u64, v: Verdict) -> bool {
    if let Verdict::AllowStartingGrace(t) = v { d.btime = t; }
    if v.allowed() { d.curspace = d.curspace.saturating_add(delta); }
    v.allowed()
}

/// Apply a verdict as a PROMISE rather than an allocation: the space is held
/// against the identity's limits without anything occupying it yet, and is
/// either taken up by [`claim_space`] or given back by [`release_reserved`].
/// # C: O(1)
pub fn apply_reserve(d: &mut Dqblk, delta: u64, v: Verdict) -> bool {
    if let Verdict::AllowStartingGrace(t) = v { d.btime = t; }
    if v.allowed() { d.rsvspace = d.rsvspace.saturating_add(delta); }
    v.allowed()
}

/// Apply an inode verdict. # C: O(1)
pub fn apply_inodes(d: &mut Dqblk, delta: u64, v: Verdict) -> bool {
    if let Verdict::AllowStartingGrace(t) = v { d.itime = t; }
    if v.allowed() { d.curinodes = d.curinodes.saturating_add(delta); }
    v.allowed()
}

/// Take up `delta` bytes of a promise: the space is now occupied rather than
/// promised, and the two together do not move.
///
/// A caller claiming more than it was promised is a bug in the caller, and
/// the claim is clamped rather than allowed to wrap the count into an
/// enormous one. # C: O(1)
pub fn claim_space(d: &mut Dqblk, delta: u64) {
    let n = delta.min(d.rsvspace);
    d.rsvspace -= n;
    d.curspace = d.curspace.saturating_add(n);
}

/// Turn occupied space back into a promise, for space that is being
/// rewritten rather than released. # C: O(1)
pub fn reclaim_space(d: &mut Dqblk, delta: u64) {
    let n = delta.min(d.curspace);
    d.curspace -= n;
    d.rsvspace = d.rsvspace.saturating_add(n);
}

/// Give back a promise nothing took up. # C: O(1)
pub fn release_reserved(d: &mut Dqblk, delta: u64) {
    d.rsvspace = d.rsvspace.saturating_sub(delta);
    stop_clock(d);
}

/// Give back `delta` bytes, clearing the grace once usage is back under the
/// soft limit. A grace left set after the usage drops denies the identity's
/// next allocation for a limit it is no longer over. # C: O(1)
pub fn free_space(d: &mut Dqblk, delta: u64) {
    d.curspace = d.curspace.saturating_sub(delta);
    stop_clock(d);
}

/// Stop the space grace once the identity is back under its soft limit.
///
/// Measured against occupied AND promised space, the same total the limit was
/// measured against: stopping the clock while a promise still holds the
/// identity over the limit restarts the whole grace when that promise is
/// taken up. # C: O(1)
fn stop_clock(d: &mut Dqblk) {
    if total_space(d) <= d.bsoftlimit { d.btime = 0; }
}

/// Give back `delta` inodes, on the same rule. # C: O(1)
pub fn free_inodes(d: &mut Dqblk, delta: u64) {
    d.curinodes = d.curinodes.saturating_sub(delta);
    if d.isoftlimit == 0 || d.curinodes <= d.isoftlimit { d.itime = 0; }
}

/// What `statfs` reports for one identity: the narrower of the two limits,
/// and what is left under it.
///
/// Zero on both means unconstrained, and that is reported as no limit rather
/// than as a full volume.
/// # C: O(1)
pub fn effective_limit(hard: u64, soft: u64) -> Option<u64> {
    match (hard, soft) {
        (0, 0) => None,
        (0, s) => Some(s),
        (h, 0) => Some(h),
        (h, s) => Some(h.min(s)),
    }
}

/// Space still available to an identity, in bytes, or `None` when it is
/// unconstrained. # C: O(1)
pub fn space_remaining(d: &Dqblk) -> Option<u64> {
    let limit = effective_limit(d.bhardlimit, d.bsoftlimit)?;
    Some(limit.saturating_sub(total_space(d)))
}

/// Inodes still available to an identity. # C: O(1)
pub fn inodes_remaining(d: &Dqblk) -> Option<u64> {
    let limit = effective_limit(d.ihardlimit, d.isoftlimit)?;
    Some(limit.saturating_sub(d.curinodes))
}
