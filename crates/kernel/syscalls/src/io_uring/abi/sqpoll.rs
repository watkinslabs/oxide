// `IORING_SETUP_SQPOLL` / `IORING_SETUP_SQ_AFF` — every decision the
// submission-polling thread makes, with none of the machinery that runs it.
//
// The thread itself is target-gated (`io_uring/sqpoll.rs`), so anything left
// there is invisible to `cargo test` (CLAUDE.md phantom-test rule). What lives
// here is exactly what can be wrong: the idle-window arithmetic, the pin-CPU
// admission, and — the one that turns a bug into a hang — the wakeup
// handshake.
//
// The handshake, stated once so both sides can be checked against it:
//
//   submitter                          poll thread
//   ---------                          -----------
//   store SQ tail                      store IORING_SQ_NEED_WAKEUP
//   <full barrier>                     <full barrier>
//   load  sq_flags                     load  SQ tail
//   if NEED_WAKEUP: enter(SQ_WAKEUP)   if tail moved: do not sleep
//
// Two stores, two loads, a full barrier between each pair: at least one side
// observes the other's store. If the submitter's tail store is visible to the
// thread's tail load, the thread stays awake and drains it. If it is not, then
// the thread's flag store preceded the submitter's flag load, so the submitter
// sees NEED_WAKEUP and rings the doorbell. Dropping either barrier, or
// checking the tail BEFORE publishing the flag, loses the entry in the window
// between them and the submitter waits forever.

use syscall::errno::Errno;

use super::uapi::{
    IORING_SETUP_ATTACH_WQ, IORING_SETUP_SQ_AFF, IORING_SETUP_SQPOLL,
    IORING_SQ_NEED_WAKEUP,
};

/// The idle window a poll thread keeps spinning for after its last unit of
/// work, when the caller named none. Linux states it as `HZ` — one second.
pub const DEFAULT_SQ_THREAD_IDLE_MS: u32 = 1_000;

/// Nanoseconds per millisecond; `p->sq_thread_idle` is milliseconds.
pub const NSEC_PER_MSEC: u64 = 1_000_000;

/// Entries one ring may take per pass when a poll thread serves several, so a
/// busy ring cannot starve its neighbours.
pub const SQPOLL_CAP_ENTRIES: u32 = 8;

/// `ctx->sq_thread_idle`: how long the thread spins on an empty ring before it
/// publishes `IORING_SQ_NEED_WAKEUP` and sleeps. Zero means the caller
/// expressed no preference, which is the default window rather than "never
/// spin" — a zero window would make every submission pay a wakeup, which is
/// the cost `IORING_SETUP_SQPOLL` exists to avoid. # C: O(1)
pub fn sq_thread_idle_ns(sq_thread_idle_ms: u32) -> u64 {
    let ms = if sq_thread_idle_ms == 0 { DEFAULT_SQ_THREAD_IDLE_MS } else { sq_thread_idle_ms };
    (ms as u64).saturating_mul(NSEC_PER_MSEC)
}

/// Which processor the poll thread is pinned to, or `None` for "wherever the
/// scheduler likes".
///
/// `allowed` is the mask the creating task itself may run on: Linux tests
/// `p->sq_thread_cpu` against `cpuset_cpus_allowed(current)`, so a task
/// confined to a cpuset cannot escape it by asking for a poll thread on a
/// processor outside it. A processor past the mask's width, one that is not
/// online, or one outside that mask is `EINVAL`, and so is `IORING_SETUP_SQ_AFF`
/// without `IORING_SETUP_SQPOLL` — there is no thread to pin. # C: O(1)
pub fn sq_cpu(flags: u32, sq_thread_cpu: u32, allowed: u64) -> Result<Option<u32>, Errno> {
    if flags & IORING_SETUP_SQ_AFF == 0 { return Ok(None); }
    if flags & IORING_SETUP_SQPOLL == 0 { return Err(Errno::Einval); }
    if sq_thread_cpu >= u64::BITS { return Err(Errno::Einval); }
    if allowed & (1u64 << sq_thread_cpu) == 0 { return Err(Errno::Einval); }
    Ok(Some(sq_thread_cpu))
}

/// Entries one pass may take. # C: O(1)
pub fn cap_submit(to_submit: u32, shared: bool) -> u32 {
    if shared && to_submit > SQPOLL_CAP_ENTRIES { SQPOLL_CAP_ENTRIES } else { to_submit }
}

/// Submission entries userspace has published and the kernel has not consumed.
/// Head and tail are free-running counters masked only at access time, so the
/// difference is wraparound-correct. # C: O(1)
pub fn sq_ready(sq_tail: u32, sq_head: u32) -> u32 { sq_tail.wrapping_sub(sq_head) }

/// Whether the SQ ring has no room for another entry — what
/// `IORING_ENTER_SQ_WAIT` waits to stop being true. # C: O(1)
pub fn sq_full(sq_tail: u32, sq_head: u32, sq_entries: u32) -> bool {
    sq_ready(sq_tail, sq_head) >= sq_entries
}

/// Publish the doorbell. This is the store the whole handshake rests on: while
/// it is set, a submitter is obliged to call `io_uring_enter` with
/// `IORING_ENTER_SQ_WAKEUP` instead of relying on the thread noticing.
/// # C: O(1)
pub fn arm_need_wakeup(sq_flags: u32) -> u32 { sq_flags | IORING_SQ_NEED_WAKEUP }

/// Retract the doorbell — the thread is awake, so a submitter must not pay for
/// a syscall it does not need. # C: O(1)
pub fn disarm_need_wakeup(sq_flags: u32) -> u32 { sq_flags & !IORING_SQ_NEED_WAKEUP }

/// Whether a submitter reading this `sq_flags` must ring the doorbell.
/// # C: O(1)
pub fn wakeup_required(sq_flags: u32) -> bool { sq_flags & IORING_SQ_NEED_WAKEUP != 0 }

/// What the poll thread observes at the top of one pass.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Observed {
    /// The ring is gone, or someone asked the thread to exit.
    pub stop: bool,
    /// A park was requested: stand down until it is released.
    pub park: bool,
    /// The ring was created `IORING_SETUP_R_DISABLED` and not yet enabled, so
    /// its entries are not the thread's to consume.
    pub disabled: bool,
    /// Entries userspace has published and nobody has taken.
    pub sq_ready: u32,
    /// This poll thread serves more than one ring.
    pub shared: bool,
    pub now_ns: u64,
}

/// What the thread does about it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    /// Leave the loop and exit.
    Stop,
    /// Stand down until unparked.
    Park,
    /// Drain this many entries.
    Submit(u32),
    /// Nothing to do, but the idle window has not closed: stay hot.
    Spin,
    /// The idle window closed with nothing to do: publish the doorbell,
    /// re-check the tail, and sleep if it is still empty.
    Idle,
}

/// The idle deadline the loop carries between passes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PollState {
    pub idle_ns: u64,
    /// Monotonic instant past which an empty ring means "sleep". Zero until
    /// the first pass arms it, which makes a thread that has never had work
    /// sleep at once rather than spin for a window it never earned.
    pub deadline_ns: u64,
}

impl PollState {
    /// # C: O(1)
    pub fn new(idle_ns: u64) -> Self { Self { idle_ns, deadline_ns: 0 } }

    /// Re-arm the idle window. Every unit of work does this, and so does
    /// coming back from a sleep: the window measures time since the thread was
    /// last useful, not time since it started. # C: O(1)
    pub fn touch(&mut self, now_ns: u64) {
        self.deadline_ns = now_ns.saturating_add(self.idle_ns);
    }
}

/// One pass's decision. # C: O(1)
pub fn step(st: &PollState, o: &Observed) -> Step {
    if o.stop { return Step::Stop; }
    if o.park { return Step::Park; }
    if o.sq_ready > 0 && !o.disabled { return Step::Submit(cap_submit(o.sq_ready, o.shared)); }
    // Linux spins while `!time_after(jiffies, timeout)` — the deadline instant
    // itself is still inside the window.
    if o.now_ns <= st.deadline_ns { return Step::Spin; }
    Step::Idle
}

/// The second half of the handshake: `IORING_SQ_NEED_WAKEUP` is published and
/// a full barrier has separated that store from the load that produced this
/// `Observed`. Sleeping is safe only if the ring is STILL empty — an entry
/// visible now was published by a submitter that may have read `sq_flags`
/// before the doorbell went up, so it is not coming back to ring it.
/// # C: O(1)
pub fn sleeps_after_arm(o: &Observed) -> bool {
    !o.stop && !o.park && (o.sq_ready == 0 || o.disabled)
}

/// What `io_uring_enter` does to a ring whose submissions belong to a poll
/// thread: it submits nothing itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct EnterSqpoll {
    /// Rouse the poll thread.
    pub wake: bool,
    /// Block until the poll thread has made SQ room.
    pub wait_room: bool,
}

/// `IORING_ENTER_SQ_WAKEUP` / `IORING_ENTER_SQ_WAIT`. The wake is
/// unconditional rather than gated on the doorbell being up: the submitter
/// already made that decision when it read `sq_flags`, and re-deciding here
/// against a word that may have changed since is how a wakeup gets dropped.
/// # C: O(1)
pub fn enter_action(enter_flags: u32) -> EnterSqpoll {
    use super::enter::{IORING_ENTER_SQ_WAIT, IORING_ENTER_SQ_WAKEUP};
    EnterSqpoll {
        wake: enter_flags & IORING_ENTER_SQ_WAKEUP != 0,
        wait_room: enter_flags & IORING_ENTER_SQ_WAIT != 0,
    }
}

/// The submit half's return value on such a ring: the entries the caller says
/// it published, none of which this call consumed. # C: O(1)
pub fn enter_submitted(to_submit: u32) -> i64 { to_submit as i64 }

/// Whether a poll thread serving `n_rings` rings has to share its passes
/// between them. # C: O(1)
pub fn shares(n_rings: u32) -> bool { n_rings > 1 }

/// Entries one ring contributes to one pass of a thread serving `n_rings`.
///
/// A disabled ring contributes nothing — its entries are not the thread's to
/// consume until it is enabled — and a ring sharing a thread is capped, so a
/// busy ring cannot starve the others by handing the thread an unbounded pass.
/// # C: O(1)
pub fn ring_take(sq_ready: u32, disabled: bool, n_rings: u32) -> u32 {
    if disabled { return 0; }
    cap_submit(sq_ready, shares(n_rings))
}

/// What `IORING_SETUP_ATTACH_WQ` does with the descriptor it names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Attach {
    /// Build this ring its own poll thread.
    Own,
    /// Join the poll thread of the ring the descriptor names.
    Join,
    /// The ring asked to attach but has no poll thread of its own to place, so
    /// the descriptor is validated and nothing else happens.
    Validate,
}

/// What the poll thread's creator knows about the descriptor `ATTACH_WQ`
/// names.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Peer {
    /// The descriptor resolves to an open description.
    pub present: bool,
    /// That description is an io_uring ring.
    pub is_ring: bool,
    /// That ring has a poll thread to join.
    pub has_thread: bool,
    /// That thread's creator shares this task's thread group.
    pub same_group: bool,
    /// That thread has already left its loop.
    pub dead: bool,
}

/// The `IORING_SETUP_ATTACH_WQ` admission ladder.
///
/// A ring that names a descriptor which is not an open description is ENXIO
/// and one that names something other than a ring is EINVAL, whether or not
/// this ring wants a poll thread at all — the descriptor was still wrong.
///
/// A ring that names a ring with no poll thread is EINVAL: there is nothing to
/// join. One that names a thread belonging to ANOTHER thread group does not
/// fail; it gets a thread of its own, because the request was for a thread and
/// the only thing refused is the sharing. One that names a thread which has
/// already exited is ENXIO — joining it would leave the ring with a submitter
/// that never runs.
/// # C: O(1)
pub fn attach_admit(flags: u32, peer: &Peer) -> Result<Attach, Errno> {
    if flags & IORING_SETUP_ATTACH_WQ == 0 {
        return Ok(if flags & IORING_SETUP_SQPOLL != 0 { Attach::Own } else { Attach::Validate });
    }
    if !peer.present { return Err(Errno::Enxio); }
    if !peer.is_ring { return Err(Errno::Einval); }
    if flags & IORING_SETUP_SQPOLL == 0 { return Ok(Attach::Validate); }
    if !peer.has_thread { return Err(Errno::Einval); }
    // Another thread group's thread borrows another process's address space
    // and descriptor table; this ring's entries would mean something else on
    // it. The ring gets its own thread rather than the request being refused.
    if !peer.same_group { return Ok(Attach::Own); }
    if peer.dead { return Err(Errno::Enxio); }
    Ok(Attach::Join)
}

/// One ring, as a sweep sees it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RingView {
    pub sq_ready: u32,
    pub disabled: bool,
}

/// What one pass of the poll loop does.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Pass {
    /// Leave the loop.
    Stop,
    /// Stand down until unparked.
    Park,
    /// Take this many entries from each ring, index-parallel with the views
    /// the sweep was given. At least one is non-zero.
    Take(alloc::vec::Vec<u32>),
    /// Nothing to take, but the idle window has not closed: stay hot.
    Spin,
    /// The idle window closed with nothing to take: publish the doorbells,
    /// re-read the tails, and sleep if they are still empty.
    Idle,
}

/// One pass over every ring a poll thread serves.
///
/// The whole loop's decision, in one place and with no ring, no thread and no
/// memory behind it: a thread that submitted to the wrong ring, starved one of
/// several, or slept with entries waiting would be wrong HERE, and this is
/// callable without any of the machinery that would otherwise be needed to ask.
///
/// A pass sweeps every ring rather than draining one: each contributes a
/// bounded share once more than one ring is attached, so a ring with a full SQ
/// cannot hold the thread while its neighbours wait. Only when the sweep finds
/// nothing anywhere does the idle window decide between spinning and sleeping.
/// # C: O(N_rings)
pub fn sweep(st: &PollState, rings: &[RingView], stop: bool, park: bool, now_ns: u64) -> Pass {
    if stop { return Pass::Stop; }
    if park { return Pass::Park; }
    let n = rings.len() as u32;
    let mut take: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
    if take.try_reserve(rings.len()).is_err() { return Pass::Spin; }
    let mut any = false;
    for v in rings {
        let t = ring_take(v.sq_ready, v.disabled, n);
        any |= t > 0;
        take.push(t);
    }
    if any { return Pass::Take(take); }
    // Nothing anywhere: the idle window is the only thing left to consult.
    match step(st, &Observed { stop, park, disabled: false, sq_ready: 0, shared: shares(n), now_ns }) {
        Step::Idle => Pass::Idle,
        _ => Pass::Spin,
    }
}

#[cfg(test)]
#[path = "sqpoll/tests.rs"]
mod tests;
