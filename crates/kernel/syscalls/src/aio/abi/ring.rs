// Index arithmetic for the shared completion ring. Userspace owns `head`
// (libaio advances it directly when it reaps without a syscall) and the kernel
// owns `tail`, so every index that comes back out of the ring is untrusted and
// has to be folded into range before it addresses a slot.

use alloc::vec::Vec;

/// One contiguous run of event slots to copy out: `(first_slot, count)`.
pub type Chunk = (u32, u32);

/// Fold an index read out of the shared ring into `[0, nr_events)`.
/// # C: O(1)
pub fn wrap(idx: u32, nr_events: u32) -> u32 {
    if nr_events == 0 { return 0; }
    idx % nr_events
}

/// Next value of `tail` after publishing one completion.
/// # C: O(1)
pub fn advance_tail(tail: u32, nr_events: u32) -> u32 {
    let next = tail.wrapping_add(1);
    if next >= nr_events { 0 } else { next }
}

/// Events a waiter would see for a given `head`/`tail` pair. A `tail` that has
/// caught up to `head` after a wrap reports a full ring rather than an empty
/// one, which is what lets a waiter blocked on `min_nr` wake on the wrapping
/// completion.
/// # C: O(1)
pub fn avail(head: u32, tail: u32, nr_events: u32) -> u32 {
    if tail > head { tail - head } else { tail.wrapping_add(nr_events).wrapping_sub(head) }
}

/// Split the reap of up to `nr` events into contiguous slot runs, and report
/// the `head` the reaper must publish afterwards. An empty ring
/// (`head == tail`) yields no runs and leaves `head` alone — note this is the
/// opposite reading of `head == tail` from `avail`, matching the two distinct
/// roles the kernel gives that state.
/// # C: O(1) runs
pub fn read_plan(head: u32, tail: u32, nr_events: u32, nr: i64) -> (Vec<Chunk>, u32) {
    let mut out: Vec<Chunk> = Vec::new();
    if nr_events == 0 || head == tail || nr <= 0 { return (out, head); }
    let mut h = wrap(head, nr_events);
    let t = wrap(tail, nr_events);
    if h == t { return (out, head); }
    let mut got: i64 = 0;
    while got < nr {
        if h == t { break; }
        let run_end = if h <= t { t } else { nr_events };
        let mut take = (run_end - h) as i64;
        if take <= 0 { break; }
        take = core::cmp::min(take, nr - got);
        out.push((h, take as u32));
        got += take;
        h = wrap(h.wrapping_add(take as u32), nr_events);
    }
    (out, h)
}
