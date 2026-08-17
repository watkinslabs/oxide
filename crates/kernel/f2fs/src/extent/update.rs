//! Taking a change to a file's blocks into a cache.
//!
//! Every change is the same three steps, and getting the order wrong is what
//! makes a cache answer with blocks a file no longer owns:
//!
//! 1. **Invalidate.** Every run overlapping the changed range is cut back to
//!    the parts outside it. A run the range covers entirely is dropped.
//! 2. **Merge.** The new run is joined to the run before or after it when the
//!    three of them describe one contiguous thing — otherwise a file written
//!    block by block ends with one entry per block and a cache that costs more
//!    than the tree it replaces.
//! 3. **Insert**, when nothing took it.
//!
//! Two refusals in step 1 exist to keep the cache worth having, and both apply
//! to the READ cache only. A fragment shorter than the minimum is dropped
//! rather than kept, and a split that would take an inode past its entry
//! ceiling drops the tail instead. Without them a random-write workload turns
//! the cache into a per-block index of itself.
//!
//! And one give-up: when a change splits a run and leaves nothing long behind
//! it, the inode is marked as not worth caching at all and its tree is thrown
//! away. A file being rewritten in small scattered pieces has no contiguity to
//! cache, and continuing to try costs memory for nothing.

use super::info::{self, Info, Kind};
use super::limits::{F2FS_EXTENT_AGE_INVALID, F2FS_MIN_EXTENT_LEN};
use super::tree::Per;

/// What one range update did that the caller must act on.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Outcome {
    /// The remembered longest run changed, so the inode's stored copy of it is
    /// stale and must be written back.
    pub largest_updated: bool,
    /// This inode is no longer worth caching; its read tree is to be dropped.
    pub gave_up: bool,
}

/// Take a change to `[tei.fofs, tei.fofs + tei.len)` into one inode's tree.
///
/// `given_up` is the caller's record of whether this inode has already been
/// declared not worth read-caching; the returned outcome says whether this
/// change declared it.
/// # C: O(runs overlapping the range, log runs each)
pub fn update_range(per: &mut Per, ino: u32, tei: Info, kind: Kind,
                    given_up: bool, max_read_extent_count: u32) -> Outcome {
    let mut out = Outcome::default();
    if tei.len == 0 || !per.trees.contains_key(&ino) { return out; }
    if kind == Kind::Read && given_up { return out; }
    let (fofs, len) = (tei.fofs, tei.len);
    let end = fofs + len;

    // The longest run as it stood BEFORE this change. The give-up rule
    // compares against it, and dropping it first would compare the change
    // against its own effect.
    let prev_largest = per.largest(ino);
    if kind == Kind::Read {
        if let Some(t) = per.trees.get_mut(&ino) { t.drop_largest(fofs, len); }
    }

    let (mut prev_key, mut next_key, start) = neighbours(per, ino, fofs);
    let dei = invalidate(per, ino, fofs, end, kind, max_read_extent_count,
                         start, &mut prev_key, &mut next_key);

    match kind {
        Kind::Read => {
            // A zero address is a range that has no blocks — a reservation or
            // a hole. Nothing to record; the invalidation above was the point.
            if tei.blk != 0 {
                let ei = Info::read(fofs, len, tei.blk);
                if !merge(per, ino, ei, prev_key, next_key, kind) { insert(per, ino, ei, kind); }
                if dei.len >= 1 && prev_largest.len < F2FS_MIN_EXTENT_LEN
                    && per.largest(ino).len < F2FS_MIN_EXTENT_LEN {
                    per.clear_largest(ino);
                    out.gave_up = true;
                }
            }
            out.largest_updated = per.take_largest_updated(ino);
        }
        Kind::BlockAge => {
            if tei.last_blocks != F2FS_EXTENT_AGE_INVALID {
                let ei = Info::aged(fofs, len, tei.age, tei.last_blocks);
                if !merge(per, ino, ei, prev_key, next_key, kind) { insert(per, ino, ei, kind); }
            }
        }
    }
    out
}

/// Cut every run overlapping `[fofs, end)` back to the parts outside it.
///
/// Returns the LAST run the pass looked at, whose length is what tells the
/// caller whether the change split anything: a zero length means the range was
/// unmapped and the give-up rule does not apply.
/// # C: O(runs overlapping, log runs each)
#[allow(clippy::too_many_arguments)]
fn invalidate(per: &mut Per, ino: u32, fofs: u32, end: u32, kind: Kind, max_count: u32,
              start: Option<u32>, prev_key: &mut Option<u32>, next_key: &mut Option<u32>)
    -> Info {
    let mut dei = Info::default();
    let mut cur = start;
    while let Some(k) = cur {
        let Some(ei) = per.ei(ino, k) else { break };
        if ei.fofs >= end { break; }
        dei = ei;
        let org_end = ei.end();
        let mut parts = 0u8;
        let mut next_k = None;
        // Keep the head, when there is one and it is long enough to be worth
        // an entry of its own.
        if fofs > ei.fofs && (kind != Kind::Read || fofs - ei.fofs >= F2FS_MIN_EXTENT_LEN) {
            let mut head = ei;
            head.len = fofs - ei.fofs;
            per.set_ei(ino, k, head);
            *prev_key = Some(k);
            parts = 1;
        }
        let room = per.count(ino) < max_count as usize;
        let keep_tail = end < org_end
            && (kind != Kind::Read || (org_end - end >= F2FS_MIN_EXTENT_LEN && room));
        let mut moved_to = None;
        if keep_tail {
            let mut tail = ei;
            info::set_info(&mut tail, end, org_end - end, ei.blk + (end - ei.fofs),
                           ei.age, ei.last_blocks, kind);
            if parts != 0 {
                per.attach(ino, tail);
                per.note_largest(ino, &tail, kind);
            } else {
                // Nothing was kept in front, so the run itself is re-based
                // rather than a second one created: same run, later start.
                per.rekey(ino, k, end);
                per.set_ei(ino, end, tail);
                moved_to = Some(end);
            }
            next_k = Some(end);
            parts += 1;
        }
        let en_key = moved_to.unwrap_or(k);
        if next_k.is_none() { next_k = per.next_after(ino, en_key); }
        if parts != 0 {
            if let Some(ei) = per.ei(ino, en_key) { per.note_largest(ino, &ei, kind); }
        } else {
            per.detach(ino, en_key);
        }
        // The cursor and the run a merge may join to are the same thing: the
        // pass stops at the first run past the range, which is exactly the run
        // the new one could be extended by.
        *next_key = next_k;
        cur = next_k;
    }
    dei
}

/// The run covering `fofs` if there is one, and the runs on either side that a
/// new run there could be joined to.
///
/// A run that covers the offset only offers a neighbour on the side the offset
/// sits AT: a change starting in the middle of a run cannot be joined to what
/// comes before it, because the run itself is in the way.
/// # C: O(log runs)
fn neighbours(per: &Per, ino: u32, fofs: u32) -> (Option<u32>, Option<u32>, Option<u32>) {
    let Some(t) = per.trees.get(&ino) else { return (None, None, None) };
    match t.lookup(fofs) {
        Some((k, _)) => {
            let ei = t.nodes[&k].ei;
            let prev = if fofs == ei.fofs { t.prev_key(fofs) } else { None };
            let next = if fofs == ei.end() - 1 { t.next_key(k) } else { None };
            (prev, next, Some(k))
        }
        None => {
            let prev = t.prev_key(fofs);
            let next = t.next_key(fofs);
            (prev, next, next)
        }
    }
}

/// Join `ei` to the run before it, the run after it, or both.
///
/// Joining both is the case that matters: a write filling the gap between two
/// runs makes ONE run, and leaving it as three is a cache that fragments under
/// exactly the workload contiguity is worth caching for. The run in front is
/// released and the run behind is extended backwards over both.
/// # C: O(log runs)
fn merge(per: &mut Per, ino: u32, ei: Info, prev_key: Option<u32>, next_key: Option<u32>,
         kind: Kind) -> bool {
    let mut cur = ei;
    let mut merged: Option<u32> = None;
    if let Some(back) = prev_key.and_then(|pk| per.ei(ino, pk).map(|e| (pk, e))) {
        let (pk, mut back) = back;
        if info::mergeable(&back, &cur, kind) {
            back.len += cur.len;
            per.set_ei(ino, pk, back);
            cur = back;
            merged = Some(pk);
        }
    }
    if let Some(front) = next_key.and_then(|nk| per.ei(ino, nk).map(|e| (nk, e))) {
        let (nk, mut front) = front;
        if info::mergeable(&cur, &front, kind) {
            // The run in front is dropped BEFORE the run behind is re-based
            // onto its offset: for the instant between they share it, and an
            // ordered map cannot hold both.
            if let Some(pk) = merged { per.detach(ino, pk); }
            front.len += cur.len;
            front.fofs = cur.fofs;
            if kind == Kind::Read { front.blk = cur.blk; }
            per.rekey(ino, nk, cur.fofs);
            per.set_ei(ino, cur.fofs, front);
            merged = Some(cur.fofs);
        }
    }
    let Some(k) = merged else { return false };
    if let Some(ei) = per.ei(ino, k) { per.note_largest(ino, &ei, kind); }
    per.touch(ino, k);
    true
}

/// Put a run in that nothing took. # C: O(log runs)
fn insert(per: &mut Per, ino: u32, ei: Info, kind: Kind) {
    per.attach(ino, ei);
    per.note_largest(ino, &ei, kind);
}

#[cfg(test)]
#[path = "../tests/extcache/update.rs"]
mod tests;
