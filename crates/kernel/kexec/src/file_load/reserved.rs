// Physical ranges the load must keep clear, and the two things it does with
// them.
//
// A reserved range is memory the RUNNING kernel handed to hardware that goes
// on using it after this kernel stops — an interrupt controller's tables are
// the case that exists. Such a range needs BOTH of:
//
//   - removal from the placement map, so this loader never puts a segment
//     there. A segment placed on top of one is copied over memory the
//     controller is still reading, and is then cleared out from under the new
//     kernel when it adopts the tables.
//   - a reservation in the tree the new kernel boots with, so the new kernel's
//     own allocator never hands the memory out. Without it the new kernel
//     places whatever it likes there and the controller writes over it; the
//     damage appears later and somewhere else, as a poisoned pointer in the
//     first driver that was given the memory.
//
// Doing one without the other closes half the hole and leaves a failure that
// depends on where an allocator happened to land. Ungated, because both are
// arithmetic over a memory map and the answer has to be checkable without a
// machine.

extern crate alloc;
use alloc::vec::Vec;

use crate::uapi::PAGE_SIZE;

/// Reserved ranges as `(pa, len)`, page-rounded OUTWARDS, sorted, and merged
/// where they overlap or abut.
///
/// Rounding outwards rather than to the nearest page is the whole point: a
/// reservation that covers only part of a page leaves the rest of that page
/// available, and a page is the smallest thing either allocator hands out. Two
/// tables allocated next to each other merge into one entry rather than two
/// abutting ones, so the tree carries what it means rather than an artefact of
/// how the memory was requested.
/// # C: O(N log N)
pub fn normalize(rs: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = Vec::new();
    for &(pa, len) in rs {
        if len == 0 { continue; }
        let start = pa / PAGE_SIZE * PAGE_SIZE;
        let end = pa.saturating_add(len).div_ceil(PAGE_SIZE).saturating_mul(PAGE_SIZE);
        if end <= start { continue; }
        v.push((start, end));
    }
    v.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (start, end) in v {
        match out.last_mut() {
            // `<=` and not `<`: two ranges that merely touch describe one
            // contiguous extent, and emitting both leaves a boundary that
            // every later comparison has to re-derive.
            Some(last) if start <= last.1 => { if end > last.1 { last.1 = end; } }
            _ => out.push((start, end)),
        }
    }
    out.into_iter().map(|(s, e)| (s, e - s)).collect()
}

/// `ranges` with every reserved extent cut out of it.
///
/// Both are half-open `[start, end)`. A reservation that falls in the middle
/// of a range splits it in two rather than truncating it — the memory above
/// the reservation is as usable as the memory below, and dropping it silently
/// shrinks the machine.
/// # C: O(N_ranges * N_reserved)
pub fn subtract(ranges: &[(u64, u64)], reserved: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let cuts = normalize(reserved);
    let mut out: Vec<(u64, u64)> = ranges.to_vec();
    for (pa, len) in cuts {
        let (cs, ce) = (pa, pa.saturating_add(len));
        let mut next: Vec<(u64, u64)> = Vec::new();
        for (s, e) in out.drain(..) {
            if ce <= s || cs >= e { next.push((s, e)); continue; }
            if s < cs { next.push((s, cs)); }
            if ce < e { next.push((ce, e)); }
        }
        out = next;
    }
    out
}

#[cfg(test)]
mod tests;
