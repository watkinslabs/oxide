//! The candidate structure must change the WORK, never the ANSWER.
//!
//! Everything else here checks a rule in isolation. This checks the whole
//! decision against a second, independent one: a flat list, replayed under
//! the same admission rule, costed longhand, and reduced by the same
//! comparison. The two must agree on every population, because the only
//! reason the ordered set exists is to reach the same section sooner.
//!
//! A cache — and an ordered candidate set is one — that returns a different
//! answer from the walk it replaces is the failure this file exists to catch.

use super::*;
use alloc::vec::Vec;

/// Blocks a section holds when full.
const SEC_BLOCKS: u32 = 100;
/// The scale the cost is computed on, written out here rather than imported
/// from the code under test.
const SCALE: u64 = 10_000;
/// Whole-percentage denominator, likewise written out.
const HUNDRED: u64 = 100;

/// Populations tried, and sections in each.
const POPULATIONS: u64 = 200;
const SECTIONS: u32 = 40;

/// A deterministic generator, so a disagreement is reproducible from its seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 { self.next() % n.max(1) }
}

/// One population: `(segno, mtime, live)` in the order a table walk reaches it.
fn population(seed: u64, span: u64) -> Vec<(u32, u64, u32)> {
    let mut r = Rng(seed | 1);
    (0..SECTIONS)
        .map(|i| (i, r.below(span), 1 + r.below(u64::from(SEC_BLOCKS) - 1) as u32))
        .collect()
}

/// The candidates the admission rule keeps, oldest first, and the span they
/// were admitted against. Replayed here rather than read out of the set under
/// test, so that a change to either side shows up as a disagreement.
fn admitted(entries: &[(u32, u64, u32)], threshold: u64) -> (Vec<(u64, u32)>, u64, u64) {
    let (mut lo, mut hi) = (u64::MAX, 0u64);
    let mut kept: Vec<(u64, u32)> = Vec::new();
    for &(segno, mtime, _) in entries {
        if mtime < lo { lo = mtime; }
        if mtime > hi { hi = mtime; }
        if hi - mtime < threshold { continue; }
        kept.push((mtime, segno));
    }
    kept.sort_unstable();
    (kept, lo, hi)
}

/// The best candidate, costed longhand over the flat list.
fn by_hand(kept: &[(u64, u32)], lo: u64, hi: u64, weight: u64, bound: u32,
           live_of: &dyn Fn(u32) -> u32) -> Option<(u32, u32, u64)> {
    if hi < lo { return None; }
    let max_mtime = hi + 1;
    let total = max_mtime - lo;
    let accu = (u64::MAX / total / HUNDRED).min(SCALE);
    let (mut best_cost, mut best_age, mut best) = (u32::MAX, 0u64, None);
    let mut iter = 0u32;
    for &(mtime, segno) in kept {
        if mtime >= lo && mtime < max_mtime {
            let age = accu * (max_mtime - mtime) / total * weight;
            let free = u64::from(SEC_BLOCKS - live_of(segno));
            let empty = accu * free / u64::from(SEC_BLOCKS) * (HUNDRED - weight);
            let cost = (u64::from(u32::MAX) - (age + empty)) as u32;
            iter += 1;
            if cost < best_cost || (cost == best_cost && age > best_age) {
                best_cost = cost;
                best_age = age;
                best = Some(segno);
            }
        }
        if iter >= bound { break; }
    }
    best.map(|segno| (segno, best_cost, best_age))
}

/// The same population offered to the real search.
fn by_search(entries: &[(u32, u64, u32)], threshold: u64, weight: u32, bound: u32,
             live_of: &dyn Fn(u32) -> u32) -> Option<(u32, u32, u64)> {
    let mut a = Atgc::new();
    a.age_threshold = threshold;
    a.age_weight = weight;
    a.max_candidate_count = bound;
    a.candidate_ratio = 0;
    a.begin();
    for &(segno, mtime, live) in entries { a.add_candidate(segno, mtime, live, false); }
    a.lookup_victim(SEC_BLOCKS, live_of).map(|p| (p.segno, p.cost, p.age))
}

/// The live-block count both sides cost through.
fn live(entries: &[(u32, u64, u32)]) -> impl Fn(u32) -> u32 + '_ {
    move |segno| entries.iter().find(|(s, _, _)| *s == segno).map_or(0, |(_, _, l)| *l)
}

/// One population under one set of tunables, both ways.
fn agree(seed: u64, span: u64, threshold: u64, weight: u32, bound: u32) {
    let e = population(seed, span);
    let f = live(&e);
    let (kept, lo, hi) = admitted(&e, threshold);
    let want = by_hand(&kept, lo, hi, u64::from(weight), bound, &f);
    let got = by_search(&e, threshold, weight, bound, &f);
    assert_eq!(got, want, "seed {seed} span {span} threshold {threshold} weight {weight}");
}

#[test]
fn the_candidate_set_reaches_the_same_section_as_a_flat_scan() {
    for seed in 1..=POPULATIONS { agree(seed, 5_000, 100, 60, u32::MAX); }
}

#[test]
fn they_agree_when_the_bound_cuts_the_search_short() {
    for seed in 1..=POPULATIONS { agree(seed, 5_000, 100, 60, 3); }
}

#[test]
fn they_agree_at_every_weight_split() {
    for weight in [0u32, 1, 25, 50, 60, 75, 99, 100] {
        for seed in 1..=20 { agree(seed, 5_000, 100, weight, u32::MAX); }
    }
}

#[test]
fn they_agree_when_the_threshold_admits_almost_nothing() {
    for seed in 1..=POPULATIONS { agree(seed, 5_000, 4_900, 60, u32::MAX); }
}

#[test]
fn they_agree_when_the_threshold_admits_everything() {
    for seed in 1..=POPULATIONS { agree(seed, 5_000, 0, 60, u32::MAX); }
}

#[test]
fn they_agree_when_the_ages_are_crowded_into_a_narrow_span() {
    // Ties on age are common here, which is where a comparison that got the
    // tiebreak backwards would show.
    for seed in 1..=POPULATIONS { agree(seed, 8, 0, 60, u32::MAX); }
}

#[test]
fn they_agree_when_every_section_carries_the_same_age() {
    for seed in 1..=20 { agree(seed, 1, 0, 60, u32::MAX); }
}

#[test]
fn they_agree_when_the_bound_is_one() {
    for seed in 1..=POPULATIONS { agree(seed, 5_000, 0, 60, 1); }
}
