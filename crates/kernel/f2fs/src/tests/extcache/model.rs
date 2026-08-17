//! The claim the whole mechanism rests on: a cached answer is the answer the
//! uncached walk would have given.
//!
//! A cache that returns a DIFFERENT block from the one a file owns is the
//! failure mode — it is silent, it is not an error at any layer, and it hands
//! one file's contents to another. So the property is checked against a model
//! that cannot be wrong because it stores nothing clever: one entry per file
//! block, rewritten by every change.
//!
//! The property is ONE-DIRECTIONAL on purpose. The cache is allowed to forget
//! — it drops fragments too short to be worth an entry, it stops splitting at
//! a ceiling, and it gives up entirely on a file being rewritten in scattered
//! pieces. What it may never do is ANSWER WRONGLY. Because "answers nothing"
//! would satisfy that trivially, the tests below also assert that the cache
//! answers a great deal.

use super::*;
use crate::extent::limits::SAME_AGE_REGION;
use alloc::collections::BTreeMap;

const INO: u32 = 3;
/// Blocks in the modelled file. Small enough that a full sweep after every
/// step is cheap, large enough that the minimum-length rules bite.
const BLOCKS: u32 = 512;
const STEPS: u32 = 400;
/// Volume address the modelled file's blocks are drawn from. Never zero: a
/// zero address means a range with no blocks behind it.
const BASE: u32 = 100_000;

/// A deterministic sequence, so a failure is reproducible from the seed alone.
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
    fn below(&mut self, n: u32) -> u32 { (self.next() % u64::from(n.max(1))) as u32 }
}

/// One file's blocks, as something with no algorithm to get wrong.
type Truth = BTreeMap<u32, u32>;

/// No run may overlap the next, and every run held must be in the reclaim
/// order — a run outside it can never be freed.
fn structurally_sound(c: &Caches, kind: Kind) {
    let per = c.per(kind);
    let mut held = 0usize;
    for t in per.trees.values() {
        held += t.nodes.len();
        let mut last_end = 0u32;
        for (&k, n) in t.nodes.iter() {
            assert_eq!(k, n.ei.fofs, "a run is filed under an offset that is not its own");
            assert!(k >= last_end, "run at {k} overlaps the one ending at {last_end}");
            assert!(n.ei.len > 0, "a run of no length answers for nothing");
            last_end = n.ei.end();
        }
    }
    assert_eq!(held, per.lru.len(), "a run outside the reclaim order can never be freed");
}

#[test]
fn a_read_cached_block_is_always_the_block_the_file_owns() {
    let mut c = Caches::new(true, true);
    c.init_trees(INO, Gate::regular(), None);
    let mut truth = Truth::new();
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    let mut answered = 0u64;
    let mut asked = 0u64;

    for step in 0..STEPS {
        let fofs = rng.below(BLOCKS);
        let len = 1 + rng.below(BLOCKS - fofs);
        // One change in five removes the blocks rather than replacing them.
        let punch = rng.below(5) == 0;
        if punch {
            c.update_range(Kind::Read, INO, Info::read(fofs, len, 0));
            for i in 0..len { truth.remove(&(fofs + i)); }
        } else {
            let blk = BASE + rng.below(BLOCKS * 8);
            c.update_range(Kind::Read, INO, Info::read(fofs, len, blk));
            for i in 0..len { truth.insert(fofs + i, blk + i); }
        }

        structurally_sound(&c, Kind::Read);
        for o in 0..BLOCKS {
            asked += 1;
            if let Some((got, _)) = c.lookup_block(INO, o).block(o) {
                answered += 1;
                assert_eq!(Some(got), truth.get(&o).copied(),
                           "step {step}: block {o} answered {got}");
            }
        }
        // Giving up models a file too scattered to be worth caching. The next
        // open starts again, and must still never answer wrongly.
        if c.no_extent(INO) {
            c.destroy(INO, 0);
            c.init_trees(INO, Gate::regular(), None);
        }
    }
    assert!(answered * 4 > asked,
            "the cache answered {answered} of {asked}: a cache that answers nothing \
             would satisfy the property trivially");
}

#[test]
fn a_read_cache_never_answers_for_a_block_the_file_does_not_have() {
    let mut c = Caches::new(true, true);
    c.init_trees(INO, Gate::regular(), None);
    let mut truth = Truth::new();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);

    // Fill the file, then punch holes through it. Every hole must stop being
    // answered for the instant it is punched.
    c.update_range(Kind::Read, INO, Info::read(0, BLOCKS, BASE));
    for i in 0..BLOCKS { truth.insert(i, BASE + i); }

    for step in 0..STEPS {
        let fofs = rng.below(BLOCKS);
        let len = 1 + rng.below(BLOCKS - fofs);
        c.update_range(Kind::Read, INO, Info::read(fofs, len, 0));
        for i in 0..len { truth.remove(&(fofs + i)); }
        for o in 0..BLOCKS {
            if c.lookup_block(INO, o).block(o).is_some() {
                assert!(truth.contains_key(&o), "step {step}: block {o} is a hole and was answered");
            }
        }
        if truth.is_empty() { break; }
    }
}

#[test]
fn a_sequential_write_leaves_every_block_cached_and_correct() {
    let mut c = Caches::new(true, true);
    c.init_trees(INO, Gate::regular(), None);
    for i in 0..BLOCKS { c.update_range(Kind::Read, INO, Info::read(i, 1, BASE + i)); }
    assert_eq!(c.node_count(Kind::Read), 1, "one run, not one entry per block");
    for o in 0..BLOCKS {
        assert_eq!(c.lookup_block(INO, o).block(o).map(|(b, _)| b), Some(BASE + o));
    }
}

#[test]
fn an_age_cached_answer_is_the_age_that_was_recorded() {
    // Ages far enough apart that no two runs are ever called the same age, so
    // the answer must be EXACT. What merging does when they are close is a
    // separate contract, checked where the merge rule is.
    let spread = SAME_AGE_REGION * 16;
    let mut c = Caches::new(true, true);
    c.init_trees(INO, Gate::regular(), None);
    let mut truth: BTreeMap<u32, (u64, u64)> = BTreeMap::new();
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    let mut answered = 0u64;

    for step in 0..STEPS {
        let fofs = rng.below(BLOCKS);
        let len = 1 + rng.below(BLOCKS - fofs);
        if rng.below(5) == 0 {
            c.update_range(Kind::BlockAge, INO, Info::invalidate(fofs, len));
            for i in 0..len { truth.remove(&(fofs + i)); }
        } else {
            let age = u64::from(rng.below(64)) * spread;
            let last = u64::from(rng.below(64)) * spread;
            c.update_range(Kind::BlockAge, INO, Info::aged(fofs, len, age, last));
            for i in 0..len { truth.insert(fofs + i, (age, last)); }
        }
        structurally_sound(&c, Kind::BlockAge);
        for o in 0..BLOCKS {
            if let Some((ei, _)) = c.lookup(Kind::BlockAge, INO, o).found() {
                answered += 1;
                assert_eq!(Some((ei.age, ei.last_blocks)), truth.get(&o).copied(),
                           "step {step}: block {o} answered an age it was not given");
            }
        }
    }
    assert!(answered > u64::from(STEPS), "the age cache answered almost nothing");
}

#[test]
fn an_age_cache_never_answers_for_a_block_whose_age_was_dropped() {
    let mut c = Caches::new(true, true);
    c.init_trees(INO, Gate::regular(), None);
    let mut truth: BTreeMap<u32, (u64, u64)> = BTreeMap::new();
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);

    for _ in 0..STEPS {
        let fofs = rng.below(BLOCKS);
        let len = 1 + rng.below(BLOCKS - fofs);
        if rng.below(3) == 0 {
            c.update_range(Kind::BlockAge, INO, Info::invalidate(fofs, len));
            for i in 0..len { truth.remove(&(fofs + i)); }
        } else {
            // Ages close together, so runs merge: the coverage must still be
            // exactly what was recorded, however the runs were joined.
            let age = u64::from(rng.below(SAME_AGE_REGION as u32 / 2));
            c.update_range(Kind::BlockAge, INO, Info::aged(fofs, len, age, age));
            for i in 0..len { truth.insert(fofs + i, (age, age)); }
        }
        structurally_sound(&c, Kind::BlockAge);
        for o in 0..BLOCKS {
            if c.lookup(Kind::BlockAge, INO, o).found().is_some() {
                assert!(truth.contains_key(&o), "block {o} has no age and one was answered");
            }
        }
    }
}

#[test]
fn the_longest_run_shortcut_never_outlives_the_blocks_it_describes() {
    // The remembered longest run answers BEFORE the tree is consulted and
    // survives its own entry being dropped, so a change overlapping it that
    // failed to forget it would be answered from a run the file no longer has.
    let mut c = Caches::new(true, true);
    c.init_trees(INO, Gate::regular(), None);
    let mut truth = Truth::new();
    let mut rng = Rng(0x0BAD_C0DE_DEAD_BEEF);

    c.update_range(Kind::Read, INO, Info::read(0, BLOCKS, BASE));
    for i in 0..BLOCKS { truth.insert(i, BASE + i); }

    for step in 0..STEPS {
        let fofs = rng.below(BLOCKS);
        let len = 1 + rng.below(BLOCKS - fofs);
        let blk = BASE + 50_000 + rng.below(BLOCKS);
        c.update_range(Kind::Read, INO, Info::read(fofs, len, blk));
        for i in 0..len { truth.insert(fofs + i, blk + i); }
        if let Some(largest) = c.largest(INO) {
            for o in largest.fofs..largest.end() {
                assert_eq!(largest.block(o), truth.get(&o).copied(),
                           "step {step}: the longest run claims block {o}");
            }
        }
        if c.no_extent(INO) {
            c.destroy(INO, 0);
            c.init_trees(INO, Gate::regular(), None);
        }
    }
}
