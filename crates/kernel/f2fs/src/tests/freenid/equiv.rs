//! The claim the cache exists to make: a cached answer is the answer a fresh
//! walk of the table would have given.
//!
//! A cache that is merely fast is worthless — the failure it can produce is
//! handing out an id something is already using, which silently overwrites one
//! file's node with another's. So the test drives the cache against a MODEL of
//! the same table and checks, after every single step, that nothing the cache
//! calls free is in use anywhere, that nothing is handed out twice, and that
//! the three counts the report publishes match what the model says they are.
//!
//! The sequence is deterministic. A failure that cannot be re-run is a failure
//! nobody can fix, so the generator is a fixed-seed shift register rather than
//! anything the machine supplies.

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;

use crate::freenid::{FreeNids, NidState};
use crate::uapi::{BLKSIZE, NAT_BLOCK_ADDR, NAT_ENTRY_PER_BLOCK, NAT_ENTRY_SIZE,
                  RESERVED_NODE_NUM};

/// Ids one table block covers. # C: O(1)
const PER: u32 = NAT_ENTRY_PER_BLOCK as u32;
/// Table blocks the model volume has. # C: O(1)
const BLOCKS: u32 = 3;
/// Ids the model volume can name. # C: O(1)
const MAX_NID: u32 = PER * BLOCKS;
/// Steps the sequence runs. Long enough that the cache empties, is refilled
/// from the map and from the table, and wraps its cursor several times.
const STEPS: u32 = 20_000;
/// Available memory, in pages, wide enough that the shrink path is driven by
/// the ceiling rather than by the budget.
const ROOMY: u64 = 1 << 20;

/// A fixed-seed shift register: the same sequence on every run and every
/// machine. # C: O(1)
struct Rng(u32);

impl Rng {
    /// # C: O(1)
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0
    }

    /// # C: O(1)
    fn below(&mut self, n: u32) -> u32 { if n == 0 { 0 } else { self.next() % n } }
}

/// The table as the model holds it, rendered into the bytes one block of it
/// would have. # C: O(ids per block)
fn nat_block(used: &BTreeSet<u32>, ofs: u32) -> Vec<u8> {
    let mut b = vec![0u8; BLKSIZE];
    let base = ofs * PER;
    for i in 0..PER {
        let nid = base + i;
        if !used.contains(&nid) { continue; }
        // Any address will do: what the walk reads off it is only whether the
        // id is spoken for, and every live node has one.
        let at = i as usize * NAT_ENTRY_SIZE + NAT_BLOCK_ADDR;
        b[at..at + 4].copy_from_slice(&(nid + 1_000).to_le_bytes());
    }
    b
}

/// Fold the whole model table into the cache, as a mount's build pass would.
/// # C: O(ids)
fn rescan(f: &mut FreeNids, used: &BTreeSet<u32>) {
    for ofs in 0..BLOCKS {
        f.scan_nat_block(&nat_block(used, ofs), ofs * PER, MAX_NID).unwrap();
    }
}

/// Every id the cache is offering, and the invariants that must hold of them.
/// # C: O(free ids log ids)
fn check(f: &FreeNids, used: &BTreeSet<u32>, out: &BTreeSet<u32>, avail: u32, step: u32) {
    let free = f.free_order();
    let mut seen = BTreeSet::new();
    for &nid in &free {
        assert!((RESERVED_NODE_NUM..MAX_NID).contains(&nid),
                "step {step}: offered {nid}, which the table cannot name");
        assert!(!used.contains(&nid), "step {step}: offered {nid}, which is a live node");
        assert!(!out.contains(&nid), "step {step}: offered {nid}, which is already handed out");
        assert!(seen.insert(nid), "step {step}: offered {nid} twice");
    }
    assert_eq!(f.free_count() as usize, free.len(), "step {step}: free tally");
    assert_eq!(f.alloc_count() as usize, out.len(), "step {step}: handed-out tally");
    assert_eq!(f.available_nids(), avail, "step {step}: remaining-id count");
}

#[test]
fn a_cached_id_is_never_one_the_table_says_is_in_use() {
    // A table with a scattering of live nodes to start from, so the first walk
    // has both kinds of entry to classify.
    let mut rng = Rng(0x1357_9bdf);
    let mut used: BTreeSet<u32> = BTreeSet::new();
    for _ in 0..300 {
        let nid = RESERVED_NODE_NUM + rng.below(MAX_NID - RESERVED_NODE_NUM);
        used.insert(nid);
    }
    let mut avail = MAX_NID - RESERVED_NODE_NUM - used.len() as u32;

    let mut f = FreeNids::new(0, avail);
    rescan(&mut f, &used);
    let mut out: BTreeSet<u32> = BTreeSet::new();
    check(&f, &used, &out, avail, 0);

    let (mut handed, mut stuck, mut returned, mut freed, mut refills) = (0u32, 0u32, 0u32, 0u32, 0u32);
    for step in 1..=STEPS {
        match rng.below(6) {
            0..=2 => {
                if let Some(nid) = f.alloc() {
                    assert!(!used.contains(&nid), "step {step}: handed out live node {nid}");
                    assert!(out.insert(nid), "step {step}: handed out {nid} twice");
                    assert_eq!(f.state_of(nid), Some(NidState::Prealloc));
                    avail -= 1;
                    handed += 1;
                }
            }
            3 => {
                if let Some(&nid) = out.iter().nth(rng.below(out.len().max(1) as u32) as usize) {
                    f.alloc_done(nid);
                    out.remove(&nid);
                    used.insert(nid);
                    stuck += 1;
                }
            }
            4 => {
                if let Some(&nid) = out.iter().nth(rng.below(out.len().max(1) as u32) as usize) {
                    f.alloc_failed(nid, ROOMY);
                    out.remove(&nid);
                    avail += 1;
                    returned += 1;
                }
            }
            _ => {
                // A node dies: its table entry empties, and the checkpoint
                // that writes that back is what offers the id again.
                if let Some(&nid) = used.iter().nth(rng.below(used.len().max(1) as u32) as usize) {
                    used.remove(&nid);
                    f.add(nid, MAX_NID, false, None);
                    avail += 1;
                    freed += 1;
                }
            }
        }
        // Refills must move nothing but the free set: neither a re-walk of the
        // map, nor a fresh table read, nor a shrink may touch what the volume
        // has left or what is in a caller's hands.
        if step % 97 == 0 {
            f.scan_free_nid_bits(MAX_NID);
            refills += 1;
        }
        if step % 313 == 0 { rescan(&mut f, &used); }
        if step % 211 == 0 { f.shrink(64); }
        check(&f, &used, &out, avail, step);
    }

    // A vacuous run would pass every assertion above, so the exercise itself
    // is asserted: each branch has to have done real work.
    assert!(handed > 1_000, "handed out only {handed}");
    assert!(stuck > 500, "only {stuck} stuck");
    assert!(returned > 500, "only {returned} given back");
    assert!(freed > 500, "only {freed} freed");
    assert!(refills > 100, "only {refills} refills");
}

#[test]
fn a_walk_of_the_table_and_the_cache_agree_on_what_is_free() {
    let mut rng = Rng(0x2468_ace0);
    let mut used: BTreeSet<u32> = BTreeSet::new();
    for _ in 0..400 {
        used.insert(RESERVED_NODE_NUM + rng.below(MAX_NID - RESERVED_NODE_NUM));
    }
    let mut f = FreeNids::new(0, MAX_NID - RESERVED_NODE_NUM - used.len() as u32);
    rescan(&mut f, &used);

    // What a walk of the table alone would call free.
    let walked: BTreeSet<u32> = (RESERVED_NODE_NUM..MAX_NID)
        .filter(|nid| !used.contains(nid))
        .collect();
    let cached: BTreeSet<u32> = f.free_order().into_iter().collect();
    assert_eq!(cached, walked);
}
