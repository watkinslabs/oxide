// Access-vector cache tests.
//
// The four partial-key cases are the point of this file: an entry cached for
// one triple must be invisible to a lookup whose source, target or class
// differs. A cache that answers those is a cache that grants access the policy
// refuses.

use alloc::vec::Vec;

use super::*;

/// Slot count exponent used by the tests; small enough that buckets collide,
/// which is exactly where a partial-key comparison would show up.
const LOG2: u32 = 4;

/// Decision granting `allowed` at sequence `seqno`.
fn avd(allowed: u32, seqno: u32) -> AvDecision {
    AvDecision { allowed, ..AvDecision::init(seqno) }
}

#[test]
fn init_audits_every_denial() {
    // Audit masks accumulate by AND, so an untouched decision must still name
    // every permission as audit-on-deny.
    let d = AvDecision::init(1);
    assert_eq!(d.auditdeny, u32::MAX);
    assert_eq!(d.allowed, 0);
    assert_eq!(d.auditallow, 0);
    assert_eq!(d.flags, 0);
    for bit in 0..32 { assert_ne!(d.auditdeny & (1 << bit), 0, "permission {bit} not audited"); }
}

#[test]
fn miss_then_hit() {
    let mut c = Avc::new(LOG2);
    assert_eq!(c.lookup(1, 2, 3), None);
    assert_eq!(c.stats().misses, 1);
    assert_eq!(c.stats().lookups, 1);

    c.insert(1, 2, 3, avd(0x0f, 0));
    assert_eq!(c.lookup(1, 2, 3), Some(avd(0x0f, 0)));
    assert_eq!(c.stats().misses, 1, "a hit must not count as a miss");
    assert_eq!(c.stats().lookups, 2);
    assert_eq!(c.stats().allocations, 1);
    assert_eq!(c.active_nodes(), 1);
}

#[test]
fn reinsert_updates_in_place() {
    let mut c = Avc::new(LOG2);
    c.insert(1, 2, 3, avd(0x1, 0));
    c.insert(1, 2, 3, avd(0x3, 0));
    assert_eq!(c.lookup(1, 2, 3).unwrap().allowed, 0x3);
    assert_eq!(c.active_nodes(), 1);
    assert_eq!(c.stats().allocations, 1);
}

// The three keys below are chosen to select the SAME bucket as the entry that
// was cached: a differing key that merely hashes elsewhere would miss even
// under a comparison that ignores the component being varied, so it would not
// test the comparison at all.

#[test]
fn different_source_sid_is_a_miss() {
    let mut c = Avc::new(LOG2);
    c.insert(1, 2, 3, avd(0xff, 0));
    let other = 1 + (1 << LOG2);
    assert_eq!(c.bucket(other, 2, 3), c.bucket(1, 2, 3));
    assert_eq!(c.lookup(other, 2, 3), None);
}

#[test]
fn different_target_sid_is_a_miss() {
    let mut c = Avc::new(LOG2);
    c.insert(1, 2, 3, avd(0xff, 0));
    let other = 2 + (1 << LOG2);
    assert_eq!(c.bucket(1, other, 3), c.bucket(1, 2, 3));
    assert_eq!(c.lookup(1, other, 3), None);
}

#[test]
fn different_class_is_a_miss() {
    let mut c = Avc::new(LOG2);
    c.insert(1, 2, 3, avd(0xff, 0));
    assert_eq!(c.bucket(1, 2, 4), c.bucket(1, 2, 3));
    assert_eq!(c.lookup(1, 2, 4), None);
}

#[test]
fn colliding_keys_do_not_answer_for_each_other() {
    // Bucket selection mixes shifted key components, so these triples land
    // together; only the full comparison separates them.
    let mut c = Avc::new(LOG2);
    c.insert(1, 2, 3, avd(0xff, 0));
    let mut wrong = 0;
    for ssid in 0..8u32 {
        for tsid in 0..8u32 {
            for tclass in 0..8u16 {
                let hit = c.lookup(ssid, tsid, tclass).is_some();
                let want = (ssid, tsid, tclass) == (1, 2, 3);
                if hit != want { wrong += 1; }
            }
        }
    }
    assert_eq!(wrong, 0);
}

#[test]
fn stale_decision_is_not_cached() {
    let mut c = Avc::new(LOG2);
    c.insert(1, 2, 3, avd(0xff, 7));
    assert_eq!(c.latest_notif(), 7);
    c.insert(4, 5, 6, avd(0xff, 6));
    assert_eq!(c.lookup(4, 5, 6), None, "decision from a superseded policy must not be cached");
    assert_eq!(c.active_nodes(), 1);
    c.insert(4, 5, 6, avd(0xff, 7));
    assert!(c.lookup(4, 5, 6).is_some());
    c.insert(7, 8, 9, avd(0xff, 8));
    assert_eq!(c.latest_notif(), 8);
    assert!(c.lookup(7, 8, 9).is_some());
}

#[test]
fn reset_empties_and_raises_the_watermark() {
    let mut c = Avc::new(LOG2);
    c.insert(1, 2, 3, avd(0xff, 1));
    c.insert(4, 5, 6, avd(0xff, 1));
    c.reset(42);
    assert_eq!(c.latest_notif(), 42);
    assert_eq!(c.active_nodes(), 0);
    assert_eq!(c.lookup(1, 2, 3), None);
    assert_eq!(c.stats().frees, 2);
    c.insert(1, 2, 3, avd(0xff, 41));
    assert_eq!(c.lookup(1, 2, 3), None, "pre-reset decisions stay refused");
}

#[test]
fn flush_drops_everything() {
    let mut c = Avc::new(LOG2);
    for i in 0..10 { c.insert(i, i + 1, 2, avd(0x1, 0)); }
    c.flush();
    assert_eq!(c.active_nodes(), 0);
    assert_eq!(c.hash_stats().entries, 0);
    assert_eq!(c.stats().frees, 10);
}

#[test]
fn grant_widens_only_the_matching_key() {
    let mut c = Avc::new(LOG2);
    c.insert(1, 2, 3, avd(0x1, 0));
    c.insert(1, 2, 4, avd(0x1, 0));
    c.grant(1, 2, 3, 0x10);
    assert_eq!(c.lookup(1, 2, 3).unwrap().allowed, 0x11);
    assert_eq!(c.lookup(1, 2, 4).unwrap().allowed, 0x1);
    // Absent keys are a no-op, not an insertion.
    let before = c.active_nodes();
    c.grant(99, 99, 99, 0xff);
    assert_eq!(c.active_nodes(), before);
    assert_eq!(c.lookup(99, 99, 99), None);
}

#[test]
fn exceeding_the_threshold_reclaims() {
    let mut c = Avc::new(LOG2);
    c.set_threshold(64);
    assert_eq!(c.threshold(), 64);
    for i in 0..64u32 { c.insert(i, 1, 1, avd(0x1, 0)); }
    assert_eq!(c.active_nodes(), 64);
    assert_eq!(c.stats().reclaims, 0);

    c.insert(1000, 1, 1, avd(0x1, 0));
    assert_eq!(c.stats().reclaims, 1);
    assert!(c.active_nodes() < 65, "reclaim must shrink the cache");
    assert_eq!(c.active_nodes(), 65 - AVC_CACHE_RECLAIM);
    assert_eq!(c.stats().frees, u64::from(AVC_CACHE_RECLAIM));
    assert_eq!(c.hash_stats().entries, c.active_nodes());
}

#[test]
fn reclaimed_entries_miss_rather_than_answer_wrongly() {
    let mut c = Avc::new(LOG2);
    c.set_threshold(32);
    // Each key gets a distinct allowed mask, so a wrong answer is detectable
    // as a value mismatch, not merely as an unexpected hit.
    for i in 0..200u32 { c.insert(i, i * 2 + 1, (i % 5) as u16, avd(i | 0x8000_0000, 0)); }
    let mut hits = 0;
    for i in 0..200u32 {
        if let Some(d) = c.lookup(i, i * 2 + 1, (i % 5) as u16) {
            assert_eq!(d.allowed, i | 0x8000_0000, "entry answered with another key's decision");
            hits += 1;
        }
    }
    assert!(hits > 0);
    assert!(c.active_nodes() <= c.threshold() + 1);
}

#[test]
fn fill_evict_refill_stays_bounded_and_never_invents_entries() {
    let mut c = Avc::new(6);
    c.set_threshold(128);
    let inserted: Vec<u32> = (0..4000u32).filter(|i| i % 3 != 0).collect();
    for &i in &inserted { c.insert(i, i ^ 0x5a5a, (i % 7) as u16, avd(i, 0)); }
    assert!(c.active_nodes() <= c.threshold() + 1, "cache grew past its threshold");
    assert!(c.stats().reclaims > 0);
    // Keys never inserted must never answer, whatever the eviction history.
    for i in (0..4000u32).step_by(3) {
        assert_eq!(c.lookup(i, i ^ 0x5a5a, (i % 7) as u16), None);
    }
    // Surviving keys answer with their own decision or not at all.
    for &i in &inserted {
        if let Some(d) = c.lookup(i, i ^ 0x5a5a, (i % 7) as u16) { assert_eq!(d.allowed, i); }
    }
    assert_eq!(c.hash_stats().entries, c.active_nodes());
    assert_eq!(c.stats().allocations - c.stats().frees, u64::from(c.active_nodes()));
}

#[test]
fn slot_count_is_capped() {
    let c = Avc::new(64);
    assert_eq!(c.hash_stats().buckets, 1 << 16);
}
