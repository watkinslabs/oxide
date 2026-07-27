// B1429: BTreeMap-backed tid/vpid registry — correctness at the point-lookup
// boundary the hint cache introduces, plus scale + concurrency coverage the
// old flat Vec never needed to prove (a Vec scan is trivially "consistent",
// it just never disagrees with itself; the vpid_hint accelerator can only
// ever be a hint, so these tests exist to pin that it never lies).

use super::common::registry_test_lock;
use crate::task::{SchedClass, Task};
use alloc::sync::Arc;
use alloc::vec::Vec as AVec;
use core::sync::atomic::Ordering;
use std::sync::Barrier;
use std::vec::Vec;

fn leader(tid: u32, vpid: u32) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "leader", SchedClass::Normal { weight: 1024 }));
    t.vtgid.store(vpid, Ordering::Release);
    t.vtid.store(vpid, Ordering::Release);
    t
}

fn member(tid: u32, vpid: u32, vtid: u32) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "member", SchedClass::Normal { weight: 1024 }));
    t.vtgid.store(vpid, Ordering::Release);
    t.vtid.store(vtid, Ordering::Release);
    t
}

#[test]
fn lookup_present_absent_and_dead_weak_tid() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let present = Arc::new(Task::new(1, "p", SchedClass::Normal { weight: 1024 }));
    crate::registry::insert(&present);
    assert!(Arc::ptr_eq(&present, &crate::registry::lookup(1).unwrap()));
    assert!(crate::registry::lookup(2).is_none(), "never-inserted tid must miss");
    {
        let dead = Arc::new(Task::new(3, "d", SchedClass::Normal { weight: 1024 }));
        crate::registry::insert(&dead);
    } // last Arc drops here — Weak decays
    assert!(crate::registry::lookup(3).is_none(), "decayed Weak must miss, not dangle");
}

#[test]
fn lookup_by_vpid_present_absent_and_dead_weak() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let l = leader(10, 500);
    crate::registry::insert(&l);
    assert!(Arc::ptr_eq(&l, &crate::registry::lookup_by_vpid(500).unwrap()));
    assert!(crate::registry::lookup_by_vpid(999).is_none(), "never-registered vpid must miss");
    {
        let dying = leader(11, 600);
        crate::registry::insert(&dying);
        assert!(crate::registry::lookup_by_vpid(600).is_some());
    } // dying drops — the vpid_hint entry now points at a decayed Weak
    assert!(crate::registry::lookup_by_vpid(600).is_none(),
        "a hint pointing at a decayed Weak must fall through to the authoritative scan and miss, not upgrade a dangling entry");
}

#[test]
fn insert_and_removal_keep_tid_and_vpid_resolution_consistent() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let l = leader(20, 700);
    crate::registry::insert(&l);
    let m = member(21, 700, 721);
    crate::registry::insert(&m);

    // Leader always wins over a member, regardless of insertion order.
    let got = crate::registry::lookup_by_vpid(700).unwrap();
    assert_eq!(got.tid, 20, "hint must prefer the thread-group leader");

    // Reaping the leader must remove it from BOTH tid lookup and vpid
    // resolution, and vpid resolution must fall back to the live member —
    // never return the reaped leader, never return nothing while a live
    // member remains.
    crate::registry::mark_reaped(&l);
    assert!(crate::registry::lookup(20).is_none(), "reaped leader must be gone from tid lookup");
    let fallback = crate::registry::lookup_by_vpid(700).unwrap();
    assert_eq!(fallback.tid, 21, "vpid resolution must fall back to the surviving member");

    // Reaping the last member must make the vpid fully unresolvable.
    crate::registry::mark_reaped(&m);
    assert!(crate::registry::lookup_by_vpid(700).is_none());
    assert!(crate::registry::lookup(21).is_none());
}

#[test]
fn hint_never_demotes_a_live_leader_to_a_later_member() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    // Member inserted BEFORE its leader (fork/exec ordering isn't guaranteed
    // to be leader-first in every caller) — the hint must still end up
    // pointing at the leader once it registers, and a later member insert
    // must not overwrite a live leader hint.
    let m = member(31, 800, 831);
    crate::registry::insert(&m);
    assert_eq!(crate::registry::lookup_by_vpid(800).unwrap().tid, 31,
        "with no leader yet registered, the sole member is the correct answer");
    let l = leader(30, 800);
    crate::registry::insert(&l);
    assert_eq!(crate::registry::lookup_by_vpid(800).unwrap().tid, 30,
        "leader insert must claim the hint from an existing member");
    let m2 = member(32, 800, 832);
    crate::registry::insert(&m2);
    assert_eq!(crate::registry::lookup_by_vpid(800).unwrap().tid, 30,
        "a second member insert must not demote the live leader hint");
}

#[test]
fn scale_thousands_of_entries_resolve_correctly() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    const N: u32 = 5_000;
    let mut kept: AVec<Arc<Task>> = AVec::with_capacity(N as usize);
    for i in 0..N {
        let tid = 100_000 + i;
        let t = leader(tid, tid); // vpid == tid keeps this test's math simple
        crate::registry::insert(&t);
        kept.push(t);
    }
    assert_eq!(crate::registry::live_tids().len(), N as usize);

    // Spot-check first, middle, last, and a handful scattered through the
    // range — a linear-scan regression would still pass a "first" probe fast
    // and a "last" probe slow; checking all corners exercises both ends of
    // the map.
    for &i in &[0u32, 1, N / 2, N - 2, N - 1] {
        let tid = 100_000 + i;
        let got = crate::registry::lookup(tid).expect("tid must resolve");
        assert_eq!(got.tid, tid);
        let got_v = crate::registry::lookup_by_vpid(tid).expect("vpid must resolve");
        assert_eq!(got_v.tid, tid);
    }
    assert!(crate::registry::lookup(100_000 + N).is_none(), "one past the inserted range must miss");
    assert!(crate::registry::lookup_by_vpid(100_000 + N).is_none());

    // Coarse cost-shape guard: an O(N) linear scan pays for the full 5,000
    // entries on every one of these 5,000 lookups (25M comparisons); a
    // BTreeMap pays ~13 comparisons each (~65K total). Generous bound (this
    // is a correctness suite, not a benchmark) — regressing to a linear scan
    // here would blow through it by orders of magnitude, not by a hair.
    let start = std::time::Instant::now();
    for i in 0..N {
        let tid = 100_000 + i;
        assert!(crate::registry::lookup(tid).is_some());
    }
    let elapsed = start.elapsed();
    assert!(elapsed.as_secs() < 5,
        "{} point lookups against {} entries took {:?} — looks like an O(N) regression",
        N, N, elapsed);
}

#[test]
fn concurrent_insert_and_lookup_from_multiple_threads() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    const THREADS: u32 = 8;
    const PER_THREAD: u32 = 200;
    let start = Arc::new(Barrier::new(THREADS as usize));
    let mut joins = Vec::new();
    for w in 0..THREADS {
        let start = Arc::clone(&start);
        joins.push(std::thread::spawn(move || {
            start.wait();
            // Keep the Arcs alive for the duration of this closure so the
            // Weak entries this thread inserts stay live while every thread
            // (including this one) concurrently looks tids up.
            let mut owned: AVec<Arc<Task>> = AVec::with_capacity(PER_THREAD as usize);
            for i in 0..PER_THREAD {
                let tid = w * 10_000 + i;
                let t = leader(tid, tid);
                crate::registry::insert(&t);
                owned.push(t);
            }
            // Look up every tid this thread just inserted — must all resolve
            // even while other threads are concurrently inserting/locking.
            for i in 0..PER_THREAD {
                let tid = w * 10_000 + i;
                assert!(crate::registry::lookup(tid).is_some(), "own insert must be visible");
            }
            owned
        }));
    }
    let mut all_owned: AVec<Arc<Task>> = AVec::new();
    for j in joins {
        all_owned.extend(j.join().expect("worker thread must not panic"));
    }
    assert_eq!(all_owned.len(), (THREADS * PER_THREAD) as usize);
    for owned in &all_owned {
        assert!(crate::registry::lookup(owned.tid).is_some(),
            "every concurrently-inserted tid must be visible after all threads join");
        assert!(crate::registry::lookup_by_vpid(owned.tid).is_some());
    }
}
