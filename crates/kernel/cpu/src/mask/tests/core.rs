extern crate std;

use super::super::*;
use ::core::sync::atomic::Ordering;
use crate::MAX_CPUS;

#[test]
fn mask_accepts_each_currently_addressable_cpu_and_rejects_the_next() {
    let mut m = CpuMask::empty();
    assert!(m.insert(0));
    assert!(m.insert(CPU_MASK_WORD_BITS - 1));
    assert!(m.contains(0));
    assert!(m.contains(CPU_MASK_WORD_BITS - 1));
    assert!(!m.contains(MAX_CPUS));
}

#[test]
fn all_names_every_addressable_cpu_without_tail_bits() {
    let mask = CpuMask::all();
    assert!(mask.contains(0));
    assert!(mask.contains(MAX_CPUS - 1));
    assert!(!mask.contains(MAX_CPUS));
}

#[test]
fn atomic_snapshot_observes_each_published_word() {
    let m = AtomicCpuMask::new();
    m.clear();
    m.set(0, Ordering::Release);
    m.set(MAX_CPUS - 1, Ordering::Release);
    let got = m.load(Ordering::Acquire);
    assert!(got.contains(0));
    assert!(got.contains(MAX_CPUS - 1));
}

#[test]
fn concurrent_replacement_never_returns_a_torn_generation() {
    let old = CpuMask::from_words(&[0xaaaa_aaaa_aaaa_aaaa, 0x1111_1111_1111_1111,
        0xcccc_cccc_cccc_cccc, 0x3333_3333_3333_3333]);
    let new = CpuMask::from_words(&[0xbbbb_bbbb_bbbb_bbbb, 0x2222_2222_2222_2222,
        0xdddd_dddd_dddd_dddd, 0x4444_4444_4444_4444]);
    let mask = std::sync::Arc::new(AtomicCpuMask::new());
    mask.store(old, Ordering::Release);
    std::thread::scope(|scope| {
        let writing = std::sync::Arc::clone(&mask);
        scope.spawn(move || {
            for i in 0..20_000 {
                writing.store(if i & 1 == 0 { new } else { old }, Ordering::Release);
            }
        });
        let reading = std::sync::Arc::clone(&mask);
        scope.spawn(move || {
            for _ in 0..20_000 {
                let seen = reading.load(Ordering::Acquire);
                assert!(seen == old || seen == new, "atomic CPU mask returned a torn generation");
            }
        });
    });
}
