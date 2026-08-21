use super::*;

// (10) Concurrent stress.
// ---------------------------------------------------------------------------

#[test]
fn concurrent_alloc_free_smoke() {
    // 4 threads, each does N alloc-then-free cycles. Verifies Spinlock
    // serializes correctly + final state is clean.
    let n_pages = 4096u64;
    let pmm = Arc::new(build(n_pages));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let pmm = Arc::clone(&pmm);
        handles.push(thread::spawn(move || {
            for _ in 0..500 {
                if let Ok(p) = pmm.alloc(Order(0)) {
                    // SAFETY: just allocated by this thread.
                    unsafe { pmm.free(p, Order(0)) };
                }
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    assert_eq!(pmm.allocated_pages(), 0);
    assert_eq!(pmm.free_pages(), n_pages);
    // SAFETY: all threads joined; sole accessor.
    unsafe { pmm.audit() };
}

#[test]
fn concurrent_pcp_drain_refill_keeps_one_owner_per_page() {
    let n_pages = 2048u64;
    let pmm = Arc::new(build(n_pages));
    let mut workers = Vec::new();
    for _ in 0..3 {
        let pmm = Arc::clone(&pmm);
        workers.push(thread::spawn(move || {
            for _ in 0..2_000 {
                if let Ok(pfn) = pmm.alloc(Order(0)) {
                    // SAFETY: this worker owns pfn until this exact free.
                    unsafe { pmm.free(pfn, Order(0)) };
                }
            }
        }));
    }
    let drainer = {
        let pmm = Arc::clone(&pmm);
        thread::spawn(move || { for _ in 0..2_000 { pmm.drain_pcp_for_test(); } })
    };
    for worker in workers { worker.join().unwrap(); }
    drainer.join().unwrap();
    pmm.drain_pcp_for_test();
    assert_eq!(pmm.allocated_pages(), 0);
    assert_eq!(pmm.free_pages(), n_pages);
    // SAFETY: every worker joined and the final drain completed.
    unsafe { pmm.audit() };
}

#[test]
fn concurrent_unique_pfns_no_overlap() {
    // Each thread allocs a batch, holds them, threads compare for overlap.
    let n_pages = 1024u64;
    let pmm = Arc::new(build(n_pages));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let pmm = Arc::clone(&pmm);
        handles.push(thread::spawn(move || {
            let mut local: Vec<(u64, u8)> = Vec::new();
            for _ in 0..50 {
                let o = (local.len() % 3) as u8;
                if let Ok(p) = pmm.alloc(Order(o)) {
                    local.push((p.0, o));
                }
            }
            local
        }));
    }
    let mut all: Vec<(u64, u8)> = Vec::new();
    for h in handles { all.extend(h.join().unwrap()); }
    // Verify no two outstanding ranges overlap.
    for i in 0..all.len() {
        let (p, o) = all[i];
        let span = 1u64 << o;
        for j in (i + 1)..all.len() {
            let (q, qo) = all[j];
            let qspan = 1u64 << qo;
            let overlap = !(q + qspan <= p || p + span <= q);
            assert!(!overlap, "overlap pfn {}+{} vs {}+{}", p, span, q, qspan);
        }
    }
    // Free everything.
    for (p, o) in all {
        // SAFETY: each (p,o) was just returned by Pmm::alloc.
        unsafe { pmm.free(Pfn(p), Order(o)) };
    }
    assert_eq!(pmm.free_pages(), n_pages);
    // SAFETY: all threads joined.
    unsafe { pmm.audit() };
}

// ---------------------------------------------------------------------------
// (11) Proptest oracle. BTreeMap-of-outstanding agreement per `10§9`.
// ---------------------------------------------------------------------------

struct Oracle {
    outstanding: BTreeMap<u64, u8>,  // pfn → order
    total_pfns: u64,
}

impl Oracle {
    fn new(total_pfns: u64) -> Self {
        Self { outstanding: BTreeMap::new(), total_pfns }
    }
    fn allocated(&self) -> u64 {
        self.outstanding.values().map(|o| 1u64 << o).sum()
    }
    fn free(&self) -> u64 { self.total_pfns - self.allocated() }
    fn overlaps(&self, p: u64, o: u8) -> bool {
        let span = 1u64 << o;
        for (&q, &qo) in self.outstanding.iter() {
            let qspan = 1u64 << qo;
            if !(q + qspan <= p || p + span <= q) { return true; }
        }
        false
    }
}

#[derive(Debug, Clone)]
enum Op { Alloc(u8), FreeNth(usize), Reserve(u32, u32) }

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0u8..=4u8).prop_map(Op::Alloc),
        4 => (0usize..64).prop_map(Op::FreeNth),
        1 => (0u32..1024, 0u32..16).prop_map(|(s, l)| Op::Reserve(s, l)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 200, max_shrink_iters: 1024, .. ProptestConfig::default()
    })]

    #[test]
    fn oracle_agreement(ops in proptest::collection::vec(op_strategy(), 1..600)) {
        let n = 1024u64;
        let pmm = build(n);
        let mut oracle = Oracle::new(n);

        for op in ops {
            match op {
                Op::Alloc(o) => {
                    match pmm.alloc(Order(o)) {
                        Ok(p) => {
                            prop_assert_eq!(p.0 & ((1u64 << o) - 1), 0);  // I4
                            prop_assert!(p.0 < n);
                            prop_assert!(!oracle.outstanding.contains_key(&p.0));
                            prop_assert!(!oracle.overlaps(p.0, o), "alloc overlap");
                            oracle.outstanding.insert(p.0, o);
                        }
                        Err(Error::NoMem) => { /* allocator may legitimately fail */ }
                        Err(e) => prop_assert!(false, "unexpected alloc err {:?}", e),
                    }
                }
                Op::FreeNth(n_idx) => {
                    let keys: Vec<(u64, u8)> = oracle.outstanding.iter().map(|(k, v)| (*k, *v)).collect();
                    if keys.is_empty() { continue; }
                    let (p, o) = keys[n_idx % keys.len()];
                    // SAFETY: (p, o) was returned by pmm.alloc and is still oracle-tracked.
                    unsafe { pmm.free(Pfn(p), Order(o)) };
                    oracle.outstanding.remove(&p);
                }
                Op::Reserve(_s, _l) => {
                    // reserve_early would race with alloc/free state in
                    // unpredictable ways; we keep it out of the oracle
                    // op stream and test it separately above.
                }
            }
            prop_assert_eq!(pmm.free_pages(), oracle.free());
            prop_assert_eq!(pmm.allocated_pages(), oracle.allocated());
            // SAFETY: hosted single-thread; audit takes its own lock.
            unsafe { pmm.audit() };
        }
        // Free everything left, expect full recovery.
        let leftover: Vec<(u64, u8)> = oracle.outstanding.iter().map(|(k,v)| (*k,*v)).collect();
        for (p, o) in leftover {
            // SAFETY: tracked outstanding by oracle ⇒ valid pfn at order.
            unsafe { pmm.free(Pfn(p), Order(o)) };
        }
        prop_assert_eq!(pmm.free_pages(), n);
        // SAFETY: hosted single-thread.
        unsafe { pmm.audit() };
    }

    #[test]
    fn aligned_pfn_invariant(o in 0u8..=8u8, n_pre in 0u32..200) {
        let pmm = build(2048);
        for _ in 0..n_pre { let _ = pmm.alloc(Order(0)); }
        if let Ok(p) = pmm.alloc(Order(o)) {
            prop_assert_eq!(p.0 & ((1u64 << o) - 1), 0);
        }
    }
}
