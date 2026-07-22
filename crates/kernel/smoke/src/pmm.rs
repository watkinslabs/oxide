//! PMM boot smoke/stress (debug-pmm). Moved out of kernel_main — exercises
//! the buddy allocator alloc/free + multi-order split/merge after init.
use pmm::{Order, PageBacking, Pmm};
use sync::IrqGate;

/// Run the PMM smoke + stress passes (klogs results).
/// # C: O(STRESS_N + orders)
pub fn run<B: PageBacking, I: IrqGate>(p: &Pmm<B, I>) {
    match p.alloc(pmm::Order(0)) {
        Ok(pfn) => {
            klog::kinfo!("pmm-smoke: alloc(0) ok");
            // SAFETY: pfn was just returned by alloc(0); free is
            // the matching counterpart and is single-threaded
            // here per pre-init contract.
            unsafe { p.free(pfn, pmm::Order(0)); }
            klog::kinfo!("pmm-smoke: free(0) ok");
        }
        Err(_) => klog::kerror!("pmm-smoke: alloc(0) failed"),
    }
    // Memory summary: `pmm: <free_mib> MiB free, <alloc> page(s) reserved`.
    let free_pages = p.free_pages();
    let alloc_pages = p.allocated_pages();
    // 4 KiB pages -> MiB: pages * 4096 / (1024*1024) = pages / 256.
    let free_mib = free_pages / 256;
    klog::write_raw(b"[INFO]  pmm: ");
    klog::write_dec_u64(free_mib);
    klog::write_raw(b" MiB free, ");
    klog::write_dec_u64(alloc_pages);
    klog::write_raw(b" page(s) reserved\n");

    // PMM stress: alloc 64 order-0 pages, free in reverse, verify
    // free_pages count matches the baseline. Catches simple
    // bookkeeping bugs the single-page smoke can't.
    const STRESS_N: usize = 64;
    let baseline = p.free_pages();
    let mut buf: [hal::Pfn; STRESS_N] = [hal::Pfn(0); STRESS_N];
    let mut got = 0usize;
    while got < STRESS_N {
        match p.alloc(pmm::Order(0)) {
            Ok(pfn) => { buf[got] = pfn; got += 1; }
            Err(_)  => break,
        }
    }
    // SAFETY: every pfn in `buf[..got]` was returned by alloc(0)
    // above and not yet freed; reverse-order frees match the
    // alloc count exactly.
    unsafe {
        while got > 0 {
            got -= 1;
            p.free(buf[got], pmm::Order(0));
        }
    }
    let after = p.free_pages();
    if after == baseline {
        klog::kinfo!("pmm-stress: 64x alloc/free balanced");
    } else {
        klog::kerror!("pmm-stress: free_pages drift");
    }

    // Multi-order stress: one alloc/free per order 0..=10. Exercises
    // the split-and-merge paths the single-order stress can't.
    let baseline_mo = p.free_pages();
    let mut order_buf: [(hal::Pfn, u8); 11] = [(hal::Pfn(0), 0); 11];
    let mut got_mo = 0usize;
    for o in 0u8..=10 {
        match p.alloc(pmm::Order(o)) {
            Ok(pfn) => { order_buf[got_mo] = (pfn, o); got_mo += 1; }
            Err(_)  => break,
        }
    }
    // SAFETY: each pair in `order_buf[..got_mo]` came from a matching
    // `alloc(o)` above; we free with the same order, single-threaded.
    unsafe {
        while got_mo > 0 {
            got_mo -= 1;
            let (pfn, o) = order_buf[got_mo];
            p.free(pfn, pmm::Order(o));
        }
    }
    if p.free_pages() == baseline_mo {
        klog::kinfo!("pmm-stress: orders 0..=10 balanced");
    } else {
        klog::kerror!("pmm-stress: multi-order drift");
    }
    // Re-emit the summary to make the round-trip visible in the trace.
    klog::write_raw(b"[INFO]  pmm: ");
    klog::write_dec_u64(p.free_pages() / 256);
    klog::write_raw(b" MiB free post-stress, ");
    klog::write_dec_u64(p.allocated_pages());
    klog::write_raw(b" page(s) reserved\n");
}
