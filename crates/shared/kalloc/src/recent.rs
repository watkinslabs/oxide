// B1347 recent-kalloc-op ring: the alloc/free call sequence bracketing a stray
// write, dumped on a tight-mode detection or on a fault.

#[cfg(feature = "debug-dealloc-diag")]
use core::sync::atomic::{AtomicU64, Ordering};

/// B1347: ring of the last `RECENT_N` kalloc op (caller_ip, base<<1|is_alloc),
/// dumped on a tight-mode detection. The stray write that corrupts a freed block
/// is NOT a kalloc op — but it happens BETWEEN two kalloc ops, so this ring names
/// the exact alloc/free call SEQUENCE around it (File::Drop / gc::collect / dput /
/// socket-close etc.), bracketing the writer's code. Also lets bad_node be matched
/// to a recent FREE (its freer + what ran right after). # C: O(1) push, O(N) dump.
#[cfg(feature = "debug-dealloc-diag")]
static RECENT_IP: [AtomicU64; crate::limits::RECENT_N] = [const { AtomicU64::new(0) }; crate::limits::RECENT_N];
#[cfg(feature = "debug-dealloc-diag")]
static RECENT_META: [AtomicU64; crate::limits::RECENT_N] = [const { AtomicU64::new(0) }; crate::limits::RECENT_N];
#[cfg(feature = "debug-dealloc-diag")]
static RECENT_IDX: AtomicU64 = AtomicU64::new(0);
/// B1347: `irq_info()` (IRQ_SEQ<<8|vec) at each op, so a jump between the last
/// clean op and the detection proves a hard IRQ fired in the write window.
#[cfg(feature = "debug-dealloc-diag")]
static RECENT_IRQ: [AtomicU64; crate::limits::RECENT_N] = [const { AtomicU64::new(0) }; crate::limits::RECENT_N];

/// Push one op into the recent-op ring. Serialized by the alloc/dealloc IRQ-off +
/// single-CPU invariant (no cross-op concurrency). # C: O(1)
#[cfg(feature = "debug-dealloc-diag")]
pub(crate) fn record_recent_op(caller_ip: u64, base: usize, is_alloc: bool) {
    use crate::limits::RECENT_N;
    let idx = RECENT_IDX.fetch_add(1, Ordering::AcqRel) as usize % RECENT_N;
    RECENT_IP[idx].store(caller_ip, Ordering::Release);
    RECENT_META[idx].store(((base as u64) & !1) | is_alloc as u64, Ordering::Release);
    RECENT_IRQ[idx].store(crate::hooks::irq_info(), Ordering::Release);
}

/// Dump the recent-op ring oldest→newest on a detection. # C: O(N)
#[cfg(feature = "debug-dealloc-diag")]
pub(crate) fn dump_recent_ops() {
    use crate::limits::RECENT_N;
    let end = RECENT_IDX.load(Ordering::Acquire) as usize;
    let start = end.saturating_sub(RECENT_N);
    for i in start..end {
        let slot = i % RECENT_N;
        let ip = RECENT_IP[slot].load(Ordering::Acquire);
        if ip == 0 { continue; }
        let meta = RECENT_META[slot].load(Ordering::Acquire);
        let irq = RECENT_IRQ[slot].load(Ordering::Acquire);
        klog::write_primary_raw(b"[KALLOC] recent-op ");
        klog::write_primary_raw(if meta & 1 != 0 { b"A" } else { b"F" });
        klog::write_primary_raw(b" ip=0x");
        klog::write_primary_hex_u64(ip);
        klog::write_primary_raw(b" base=0x");
        klog::write_primary_hex_u64(meta & !1);
        klog::write_primary_raw(b" irqseq=");
        klog::write_primary_dec_u64(irq >> 8);
        klog::write_primary_raw(b" vec=0x");
        klog::write_primary_hex_u64(irq & 0xff);
        klog::write_primary_raw(b"\n");
    }
}

/// B1347: dump the recent-op ring + current IRQ info on a FAULT (any
/// manifestation — kalloc panic, #GP xrstor, #PF small-ptr), so the same
/// corruption evidence is captured even when the stray offset-0/8 write lands on
/// a LIVE structure and faults on use before a kalloc op catches it. A jump in
/// `irqseq_now` above the last recent-op's `irqseq` proves a hard IRQ fired since
/// the last kalloc op — i.e. the write was in that IRQ handler. Always compiled;
/// no-op unless `debug-dealloc-diag` is built AND tight mode is armed. # C: O(N)
pub fn dump_corruption_diag() {
    #[cfg(feature = "debug-dealloc-diag")]
    if crate::validate::TIGHT_VALIDATE.load(Ordering::Acquire) {
        let irq = crate::hooks::irq_info();
        klog::write_primary_raw(b"[KALLOC] fault-diag irqseq_now=");
        klog::write_primary_dec_u64(irq >> 8);
        klog::write_primary_raw(b" vec=0x");
        klog::write_primary_hex_u64(irq & 0xff);
        klog::write_primary_raw(b"\n");
        dump_recent_ops();
    }
}
