// Free-list integrity checking: the tight/periodic validators the corruption
// hunts run on, plus the on-demand checkpoint + dump entry points.

#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
use core::sync::atomic::{AtomicBool, Ordering};

use crate::state::KAlloc;
#[cfg(feature = "debug-dealloc-diag")]
use crate::state::GLOBAL_ALLOC;
#[cfg(feature = "debug-dealloc-diag")]
use crate::limits::DIAG_VALIDATE_INTERVAL;
#[cfg(feature = "debug-heappoison")]
use crate::limits::VALIDATE_INTERVAL;
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
use crate::hooks::{next_seq, probe_corruption};
#[cfg(feature = "debug-dealloc-diag")]
use crate::hooks::{current_ctx, irq_info};
#[cfg(feature = "debug-dealloc-diag")]
use crate::recent::dump_recent_ops;

/// B1347: when set, `periodic_validate_diag` validates on EVERY kalloc op
/// (bypassing the countdown). Armed by `arm_tight_validate` at the start of the
/// zram-disksize sysfs write — the narrow window where the boot corruptor
/// writes garbage into a freed block <32 kalloc ops before the big allocation's
/// carve trips on it. Per-op validation from that point catches the first bad
/// node within ONE op of the stray write, so `current_ctx()` names the WRITER.
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
pub(crate) static TIGHT_VALIDATE: AtomicBool = AtomicBool::new(false);

/// Arm per-op free-list validation for the corruption hunt. No-op unless a diag
/// feature is compiled in, so callers (the zram sysfs handler) need no cfg gate
/// or feature plumbing. # C: O(1)
pub fn arm_tight_validate() {
    #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
    if !TIGHT_VALIDATE.swap(true, Ordering::AcqRel) {
        klog::write_primary_raw(b"[KALLOC] tight-validate-armed\n");
    }
}

/// B1347: validate the free list NOW and log `[KALLOC] chkpt <tag> ok|BAD`. The
/// corruptor is process-context in the set_disksize call chain (C210 proved no
/// IRQ fires in the window); sprinkling checkpoints through that synchronous code
/// pinpoints the exact sub-operation between the last-clean and first-corrupt
/// checkpoint — that call did the stray write. No-op off dealloc-diag/unarmed.
/// # C: O(N free nodes)
pub fn checkpoint(tag: &'static [u8]) {
    #[cfg(feature = "debug-dealloc-diag")]
    if TIGHT_VALIDATE.load(Ordering::Acquire) {
        // SAFETY: GLOBAL_ALLOC is the canonical allocator installed at boot.
        let raw = GLOBAL_ALLOC.load(Ordering::Acquire);
        if raw == 0 { return; }
        // SAFETY: raw is the &'static KAlloc published by install_global.
        let a: &KAlloc = unsafe { &*(raw as *const KAlloc) };
        let bad = a.inner.lock().holes.validate();
        klog::write_primary_raw(b"[KALLOC] chkpt ");
        klog::write_primary_raw(tag);
        match bad {
            None => klog::write_primary_raw(b" ok\n"),
            Some(b) => {
                klog::write_primary_raw(b" BAD@0x");
                klog::write_primary_hex_u64(b as u64);
                klog::write_primary_raw(b"\n");
            }
        }
    }
    #[cfg(not(feature = "debug-dealloc-diag"))]
    let _ = tag;
}

impl KAlloc {
    /// B1347 diagnostic: every `DIAG_VALIDATE_INTERVAL`th dealloc, walk the whole
    /// free list and, on the FIRST corrupt node (deduped by address so a
    /// not-yet-overwritten bad node logs once), print the running context that
    /// the stale write happened under — packed `current_ctx()` decoded into
    /// tid / last_syscall / preempt_count / in-IRQ — plus the node's free-IP
    /// provenance. Does NOT panic: boot continues so the eventual zram-stumble
    /// crash still appears and can be correlated with the early context capture.
    /// # C: amortized O(1), O(N) on tick
    #[cfg(feature = "debug-dealloc-diag")]
    pub(crate) fn periodic_validate_diag(&self, op_ip: u64) {
        // Tight mode (armed for the zram window) validates on EVERY op so the
        // stray write is caught within one kalloc op; otherwise every Nth op.
        if !TIGHT_VALIDATE.load(Ordering::Acquire) {
            if self.validate_countdown_diag.fetch_sub(1, Ordering::AcqRel) != 1 { return; }
            self.validate_countdown_diag.store(DIAG_VALIDATE_INTERVAL, Ordering::Release);
        }
        self.validate_and_report_diag(op_ip);
    }

    /// B1347: tight-mode op-START check. `periodic_validate_diag` runs at op END
    /// (after the carve/coalesce) — but the crashing carve PANICS inside
    /// `holes.alloc`/`holes.dealloc` BEFORE that end-of-op check runs (boot4 got
    /// 0 diag hits for this reason). Validating at op START, when tight, catches
    /// a corruption ALREADY present (written by the immediately-preceding op /
    /// stray write) before this op's carve can panic on it — so `current_ctx()`
    /// names the writer instead of the boot dying uninstrumented. # C: O(1)/O(N)
    #[cfg(feature = "debug-dealloc-diag")]
    pub(crate) fn tight_precheck(&self, op_ip: u64) {
        if TIGHT_VALIDATE.load(Ordering::Acquire) { self.validate_and_report_diag(op_ip); }
    }

    /// Walk the free list once and, on the first NEW corrupt node (deduped by
    /// address), log the running context + provenance. Shared by the op-end
    /// (`periodic_validate_diag`) and op-start (`tight_precheck`) paths. Does NOT
    /// panic. # C: O(N free nodes)
    #[cfg(feature = "debug-dealloc-diag")]
    fn validate_and_report_diag(&self, op_ip: u64) {
        // Bind+drop the guard before logging (same lifetime-extension / panic-path
        // re-entrancy reasoning as `periodic_validate`).
        let bad = self.inner.lock().holes.validate();
        let Some(bad) = bad else { return; };
        if self.last_bad_diag.swap(bad as u64, Ordering::AcqRel) == bad as u64 { return; }
        // Packed by the kernel hook: bits[63:40]=preempt_count(24), [39:20]=syscall(20),
        // [19:0]=tid(20). `u64::MAX` = no current task.
        let ctx = current_ctx();
        let preempt = (ctx >> 40) & 0xFF_FFFF;
        klog::write_primary_raw(b"[KALLOC] seq=");
        klog::write_primary_dec_u64(next_seq());
        klog::write_primary_raw(b" diag-validate-failed bad_node=0x");
        klog::write_primary_hex_u64(bad as u64);
        klog::write_primary_raw(b" last_op_ip=0x");
        klog::write_primary_hex_u64(op_ip);
        klog::write_primary_raw(b" ctx.tid=");
        klog::write_primary_dec_u64(ctx & 0xF_FFFF);
        klog::write_primary_raw(b" ctx.syscall=");
        klog::write_primary_dec_u64((ctx >> 20) & 0xF_FFFF);
        klog::write_primary_raw(b" ctx.preempt=0x");
        klog::write_primary_hex_u64(preempt);
        // in_irq: any softirq(8-15)/hardirq(16-19)/nmi bit above the low preempt byte.
        klog::write_primary_raw(b" ctx.in_irq=");
        klog::write_primary_dec_u64(((preempt >> 8) != 0) as u64);
        // B1347: hard-IRQ arrival counter+vector NOW. Compare `irqseq` here with
        // the last recent-op's irqseq: a jump ⇒ a hard IRQ fired in the write
        // window (and `vec` names it) — the write happened in that IRQ handler.
        let irq = irq_info();
        klog::write_primary_raw(b" irqseq=");
        klog::write_primary_dec_u64(irq >> 8);
        klog::write_primary_raw(b" vec=0x");
        klog::write_primary_hex_u64(irq & 0xff);
        klog::write_primary_raw(b"\n");
        // Provenance of the corrupt node + PMM classification of its address.
        self.inner.lock().holes.print_free_ip(bad);
        probe_corruption(bad);
        // Recent alloc/free call sequence around the stray write (brackets the writer).
        dump_recent_ops();
    }

    /// Diagnostic (`debug-heappoison`) periodic integrity check: every
    /// `VALIDATE_INTERVAL`th call runs a full free-list `validate()` and
    /// panics naming the bad node immediately, instead of waiting for a
    /// later unrelated `alloc`/merge to trip over already-stale corruption.
    /// Tightens the corruption-to-detection window from "one execve" to
    /// "one interval of alloc/dealloc calls". # C: amortized O(1), O(N) on tick
    #[cfg(feature = "debug-heappoison")]
    pub(crate) fn periodic_validate(&self, op_ip: u64) {
        if self.validate_countdown.fetch_sub(1, Ordering::AcqRel) != 1 { return; }
        self.validate_countdown.store(VALIDATE_INTERVAL, Ordering::Release);
        // `if let Some(bad) = self.inner.lock().holes.validate() { ... }` would
        // extend the lock guard's temporary lifetime across the whole block
        // (Rust's if-let temporary-lifetime-extension) -- holding this lock
        // while `assert!` panics below. The panic handler's own klog path can
        // reach a framebuffer console scroll that allocates, which would then
        // self-deadlock reacquiring this same lock on this same CPU: a silent
        // hang with the diagnostic print as the last-ever output, instead of a
        // visible panic. Bind and drop explicitly before asserting.
        let bad = self.inner.lock().holes.validate();
        if let Some(bad) = bad {
            klog::write_primary_raw(b"[KALLOC] seq=");
            klog::write_primary_dec_u64(next_seq());
            klog::write_primary_raw(b" periodic-validate-failed bad_node=");
            klog::write_primary_hex_u64(bad as u64);
            klog::write_primary_raw(b" last_op_ip=");
            klog::write_primary_hex_u64(op_ip);
            klog::write_primary_raw(b"\n");
            probe_corruption(bad);
            assert!(false, "kalloc periodic validate failed");
        }
    }

    /// Walk the whole free list now and report the first corrupt node, if
    /// any. Diagnostic-only bisection checkpoint: call at several points
    /// during boot to localize WHEN the free list first breaks, rather than
    /// waiting for the next unrelated `alloc`/`dealloc` to trip a reactive
    /// assert far downstream of the actual corruption. # C: O(N)
    #[cfg(feature = "debug-heappoison")]
    pub fn validate_now(&self) -> Option<usize> { self.inner.lock().holes.validate() }

    /// Print the free list's (addr, size) layout right now, capped at
    /// `cap` entries. Diagnostic-only (debug-heappoison): names the
    /// allocation adjacent to a corrupted node in address order. # C: O(cap)
    #[cfg(feature = "debug-heappoison")]
    pub fn dump_now(&self, cap: usize) { self.inner.lock().holes.dump(cap); }
}
