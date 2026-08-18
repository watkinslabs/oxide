// Scheduler-side classification of an aarch64 bad-stack entry.
//
// The arch report states the comparison the entry asm made — SP, the bounds,
// which side, ESR/ELR/FAR. What it cannot state is anything the scheduler owns:
// which KIND of stack that slot is, how a 16 KiB stack came to be full, and the
// chain of return sites still on it. Those decide the fix — a deep call chain,
// a runaway recursion and interrupts nesting on the wrong stack all print the
// same register dump and need three different repairs.
//
// `hal` cannot reach `sched` (the dependency runs the other way), so the arch
// side takes this as a hook. Same shape as the x86 `install_stack_name_hook`,
// which is the equivalent report on that arch; aarch64 had the hook and no
// caller, so every overflow so far was diagnosed from registers alone.
//
// Runs on the per-CPU overflow stack with ~4 KiB of room and DAIF masked, so:
// no locks, no allocation, one small fixed buffer, atomics only.

use super::{classify, kernel_text_bounds, span_of, stack_top_repeat};

/// Return sites printed. The chain that matters is the innermost end; a deeper
/// buffer costs overflow-stack bytes the report cannot spare.
const CHAIN_MAX: usize = 24;

/// Print what the scheduler knows about the stack `sp` overflowed.
///
/// Installed into `hal_aarch64` as its bad-stack probe. Reads the faulting
/// slot's own words, which are mapped for as long as the slot is handed out.
/// # C: O(KSTACK_BYTES/8)
/// # Ctx: exception, IRQ-off, on the per-CPU overflow stack
/// # Lk: none — atomics only
pub fn report(sp: u64) {
    let pc = crate::preempt::preempt_count();
    klog::write_raw(b"[BADSTACK] preempt_count=");
    klog::write_hex_u64(pc as u64);
    klog::write_raw(b" hardirq=");
    klog::write_dec_u64(crate::preempt::hardirq_count() as u64);
    klog::write_raw(b" softirq=");
    klog::write_dec_u64(crate::preempt::softirq_count() as u64);
    let Some(span) = span_of(sp) else {
        klog::write_raw(b" stack=OUTSIDE-WINDOW\n");
        return;
    };
    let (kind, _) = match super::describe_fault(span.stack_lo) {
        Some(v) => v,
        None => (classify::StackKind::Unowned, span),
    };
    klog::write_raw(b" kind=");
    klog::write_raw(kind.name());
    klog::write_raw(b" slot=");
    klog::write_dec_u64(span.slot as u64);
    let (site, count) = stack_top_repeat(&span);
    klog::write_raw(b" top_repeat=");
    klog::write_hex_u64(site);
    klog::write_raw(b" x");
    klog::write_dec_u64(count as u64);
    klog::write_raw(b"\n");
    let n = ((span.stack_hi - span.stack_lo) / 8) as usize;
    // SAFETY: [stack_lo, stack_hi) is the faulting slot's mapped stack; reading it as words is an aligned read of memory mapped for as long as the slot is handed out.
    let words = unsafe { core::slice::from_raw_parts(span.stack_lo as *const u64, n) };
    let mut chain = [0u64; CHAIN_MAX];
    let (text_lo, text_hi) = kernel_text_bounds();
    let got = classify::text_frames(words, text_lo, text_hi, &mut chain);
    klog::write_raw(b"[BADSTACK] chain innermost-first:");
    for a in chain.iter().take(got) {
        klog::write_raw(b" ");
        klog::write_hex_u64(*a);
    }
    klog::write_raw(b"\n");
}
