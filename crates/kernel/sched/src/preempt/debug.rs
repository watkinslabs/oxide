// `CONFIG_DEBUG_PREEMPT` subset: names a `preempt_count` leak at the
// instruction that causes it, instead of minutes later as an unexplained
// "both CPUs idle, nothing runnable" wedge.
//
// Two detectors, covering the two ways the count goes wrong here:
//
//   * **irq_exit underflow** — `irq_exit()` reached with the HARDIRQ field
//     already clear. Either an entry path skipped `irq_enter()`, or something
//     between them cleared the field. The `fetch_sub` then borrows out of the
//     HARDIRQ field into the SOFTIRQ field above it, so `in_interrupt()` is
//     pinned true on that CPU from then on: it stops draining softirqs and
//     `should_resched()` — which gates on the WHOLE word — can never fire
//     again. Linux catches the same case in `irq_exit_rcu`'s
//     `WARN_ONCE(!in_interrupt())`.
//
//   * **idle-with-count** — a CPU about to park in `halt_forever` while
//     `in_interrupt()` is true. An idle CPU is by construction not inside a
//     hard IRQ and not serving a bottom half, so a non-zero field there is a
//     leak that has already happened. This is the detector that turns the
//     observed wedge signature into a named failure: the count is readable at
//     exactly the moment the CPU gives up looking for work.
//
// Both latch one-shot per CPU. Each condition, once true, is true on every
// subsequent tick — an unlatched detector floods the serial log it exists to
// produce, and the flood is what would push the boot past its timeout.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use cpu::MAX_CPUS;

use super::{HARDIRQ_MASK, this_cpu};

/// One-shot latch per CPU for the `irq_exit` underflow report.
static IRQ_EXIT_REPORTED: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];
/// Debug witness for the `irq_enter` / `irq_exit` pairing on each CPU.
/// It is independent of `preempt_count`, so an underflow can distinguish a
/// duplicate exit from accounting that changed between a real entry and exit.
static IRQ_ENTRY_DEPTH: [AtomicU8; MAX_CPUS] = [const { AtomicU8::new(0) }; MAX_CPUS];
/// One-shot latch per CPU for the idle-with-count report.
static IDLE_LEAK_REPORTED: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];

/// Take a CPU's one-shot latch. True exactly once per CPU per latch.
/// # C: O(1)
fn take(latch: &[AtomicBool; MAX_CPUS], cpu: usize) -> bool {
    latch.get(cpu).is_some_and(|l| !l.swap(true, Ordering::AcqRel))
}

/// Pure decision, split out so the host tests can pin it without a CPU:
/// an `irq_exit` is an underflow iff the HARDIRQ field is already clear.
/// # C: O(1)
pub fn is_irq_exit_underflow(pc: u32) -> bool { (pc & HARDIRQ_MASK) == 0 }

/// Record one hard-IRQ entry before its count increment. # C: O(1)
pub fn note_irq_enter() {
    let cpu = this_cpu();
    if let Some(depth) = IRQ_ENTRY_DEPTH.get(cpu) {
        let prior = depth.fetch_add(1, Ordering::AcqRel);
        debug_assert!(prior != u8::MAX, "irq entry witness overflow");
    }
}

/// Consume one independent entry witness and return its depth before the
/// consume. `None` proves this logical CPU reached an exit with no matching
/// dispatcher entry.
fn take_irq_entry(cpu: usize) -> Option<u8> {
    let depth = IRQ_ENTRY_DEPTH.get(cpu)?;
    let mut prior = depth.load(Ordering::Acquire);
    loop {
        if prior == 0 { return None; }
        match depth.compare_exchange_weak(prior, prior - 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(prior),
            Err(next) => prior = next,
        }
    }
}

/// Called from `irq_exit` BEFORE the subtract, with the live count.
/// # C: O(1)
pub fn check_irq_exit(pc: u32) {
    let cpu = this_cpu();
    let entry_depth = take_irq_entry(cpu);
    if !is_irq_exit_underflow(pc) { return; }
    if !take(&IRQ_EXIT_REPORTED, cpu) { return; }
    klog::write_raw(b"\n[PREEMPT-LEAK] irq_exit underflow cpu=");
    klog::write_dec_u64(cpu as u64);
    klog::write_raw(b" entry_depth=");
    klog::write_dec_u64(entry_depth.unwrap_or(0) as u64);
    klog::write_raw(b" preempt_count=0x");
    klog::write_hex_u64(pc as u64);
    klog::write_raw(b" (HARDIRQ field already clear: the sub borrows into SOFTIRQ and pins in_interrupt() true)\n");
}

/// Called from the idle loop just before parking, with the live count.
/// # C: O(1)
pub fn check_idle(pc: u32) {
    if (pc & (super::SOFTIRQ_MASK | HARDIRQ_MASK)) == 0 { return; }
    let cpu = this_cpu();
    if !take(&IDLE_LEAK_REPORTED, cpu) { return; }
    klog::write_raw(b"\n[PREEMPT-LEAK] idle with in_interrupt() cpu=");
    klog::write_dec_u64(cpu as u64);
    klog::write_raw(b" preempt_count=0x");
    klog::write_hex_u64(pc as u64);
    klog::write_raw(b" need_resched=");
    klog::write_dec_u64(super::need_resched() as u64);
    klog::write_raw(b" (leaked field: this CPU can no longer reschedule)\n");
}

/// Hosted-test-only latch reset — production never clears these.
/// # C: O(MAX_CPUS)
#[cfg(any(test, feature = "hosted"))]
pub fn _test_reset() {
    for l in IRQ_EXIT_REPORTED.iter()  { l.store(false, Ordering::Release); }
    for d in IRQ_ENTRY_DEPTH.iter() { d.store(0, Ordering::Release); }
    for l in IDLE_LEAK_REPORTED.iter() { l.store(false, Ordering::Release); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preempt::{HARDIRQ_OFFSET, SOFTIRQ_OFFSET};

    #[test]
    fn underflow_iff_hardirq_field_clear() {
        assert!(is_irq_exit_underflow(0));
        // A softirq drain in progress is NOT a hardirq nesting level.
        assert!(is_irq_exit_underflow(SOFTIRQ_OFFSET));
        // Plain preempt_disable nesting is not either.
        assert!(is_irq_exit_underflow(1));
        assert!(!is_irq_exit_underflow(HARDIRQ_OFFSET));
        assert!(!is_irq_exit_underflow(HARDIRQ_OFFSET * 2));
        assert!(!is_irq_exit_underflow(HARDIRQ_OFFSET | SOFTIRQ_OFFSET | 1));
    }

    #[test]
    fn entry_witness_separates_double_exit_from_lost_accounting() {
        _test_reset();
        assert_eq!(take_irq_entry(0), None, "an exit without entry has no witness");
        note_irq_enter();
        assert_eq!(take_irq_entry(0), Some(1), "a real entry remains visible at exit");
        assert_eq!(take_irq_entry(0), None, "the matched exit consumes exactly one witness");
        note_irq_enter();
        note_irq_enter();
        assert_eq!(take_irq_entry(0), Some(2), "nested entry preserves depth");
        assert_eq!(take_irq_entry(0), Some(1), "nested exits unwind in order");
        assert_eq!(take_irq_entry(0), None);
    }

    #[test]
    fn each_latch_fires_once_per_cpu() {
        _test_reset();
        assert!(take(&IRQ_EXIT_REPORTED, 0));
        assert!(!take(&IRQ_EXIT_REPORTED, 0));
        // A different CPU still gets its own report.
        assert!(take(&IRQ_EXIT_REPORTED, 1));
        // The two latches are independent.
        assert!(take(&IDLE_LEAK_REPORTED, 0));
        _test_reset();
        assert!(take(&IRQ_EXIT_REPORTED, 0));
    }

    #[test]
    fn out_of_range_cpu_never_reports() {
        _test_reset();
        assert!(!take(&IRQ_EXIT_REPORTED, MAX_CPUS));
        assert!(!take(&IDLE_LEAK_REPORTED, MAX_CPUS + 7));
    }
}
