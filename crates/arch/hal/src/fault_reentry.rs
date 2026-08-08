// Fault-dispatch re-entry policy, shared by both architectures' exception
// dispatchers.
//
// A synchronous exception is allowed to nest. Resolving a user fault can
// legitimately touch user memory again — pushing a signal frame onto an
// unfaulted user stack is the everyday case — and that second access may itself
// fault and be resolved. What is NEVER legitimate is the SAME faulting address
// recurring on the SAME kernel stack while an earlier fault at that address is
// still being resolved: the resolver has demonstrably failed to make progress,
// and taking the fault again can only produce another identical failure, one
// exception frame deeper, until the stack's guard page ends it.
//
// That is what a kernel-mode access to an unmapped user address did here: an
// in-range pointer that nothing maps, dereferenced with no exception-table
// fixup, produced a repeating frame and a stack-guard hit instead of a
// diagnosis. The reference's fault path cannot loop that way because its "no VMA
// covers this address" verdict is TERMINAL for a kernel-mode access — it oopses
// there rather than re-entering the resolver.
//
// So this module supplies the terminal condition oxide's dispatchers were
// missing, as a rule with no tunable in it: a fault address already in flight on
// this kernel stack is unresolvable, full stop.
//
// WHY THE STACK POINTER IS PART OF THE KEY, AND WHY THERE IS NO UNWIND CALL
//
// A fault resolver here may BLOCK — demand paging waits on real block I/O — so
// the CPU switches to another task with a fault still in flight. A record that
// had to be retired by a matching "leave" would therefore leak on every blocking
// fault, and a leaked record is worse than no guard: it eventually refuses a
// legitimate fault and halts a healthy kernel.
//
// So a record carries the kernel stack pointer of the frame that made it, and
// every entry PRUNES records that cannot be outer frames of the caller. Stacks
// grow down, so a genuine outer frame sits ABOVE the caller by less than one
// stack's span; a record left behind by a different task is on a different stack
// and fails that window. The guard is therefore self-correcting: it needs no
// unwind, cannot leak, and cannot be left unbalanced by an early return.
//
// Pure state machine over explicit CPU/address/stack inputs, so every transition
// is `cargo test -p hal` provable rather than only observable at a QEMU boot.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// CPU slots tracked. An index at or above it folds into range rather than
/// being dropped, because a mis-indexed CPU must still be guarded.
pub const CPUS: usize = 64;

/// In-flight faults tracked per CPU. A legitimate chain is short — a user
/// access faults, its resolution touches user memory once more. Exhausting the
/// records means the nesting is not a chain but a runaway.
pub const DEPTH: usize = 4;

/// What the dispatcher should do with the fault it just took.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// Not already in flight on this stack; run the resolver.
    Resolve,
    /// Already being resolved at this address on this stack, or nested past the
    /// record bound. The dispatcher must NOT run the resolver again: report and
    /// halt.
    Runaway,
}

/// Sentinel for an unused record. A real stack pointer of `0` cannot name a
/// frame.
const EMPTY_SP: u64 = 0;

static ADDRS: [[AtomicU64; DEPTH]; CPUS] =
    [const { [const { AtomicU64::new(0) }; DEPTH] }; CPUS];
static SPS: [[AtomicU64; DEPTH]; CPUS] =
    [const { [const { AtomicU64::new(EMPTY_SP) }; DEPTH] }; CPUS];
static DEPTHS: [AtomicUsize; CPUS] = [const { AtomicUsize::new(0) }; CPUS];

/// Fold a raw CPU identifier (APIC id, MPIDR affinity) into a slot.
/// # C: O(1)
pub fn slot(raw: u64) -> usize { (raw as usize) % CPUS }

/// Is the record at `rec_sp` an outer frame of a fault taken at `sp`, on the
/// same `span`-byte kernel stack? Outer frames sit above, by less than one
/// stack; anything else belongs to a stack this fault is not running on.
/// # C: O(1)
pub fn is_outer_frame(rec_sp: u64, sp: u64, span: u64) -> bool {
    rec_sp != EMPTY_SP && rec_sp > sp && rec_sp - sp < span
}

/// Record that this CPU has begun resolving a fault at `addr`, from a frame
/// whose kernel stack pointer is `sp` on a `span`-byte stack, and say whether it
/// may. Self-correcting: records that cannot be outer frames of this one are
/// dropped here, so there is nothing to retire afterwards.
///
/// Single-CPU-owned state: only the faulting CPU touches its own records, with
/// interrupts masked, so the ordering only has to stop the compiler hoisting
/// across the fault window.
/// # C: O(DEPTH)
pub fn enter(cpu: usize, addr: u64, sp: u64, span: u64) -> Verdict {
    let cpu = cpu % CPUS;
    let d = DEPTHS[cpu].load(Ordering::Relaxed);
    let mut kept = 0usize;
    let mut seen = false;
    for i in 0..d.min(DEPTH) {
        let rec_sp = SPS[cpu][i].load(Ordering::Relaxed);
        if !is_outer_frame(rec_sp, sp, span) { continue; }
        let rec_addr = ADDRS[cpu][i].load(Ordering::Relaxed);
        if rec_addr == addr { seen = true; }
        SPS[cpu][kept].store(rec_sp, Ordering::Relaxed);
        ADDRS[cpu][kept].store(rec_addr, Ordering::Relaxed);
        kept += 1;
    }
    DEPTHS[cpu].store(kept, Ordering::Relaxed);
    if seen || kept >= DEPTH { return Verdict::Runaway; }
    SPS[cpu][kept].store(sp, Ordering::Relaxed);
    ADDRS[cpu][kept].store(addr, Ordering::Relaxed);
    DEPTHS[cpu].store(kept + 1, Ordering::Relaxed);
    Verdict::Resolve
}

/// Retire the record this CPU made for the fault taken at `sp`, once that fault
/// has been resolved (or conceded). Matching on `sp` rather than popping the
/// newest keeps the retirement correct when a resolver blocked and another
/// fault made a record in the meantime.
///
/// Retiring is not what makes the guard safe — the prune in [`enter`] already
/// bounds a record's life to frames that could be outer frames of the next
/// fault. It is what makes it PRECISE: without it a resolved fault's record
/// outlives the frame that made it, and the next legitimate fault at the same
/// address from a deeper frame on the same stack reads as a recursion. A COW
/// write fault on one page, resolved and taken again later in the same syscall,
/// is exactly that shape.
/// # C: O(DEPTH)
pub fn leave(cpu: usize, sp: u64) {
    let cpu = cpu % CPUS;
    let d = DEPTHS[cpu].load(Ordering::Relaxed).min(DEPTH);
    let mut kept = 0usize;
    for i in 0..d {
        let rec_sp = SPS[cpu][i].load(Ordering::Relaxed);
        if rec_sp == sp { continue; }
        let rec_addr = ADDRS[cpu][i].load(Ordering::Relaxed);
        SPS[cpu][kept].store(rec_sp, Ordering::Relaxed);
        ADDRS[cpu][kept].store(rec_addr, Ordering::Relaxed);
        kept += 1;
    }
    DEPTHS[cpu].store(kept, Ordering::Relaxed);
}

/// Records currently in flight for `cpu`, for the runaway report. # C: O(1)
pub fn depth(cpu: usize) -> usize { DEPTHS[cpu % CPUS].load(Ordering::Relaxed) }

#[cfg(test)] mod tests;
