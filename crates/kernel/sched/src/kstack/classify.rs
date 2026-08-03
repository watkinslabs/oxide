// Naming the stack a faulting address belongs to.
//
// A guard-page hit reports raw registers today, and the register that matters
// (`rsp` on the guard boundary) says only "some 16 KiB stack overflowed". Task
// stacks and the per-CPU hardirq stack come out of ONE allocator window, so the
// address alone cannot say which — and the two have different budgets, different
// worst cases and different fixes. Three sessions have been spent deciding that
// question by hand from a register dump.
//
// The reference answers it in the double-fault handler: classify the faulting
// address into a NAMED stack and print the name with the stack's bounds
// (`BUG: <name> stack guard page was hit at <addr> (stack is <lo>..<hi>)`).
// This is that classification.
//
// The arithmetic is pure and lives here, ungated, so it is testable without a
// kernel target: everything that decides an answer belongs somewhere `cargo
// test` compiles it (`docs/53`). Only the two REGISTRIES it consults — the
// leaked per-CPU interrupt-stack tops, and the running task's stack — need the
// kernel, and they are passed in.

use super::{KSTACK_VA_BASE, MAX_STACKS, PAGE, SLOT_BYTES};

/// Which stack a slot is. The names match what the fault report prints.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StackKind {
    /// A per-CPU interrupt stack (`alloc_leaked_top`), never freed.
    Irq,
    /// An ordinary kernel thread stack.
    Task,
    /// Inside the window but matching no live registration — a slot that has
    /// been freed, or one whose owner never registered. Reported as its own
    /// answer rather than guessed at: "running on a recycled slot" is a real
    /// failure mode and must not read as an ordinary task stack.
    Unowned,
}

impl StackKind {
    /// # C: O(1)
    pub const fn name(self) -> &'static [u8] {
        match self { Self::Irq => b"IRQ", Self::Task => b"TASK", Self::Unowned => b"UNOWNED" }
    }
}

/// One slot of the kstack window: an unmapped guard page then the stack.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Span {
    pub slot: usize,
    /// First byte of the guard page.
    pub guard_lo: u64,
    /// Lowest addressable stack byte; also one past the guard page.
    pub stack_lo: u64,
    /// One past the highest stack byte.
    pub stack_hi: u64,
}

impl Span {
    /// True when `va` is in the guard page — the overflow itself, as opposed to
    /// an address merely inside this slot. # C: O(1)
    pub const fn is_guard(&self, va: u64) -> bool { va >= self.guard_lo && va < self.stack_lo }

    /// Bytes still unused when the stack pointer sat at `sp`. Zero means the
    /// stack was exhausted to its last byte. # C: O(1)
    pub const fn headroom(&self, sp: u64) -> u64 {
        if sp < self.stack_lo || sp > self.stack_hi { 0 } else { sp - self.stack_lo }
    }
}

/// The slot containing `va`, or `None` outside the window.
///
/// Takes an address, not a one-past-the-end bound: a stack's `top` is the first
/// byte of the NEXT slot's guard page, so passing it names the wrong slot.
/// # C: O(1)
pub const fn span_of(va: u64) -> Option<Span> {
    if va < KSTACK_VA_BASE { return None; }
    let off = va - KSTACK_VA_BASE;
    let slot = (off / SLOT_BYTES) as usize;
    if slot >= MAX_STACKS { return None; }
    let guard_lo = KSTACK_VA_BASE + slot as u64 * SLOT_BYTES;
    Some(Span { slot, guard_lo, stack_lo: guard_lo + PAGE, stack_hi: guard_lo + SLOT_BYTES })
}

/// Slot tags, written when a slot is handed out and cleared when it is freed.
/// A tag is the only thing that distinguishes the two kinds of stack: they are
/// slots of one window and the address alone cannot say which.
pub const TAG_NONE: u8 = 0;
pub const TAG_TASK: u8 = 1;
pub const TAG_IRQ: u8 = 2;

/// Name a slot from its tag.
///
/// An untagged slot is reported as its own answer rather than defaulted to
/// TASK: running on a slot nobody owns — freed underneath its user, or never
/// registered — is a distinct failure mode and must not read as an ordinary
/// task stack.
/// # C: O(1)
pub const fn kind_from_tag(tag: u8) -> StackKind {
    match tag { TAG_IRQ => StackKind::Irq, TAG_TASK => StackKind::Task, _ => StackKind::Unowned }
}


/// Distinct return sites tracked when asking what filled a stack. Runaway
/// nesting repeats ONE site thousands of times, so a small table finds it.
const HIST_SLOTS: usize = 6;

/// The most-repeated code address among `words`, with its count.
///
/// Answers the question a `headroom=0` report raises and cannot itself settle:
/// was the stack consumed by a deep-but-finite chain, or by the same frame over
/// and over? A static depth walk measures ONE pass, so when it says 8.7 KB and
/// the stack dies at 16 KB, the difference is repetition — and the address that
/// repeats names the site.
///
/// Pure over a slice so it is testable without a kernel; the caller supplies
/// the stack's words and the kernel-text bounds that make an address a return
/// site rather than data.
/// # C: O(words · HIST_SLOTS)
pub fn top_repeat(words: &[u64], text_lo: u64, text_hi: u64) -> (u64, u32) {
    let mut addr = [0u64; HIST_SLOTS];
    let mut cnt = [0u32; HIST_SLOTS];
    for &v in words {
        if v < text_lo || v >= text_hi { continue; }
        let mut hit = false;
        for i in 0..HIST_SLOTS {
            if addr[i] == v { cnt[i] += 1; hit = true; break; }
        }
        if hit { continue; }
        // Replace the weakest entry, so a site that dominates survives even if
        // it is not seen first.
        let mut weakest = 0;
        for i in 1..HIST_SLOTS { if cnt[i] < cnt[weakest] { weakest = i; } }
        if cnt[weakest] == 0 { addr[weakest] = v; cnt[weakest] = 1; }
        else { cnt[weakest] -= 1; }
    }
    let mut best = 0;
    for i in 1..HIST_SLOTS { if cnt[i] > cnt[best] { best = i; } }
    (addr[best], cnt[best])
}

#[cfg(test)]
#[path = "classify/tests.rs"] mod tests;
