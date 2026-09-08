//! One thread's kernel-owned native text runs and the paint ends they gate.
//!
//! A kernel-owned run does not rasterize inside the call that issues it: the
//! syscall frame is rewritten to the font backend's entry, so the glyphs only
//! reach the surface after that syscall returns (`31ge§1`). A paint that
//! draws its fills and its text in one kernel pass and presents at the end of
//! the same pass therefore presents a surface the glyphs have not reached,
//! and deletes the paint HDC the pending upload still names.
//!
//! Runs and the ends that owe their present to them share one FIFO. The item
//! at the head is the one in the backend; the next item starts only when it
//! completes, so runs rasterize in issue order at callback depth one instead
//! of chaining N deep on the per-thread continuation stack.
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use ipc::win32_gdi::Font;
use syscall::nt_native_gdi::TextRequest;

/// Runs one thread queues before further text of the same pass is dropped
/// rather than grow an unbounded kernel queue behind a stalled backend.
pub(crate) const MAX_PENDING: usize = 256;

/// One kernel-owned text run, held with its own copy of the units because the
/// caller's plan does not outlive the pass that built it.
#[derive(Clone)]
pub(crate) struct Run { pub request: TextRequest, pub text: Vec<u16> }

/// The end of a paint owed to a window once the runs before it have finished.
#[derive(Clone, Copy)]
pub(crate) struct Owed { pub hwnd: u64, pub dc: u64, pub finish: fn(u64, u64) }

/// A queued unit of one thread's ordered text work.
pub(crate) enum Item { Run(Run), Cells(Font), End(Owed) }

/// What the caller performs next; `Idle` means the thread owes nothing.
pub(crate) enum Next { Idle, Launch(Run), Cells(Font), End(Owed) }

/// Ordered kernel-owned text work of one thread.
pub(crate) struct Queue { items: VecDeque<Item>, in_flight: bool }

impl Queue {
    /// # C: O(1)
    pub(crate) const fn new() -> Self { Self { items: VecDeque::new(), in_flight: false } }
    /// # C: O(1)
    pub(crate) fn idle(&self) -> bool { !self.in_flight && self.items.is_empty() }
    /// # C: O(1)
    #[cfg(test)]
    pub(crate) fn depth(&self) -> usize { self.items.len() }
    fn push(&mut self, item: Item) -> bool {
        if self.items.len() >= MAX_PENDING || self.items.try_reserve(1).is_err() { return false; }
        self.items.push_back(item); true
    }
    /// Take one run of the current pass. The first run of an idle thread goes
    /// to the backend at once; the rest wait behind it. # C: O(1) amortized
    pub(crate) fn submit(&mut self, run: Run) -> Next {
        if self.idle() { self.in_flight = true; return Next::Launch(run); }
        let _ = self.push(Item::Run(run));
        Next::Idle
    }

    /// Take one measurement of the menu face, ahead of the runs of the pass
    /// that asked for it. It rides the same queue because it enters the same
    /// backend by the same one-at-a-time redirect. # C: O(1) amortized
    pub(crate) fn submit_cells(&mut self, font: Font) -> Next {
        if self.idle() { self.in_flight = true; return Next::Cells(font); }
        let _ = self.push(Item::Cells(font));
        Next::Idle
    }
    /// Take the end of a paint. `Some` is an end the caller performs now: the
    /// pass issued no run that has still to rasterize, or the queue cannot
    /// hold the end and the fills reach the screen without their text rather
    /// than a paint that never ends. An end never displaces a run already in
    /// the backend. # C: O(1) amortized
    pub(crate) fn defer_end(&mut self, owed: Owed) -> Option<Owed> {
        if self.idle() { return Some(owed); }
        // Ends are bounded by paint nesting, not by the run cap: a plan whose
        // text overflowed the queue still has its present held.
        if self.items.try_reserve(1).is_ok() { self.items.push_back(Item::End(owed)); return None; }
        Some(owed)
    }
    /// The item at the head finished: a completed run, a run whose redirect
    /// never installed, or a performed end. # C: O(1)
    pub(crate) fn advance(&mut self) -> Next {
        self.in_flight = false;
        match self.items.pop_front() {
            Some(Item::Run(run)) => { self.in_flight = true; Next::Launch(run) }
            Some(Item::Cells(font)) => { self.in_flight = true; Next::Cells(font) }
            Some(Item::End(owed)) => Next::End(owed),
            None => Next::Idle,
        }
    }
    /// Thread teardown drops queued work and reports the ends still owed, so
    /// their paint resources are released exactly once. # C: O(N_items)
    pub(crate) fn cancel(&mut self) -> Vec<Owed> {
        self.in_flight = false;
        let mut owed = Vec::new();
        while let Some(item) = self.items.pop_front() {
            if let Item::End(end) = item { if owed.try_reserve(1).is_ok() { owed.push(end); } }
        }
        owed
    }
}

/// Drive one thread's queue until it owes nothing that can be done now.
/// `launch` reports whether the redirect into the backend was installed: a
/// run that never leaves does not hold the ends behind it. `next` re-reads
/// the queue under its owner's lock after every step. # C: O(N_items)
pub(crate) fn drive(first: Next, mut launch: impl FnMut(Run) -> bool, mut cells: impl FnMut(Font) -> bool,
    mut end: impl FnMut(Owed), mut next: impl FnMut() -> Next) {
    let mut step = first;
    loop {
        match step {
            Next::Idle => return,
            Next::Launch(run) => { if launch(run) { return; } }
            Next::Cells(font) => { if cells(font) { return; } }
            Next::End(owed) => end(owed),
        }
        step = next();
    }
}

#[cfg(test)]
#[path = "tests/order.rs"]
mod tests;
