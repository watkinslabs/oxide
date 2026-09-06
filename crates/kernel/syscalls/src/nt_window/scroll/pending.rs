//! Bounded SetScrollInfo frame-change continuations.

use alloc::vec::Vec;

const MAX_PENDING: usize = 64;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Outcome { Complete(u64), Pending, Failed }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Pending {
    pub(crate) token: u64,
    pub(crate) tid: u64,
    pub(crate) root: u64,
    pub(crate) bar: i32,
    pub(crate) result: i32,
    pub(crate) redraw: bool,
    pub(crate) hidden: bool,
}

impl Pending {
    pub(crate) const fn should_repaint(self) -> bool { self.redraw && !self.hidden }
}

#[derive(Default)]
pub(crate) struct Queue { next: u64, entries: Vec<Pending> }

impl Queue {
    pub(crate) fn admit(&mut self, tid: u64, root: u64, bar: i32, result: i32, redraw: bool, hidden: bool) -> Option<u64> {
        if self.entries.len() >= MAX_PENDING || self.entries.try_reserve(1).is_err() { return None; }
        let token = self.next.wrapping_add(1);
        if token == 0 { return None; }
        self.next = token;
        self.entries.push(Pending { token, tid, root, bar, result, redraw, hidden });
        Some(token)
    }

    pub(crate) fn complete(&mut self, tid: u64, token: u64, outcome: Outcome) -> Option<Pending> {
        if outcome == Outcome::Pending { return None; }
        let index = self.entries.iter().position(|pending| pending.token == token && pending.tid == tid)?;
        let pending = self.entries.remove(index);
        match outcome { Outcome::Complete(_) | Outcome::Failed => Some(pending), Outcome::Pending => None }
    }

    pub(crate) fn cancel_tid(&mut self, tid: u64) { self.entries.retain(|pending| pending.tid != tid); }
    pub(crate) fn cancel_root(&mut self, root: u64) { self.entries.retain(|pending| pending.root != root); }
    pub(crate) fn len(&self) -> usize { self.entries.len() }
}

#[cfg(test)]
#[path = "tests/pending.rs"]
mod tests;
