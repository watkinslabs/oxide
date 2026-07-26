use alloc::sync::Weak;
use alloc::vec::Vec;

use crate::Task;

/// One armed wall-clock POSIX timer.
///
/// `owner` is the point of this type carrying more than an id: the timer IRQ
/// pops due entries and needs the owning task, and resolving that from
/// `owner_tid` meant `registry::lookup` — an O(N_tasks) scan of `REG` in hard-IRQ
/// context on every expiry (`skizm.md` Step 1b). A `Weak` resolves in O(1) with
/// no lock at all, and being weak it does not keep a dead task alive: an expiry
/// whose owner has exited simply fails to upgrade and is dropped, which is the
/// same outcome the failed lookup produced.
///
/// `owner_tid` stays because it is the queue's identity key (`remove`/`upsert`
/// address entries by `(tid, timer_id)`), and it remains meaningful after the
/// `Weak` has decayed.
#[derive(Clone)]
pub(crate) struct WallEntry {
    pub deadline_ns: u64,
    pub owner_tid: u32,
    pub timer_id: usize,
    pub owner: Weak<Task>,
}

impl WallEntry {
    fn order(&self) -> (u64, u32, usize) { (self.deadline_ns, self.owner_tid, self.timer_id) }
}

pub(crate) struct WallQueue { heap: Vec<WallEntry> }

impl WallQueue {
    pub const fn new() -> Self { Self { heap: Vec::new() } }

    fn earlier(a: &WallEntry, b: &WallEntry) -> bool { a.order() < b.order() }

    fn sift_up(&mut self, mut at: usize) {
        while at != 0 {
            let parent = (at - 1) / 2;
            if !Self::earlier(&self.heap[at], &self.heap[parent]) { break; }
            self.heap.swap(at, parent);
            at = parent;
        }
    }

    fn sift_down(&mut self, mut at: usize) {
        loop {
            let left = at * 2 + 1;
            if left >= self.heap.len() { break; }
            let right = left + 1;
            let child = if right < self.heap.len()
                && Self::earlier(&self.heap[right], &self.heap[left]) { right } else { left };
            if !Self::earlier(&self.heap[child], &self.heap[at]) { break; }
            self.heap.swap(at, child);
            at = child;
        }
    }

    fn remove_at(&mut self, at: usize) -> WallEntry {
        let removed = self.heap.swap_remove(at);
        if at < self.heap.len() {
            self.sift_down(at);
            self.sift_up(at);
        }
        removed
    }

    pub fn remove(&mut self, owner_tid: u32, timer_id: usize) -> Option<WallEntry> {
        let at = self.heap.iter().position(|entry|
            entry.owner_tid == owner_tid && entry.timer_id == timer_id)?;
        Some(self.remove_at(at))
    }

    pub fn upsert(&mut self, entry: Option<WallEntry>, owner_tid: u32, timer_id: usize) {
        self.remove(owner_tid, timer_id);
        if let Some(entry) = entry {
            self.heap.push(entry);
            self.sift_up(self.heap.len() - 1);
        }
    }

    pub fn first(&self) -> Option<&WallEntry> { self.heap.first() }

    pub fn pop_due(&mut self, now_ns: u64) -> Option<WallEntry> {
        (self.first()?.deadline_ns <= now_ns).then(|| self.remove_at(0))
    }

    /// Earliest armed deadline, or `u64::MAX` when the queue is empty.
    /// # C: O(1)
    pub fn earliest_ns(&self) -> u64 {
        self.first().map_or(u64::MAX, |entry| entry.deadline_ns)
    }

    /// Reinsert a popped periodic timer without growing storage in IRQ context.
    pub fn restart(&mut self, entry: WallEntry) {
        debug_assert!(self.heap.len() < self.heap.capacity());
        self.heap.push(entry);
        self.sift_up(self.heap.len() - 1);
    }

    fn rebuild(&mut self) {
        if self.heap.len() < 2 { return; }
        for at in (0..=(self.heap.len() / 2)).rev() { self.sift_down(at); }
    }

    pub fn reproject(&mut self, mut project: impl FnMut(&WallEntry) -> Option<u64>) {
        self.heap.retain_mut(|entry| {
            let Some(deadline_ns) = project(entry) else { return false };
            entry.deadline_ns = deadline_ns;
            true
        });
        self.rebuild();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Entries under test carry a decayed `Weak` — the ordering and identity
    /// logic never touches the owner, and a dead owner is exactly the case the
    /// expiry path must tolerate.
    fn entry(deadline_ns: u64, owner_tid: u32, timer_id: usize) -> WallEntry {
        WallEntry { deadline_ns, owner_tid, timer_id, owner: Weak::new() }
    }

    /// Identity comparison for the tests: `WallEntry` deliberately has no
    /// `PartialEq`, because `Weak` has none and comparing owners is meaningless.
    fn same(a: &WallEntry, b: &WallEntry) -> bool {
        a.deadline_ns == b.deadline_ns && a.owner_tid == b.owner_tid && a.timer_id == b.timer_id
    }

    #[test]
    fn orders_and_restarts_without_growth() {
        let mut queue = WallQueue::new();
        queue.upsert(Some(entry(30, 3, 0)), 3, 0);
        queue.upsert(Some(entry(10, 1, 0)), 1, 0);
        queue.upsert(Some(entry(20, 2, 0)), 2, 0);
        let due = queue.pop_due(10).unwrap();
        let capacity = queue.heap.capacity();
        queue.restart(entry(40, due.owner_tid, due.timer_id));
        assert_eq!(queue.heap.capacity(), capacity, "restart must not reallocate in IRQ context");
        assert!(same(&queue.pop_due(20).unwrap(), &entry(20, 2, 0)));
        assert!(same(&queue.pop_due(30).unwrap(), &entry(30, 3, 0)));
        assert!(same(&queue.pop_due(40).unwrap(), &entry(40, 1, 0)));
    }

    #[test]
    fn upsert_disarms_and_reproject_rebuilds() {
        let mut queue = WallQueue::new();
        queue.upsert(Some(entry(10, 1, 0)), 1, 0);
        queue.upsert(Some(entry(20, 2, 0)), 2, 0);
        queue.upsert(Some(entry(5, 1, 0)), 1, 0);
        queue.upsert(None, 1, 0);
        assert!(same(queue.first().unwrap(), &entry(20, 2, 0)));
        queue.upsert(Some(entry(30, 3, 0)), 3, 0);
        queue.reproject(|old| (old.owner_tid != 2).then_some(40 - old.deadline_ns));
        assert!(same(&queue.pop_due(30).unwrap(), &entry(10, 3, 0)));
    }

    #[test]
    fn earliest_is_max_when_empty() {
        let mut queue = WallQueue::new();
        assert_eq!(queue.earliest_ns(), u64::MAX);
        queue.upsert(Some(entry(7, 1, 0)), 1, 0);
        assert_eq!(queue.earliest_ns(), 7);
    }

    #[test]
    fn a_decayed_owner_still_orders_and_pops() {
        // The owner Weak is irrelevant to queue mechanics; an entry whose task
        // has exited must still be reachable so the expiry path can discard it.
        let mut queue = WallQueue::new();
        queue.upsert(Some(entry(1, 9, 0)), 9, 0);
        let due = queue.pop_due(1).expect("a dead owner must not hide the entry");
        assert_eq!(due.owner_tid, 9);
        assert!(due.owner.upgrade().is_none());
    }
}
