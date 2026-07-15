use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct WallEntry {
    pub deadline_ns: u64,
    pub owner_tid: u32,
    pub timer_id: usize,
}

impl WallEntry {
    fn order(self) -> (u64, u32, usize) { (self.deadline_ns, self.owner_tid, self.timer_id) }
}

pub(crate) struct WallQueue { heap: Vec<WallEntry> }

impl WallQueue {
    pub const fn new() -> Self { Self { heap: Vec::new() } }

    fn earlier(a: WallEntry, b: WallEntry) -> bool { a.order() < b.order() }

    fn sift_up(&mut self, mut at: usize) {
        while at != 0 {
            let parent = (at - 1) / 2;
            if !Self::earlier(self.heap[at], self.heap[parent]) { break; }
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
                && Self::earlier(self.heap[right], self.heap[left]) { right } else { left };
            if !Self::earlier(self.heap[child], self.heap[at]) { break; }
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

    pub fn first(&self) -> Option<WallEntry> { self.heap.first().copied() }

    pub fn pop_due(&mut self, now_ns: u64) -> Option<WallEntry> {
        (self.first()?.deadline_ns <= now_ns).then(|| self.remove_at(0))
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

    pub fn reproject(&mut self, mut project: impl FnMut(WallEntry) -> Option<u64>) {
        self.heap.retain_mut(|entry| {
            let Some(deadline_ns) = project(*entry) else { return false };
            entry.deadline_ns = deadline_ns;
            true
        });
        self.rebuild();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(deadline_ns: u64, owner_tid: u32, timer_id: usize) -> WallEntry {
        WallEntry { deadline_ns, owner_tid, timer_id }
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
        assert_eq!(queue.heap.capacity(), capacity);
        assert_eq!(queue.pop_due(20), Some(entry(20, 2, 0)));
        assert_eq!(queue.pop_due(30), Some(entry(30, 3, 0)));
        assert_eq!(queue.pop_due(40), Some(entry(40, 1, 0)));
    }

    #[test]
    fn upsert_disarms_and_reproject_rebuilds() {
        let mut queue = WallQueue::new();
        queue.upsert(Some(entry(10, 1, 0)), 1, 0);
        queue.upsert(Some(entry(20, 2, 0)), 2, 0);
        queue.upsert(Some(entry(5, 1, 0)), 1, 0);
        queue.upsert(None, 1, 0);
        assert_eq!(queue.first(), Some(entry(20, 2, 0)));
        queue.upsert(Some(entry(30, 3, 0)), 3, 0);
        queue.reproject(|old| (old.owner_tid != 2).then_some(40 - old.deadline_ns));
        assert_eq!(queue.pop_due(30), Some(entry(10, 3, 0)));
    }
}
