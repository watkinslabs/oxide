//! Circular loader-list topology shared by process construction and mutation.

use alloc::vec;
use alloc::vec::Vec;

pub const LIST_COUNT: usize = 3;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Link { pub next: usize, pub prev: usize }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { Capacity, Active, Inactive, Invalid }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoaderList {
    capacity: usize,
    active: Vec<bool>,
    links: Vec<[Link; LIST_COUNT]>,
}

impl LoaderList {
    /// Create a process-local list with `capacity` stable entry slots.
    /// # C: O(capacity)
    pub fn new(capacity: usize) -> Self {
        let sentinel = capacity;
        let empty = [Link { next: sentinel, prev: sentinel }; LIST_COUNT];
        Self { capacity, active: vec![false; capacity], links: vec![empty; capacity] }
    }

    /// Sentinel index used as the list head for each ordering.
    /// # C: O(1)
    pub fn sentinel(&self) -> usize { self.capacity }

    /// Add one previously unused stable slot at every list tail.
    /// # C: O(LIST_COUNT)
    pub fn insert_tail(&mut self, slot: usize) -> Result<(), Error> {
        if slot >= self.capacity { return Err(Error::Capacity); }
        if self.active[slot] { return Err(Error::Active); }
        let sentinel = self.sentinel();
        for list in 0..LIST_COUNT {
            let mut last = sentinel;
            for candidate in 0..self.capacity {
                if self.active[candidate] && self.links[candidate][list].next == sentinel {
                    last = candidate;
                    break;
                }
            }
            let next = if last == sentinel { sentinel } else { self.links[last][list].next };
            self.links[slot][list] = Link { next, prev: last };
            if last != sentinel { self.links[last][list].next = slot; }
            if next != sentinel { self.links[next][list].prev = slot; }
        }
        self.active[slot] = true;
        Ok(())
    }

    /// Remove a slot while preserving circularity of every ordering.
    /// # C: O(capacity * LIST_COUNT)
    pub fn remove(&mut self, slot: usize) -> Result<(), Error> {
        if slot >= self.capacity { return Err(Error::Capacity); }
        if !self.active[slot] { return Err(Error::Inactive); }
        let sentinel = self.sentinel();
        for list in 0..LIST_COUNT {
            let link = self.links[slot][list];
            if link.next == slot || link.prev == slot { return Err(Error::Invalid); }
            if link.prev != sentinel { self.links[link.prev][list].next = link.next; }
            if link.next != sentinel { self.links[link.next][list].prev = link.prev; }
        }
        self.active[slot] = false;
        self.links[slot] = [Link { next: sentinel, prev: sentinel }; LIST_COUNT];
        Ok(())
    }

    /// Return whether a stable slot is currently published.
    /// # C: O(1)
    pub fn contains(&self, slot: usize) -> bool { slot < self.capacity && self.active[slot] }

    /// Return the link for one published slot and ordering.
    /// # C: O(1)
    pub fn link(&self, slot: usize, list: usize) -> Option<Link> {
        if slot >= self.capacity || list >= LIST_COUNT || !self.active[slot] { return None; }
        Some(self.links[slot][list])
    }

    /// Return the first and last stable slots for one ordering.
    /// # C: O(1)
    pub fn head(&self, list: usize) -> Option<Link> {
        if list >= LIST_COUNT { return None; }
        let sentinel = self.sentinel();
        let mut first = sentinel;
        let mut last = sentinel;
        for slot in 0..self.capacity {
            if self.active[slot] && self.links[slot][list].prev == sentinel { first = slot; }
            if self.active[slot] && self.links[slot][list].next == sentinel { last = slot; }
        }
        Some(Link { next: first, prev: last })
    }

    /// Check all forward/backward links and active-slot cardinality.
    /// # C: O(capacity² * LIST_COUNT)
    pub fn validate(&self) -> bool {
        let sentinel = self.sentinel();
        for list in 0..LIST_COUNT {
            let Some(head) = self.head(list) else { return false; };
            let mut seen = vec![false; self.capacity];
            let mut current = head.next;
            while current != sentinel {
                if current >= self.capacity || !self.active[current] || seen[current] { return false; }
                seen[current] = true;
                let link = self.links[current][list];
                if link.next != sentinel && (link.next >= self.capacity || self.links[link.next][list].prev != current) { return false; }
                if link.prev != sentinel && (link.prev >= self.capacity || self.links[link.prev][list].next != current) { return false; }
                current = link.next;
            }
            if seen.iter().copied().filter(|v| *v).count() != self.active.iter().copied().filter(|v| *v).count() { return false; }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insertion_and_removal_preserve_all_three_circular_orders() {
        let mut lists = LoaderList::new(8);
        for slot in [2, 0, 5, 1] { lists.insert_tail(slot).unwrap(); assert!(lists.validate()); }
        assert_eq!(lists.head(0).unwrap().next, 2);
        assert_eq!(lists.head(0).unwrap().prev, 1);
        lists.remove(0).unwrap();
        assert!(!lists.contains(0));
        assert!(lists.validate());
        assert_eq!(lists.link(2, 0).unwrap().next, 5);
        assert_eq!(lists.link(5, 0).unwrap().prev, 2);
    }

    #[test]
    fn invalid_slot_lifecycle_is_rejected_without_mutation() {
        let mut lists = LoaderList::new(2);
        assert_eq!(lists.insert_tail(2), Err(Error::Capacity));
        lists.insert_tail(0).unwrap();
        assert_eq!(lists.insert_tail(0), Err(Error::Active));
        assert_eq!(lists.remove(1), Err(Error::Inactive));
        assert!(lists.validate());
    }
}
