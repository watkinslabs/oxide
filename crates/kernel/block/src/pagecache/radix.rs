//! Radix tree keyed by page index (`17§4.1`).
//!
//! 64-way fixed-fanout tree over a `u64` index, the same shape the reference
//! page cache indexes a mapping with: six index bits per level, a root that
//! grows a level at a time as indexes get larger, and nodes that disappear
//! when their last slot empties. Lookup is O(height) with height bounded by
//! 11 for the whole `u64` range and 1-2 for the small per-file indexes a
//! cached file actually uses.
//!
//! Why not an ordered map: a mapping is indexed, not compared. The tree's cost
//! is a function of the index WIDTH rather than of how many pages the file
//! has, so a large sparse file pays what a small dense one does, and an
//! in-order walk is a pointer chase rather than a rebalanced traversal.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// Index bits consumed per level.
const SHIFT: u32 = 6;
/// Slots per node.
const WIDTH: usize = 1 << SHIFT;
/// Index bits a leaf node covers.
const MASK: u64 = WIDTH as u64 - 1;

enum Slot<T> { Empty, Item(T), Child(Box<Node<T>>) }

impl<T> Slot<T> {
    fn is_empty(&self) -> bool { matches!(self, Slot::Empty) }
}

struct Node<T> {
    slots: [Slot<T>; WIDTH],
    /// Occupied slots, so a node can be freed the moment it empties.
    used:  usize,
}

impl<T> Node<T> {
    fn new() -> Box<Self> { Box::new(Self { slots: [const { Slot::Empty }; WIDTH], used: 0 }) }
}

/// Page-index-keyed radix tree.
pub struct RadixTree<T> {
    root:  Option<Box<Node<T>>>,
    /// Index shift of the root level. `0` = the root is a leaf.
    shift: u32,
    len:   usize,
}

impl<T> RadixTree<T> {
    /// # C: O(1)
    pub const fn new() -> Self { Self { root: None, shift: 0, len: 0 } }

    /// Entries held. # C: O(1)
    pub fn len(&self) -> usize { self.len }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// Highest index the current height can address.
    fn capacity_shift(&self) -> u32 { self.shift + SHIFT }

    fn covers(&self, index: u64) -> bool {
        let bits = self.capacity_shift();
        bits >= u64::BITS || (index >> bits) == 0
    }

    /// # C: O(height)
    pub fn get(&self, index: u64) -> Option<&T> {
        let mut node = self.root.as_deref()?;
        if !self.covers(index) { return None; }
        let mut shift = self.shift;
        loop {
            let slot = &node.slots[((index >> shift) & MASK) as usize];
            match slot {
                Slot::Item(v) if shift == 0 => return Some(v),
                Slot::Child(c) if shift != 0 => { node = c; shift -= SHIFT; }
                _ => return None,
            }
        }
    }

    /// Insert, returning the value previously at `index`. # C: O(height)
    pub fn insert(&mut self, index: u64, value: T) -> Option<T> {
        while !self.covers(index) { self.grow(); }
        if self.root.is_none() { self.root = Some(Node::new()); }
        // SAFETY-free descent: every level below the root is created on demand.
        let mut node = self.root.as_deref_mut().expect("root just ensured");
        let mut shift = self.shift;
        while shift != 0 {
            let i = ((index >> shift) & MASK) as usize;
            if node.slots[i].is_empty() { node.slots[i] = Slot::Child(Node::new()); node.used += 1; }
            let Slot::Child(next) = &mut node.slots[i] else { return None };
            node = next;
            shift -= SHIFT;
        }
        let i = (index & MASK) as usize;
        let prev = core::mem::replace(&mut node.slots[i], Slot::Item(value));
        match prev {
            Slot::Item(v) => Some(v),
            _ => { node.used += 1; self.len += 1; None }
        }
    }

    /// Add a level, the old root becoming slot 0 of the new one.
    fn grow(&mut self) {
        if self.capacity_shift() >= u64::BITS { return; }
        if let Some(old) = self.root.take() {
            let mut root = Node::new();
            root.slots[0] = Slot::Child(old);
            root.used = 1;
            self.root = Some(root);
        }
        self.shift += SHIFT;
    }

    /// Remove and return the value at `index`. # C: O(height)
    pub fn remove(&mut self, index: u64) -> Option<T> {
        if !self.covers(index) { return None; }
        let shift = self.shift;
        let root = self.root.as_deref_mut()?;
        let (taken, empty) = Self::remove_at(root, index, shift);
        if taken.is_some() { self.len -= 1; }
        if empty { self.root = None; self.shift = 0; }
        taken
    }

    /// Remove from `node`, reporting whether `node` is now empty so the caller
    /// can drop the branch that leads to it.
    fn remove_at(node: &mut Node<T>, index: u64, shift: u32) -> (Option<T>, bool) {
        let i = ((index >> shift) & MASK) as usize;
        if shift == 0 {
            let prev = core::mem::replace(&mut node.slots[i], Slot::Empty);
            return match prev {
                Slot::Item(v) => { node.used -= 1; (Some(v), node.used == 0) }
                other => { node.slots[i] = other; (None, false) }
            };
        }
        let Slot::Child(child) = &mut node.slots[i] else { return (None, false) };
        let (taken, child_empty) = Self::remove_at(child, index, shift - SHIFT);
        if child_empty { node.slots[i] = Slot::Empty; node.used -= 1; }
        (taken, node.used == 0)
    }

    /// Indexes in `[lo, hi)`, ascending. # C: O(entries in range + height)
    pub fn keys_in_range(&self, lo: u64, hi: u64) -> Vec<u64> {
        let mut out = Vec::new();
        if hi <= lo { return out; }
        if let Some(root) = self.root.as_deref() { Self::walk(root, self.shift, 0, lo, hi, &mut |k, _| out.push(k)); }
        out
    }

    /// Every `(index, value)` ascending. # C: O(entries + height)
    pub fn for_each<F: FnMut(u64, &T)>(&self, mut f: F) {
        if let Some(root) = self.root.as_deref() { Self::walk(root, self.shift, 0, 0, u64::MAX, &mut f); }
    }

    /// Ascending in-order walk restricted to `[lo, hi)`, skipping whole
    /// subtrees whose index span falls outside the window.
    fn walk<F: FnMut(u64, &T)>(node: &Node<T>, shift: u32, base: u64, lo: u64, hi: u64, f: &mut F) {
        for (i, slot) in node.slots.iter().enumerate() {
            let key = base | ((i as u64) << shift);
            match slot {
                Slot::Empty => {}
                Slot::Item(v) => { if key >= lo && key < hi { f(key, v); } }
                Slot::Child(c) => {
                    // Slot `i` of a node at `shift` spans the `shift` low bits
                    // under `key`; a subtree entirely outside the window is
                    // never descended.
                    let span_end = key | ((1u64 << shift) - 1);
                    if span_end < lo || key >= hi { continue; }
                    Self::walk(c, shift - SHIFT, key, lo, hi, f);
                }
            }
        }
    }
}

impl<T> Default for RadixTree<T> {
    fn default() -> Self { Self::new() }
}
