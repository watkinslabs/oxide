//! One inode's ordered runs, and the mount-wide list that decides which run
//! is dropped first when memory is short.
//!
//! The runs of one inode are held ORDERED BY FILE OFFSET and never overlap, so
//! the run answering an offset is the last one starting at or before it. That
//! is the whole lookup, and it is why the structure is an ordered map rather
//! than a list: a list would make a lookup cost the file's fragmentation.
//!
//! Reclaim is MOUNT-WIDE, not per inode. A per-inode bound would keep a run
//! for an inode nothing has touched in an hour while dropping one for the file
//! being read right now, so every run of every inode sits in one order of last
//! use. The order is kept as a stamp per run and a map from stamp to run:
//! touching a run is two ordered-map operations, and the least recently used
//! run of the whole mount is the first entry.

use alloc::collections::{BTreeMap, VecDeque};

use super::info::{Hit, Info, Kind};

/// One cached run, and where it sits in the mount-wide order of last use.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Node {
    pub ei: Info,
    /// Position in the mount-wide order; larger is more recently used.
    pub stamp: u64,
}

/// Every run one inode has cached, for one of the two caches.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Tree {
    /// Runs by first file block. Never overlapping, so the map IS the index.
    pub nodes: BTreeMap<u32, Node>,
    /// The run last asked for, checked before the map is walked.
    pub cached: Option<u32>,
    /// The longest run this tree has held, kept even after the run itself is
    /// dropped — it is what the inode stores, and what answers before the tree
    /// is consulted at all. READ cache only.
    pub largest: Info,
    /// Whether `largest` has changed since the owner was last told.
    pub largest_updated: bool,
    /// Whether the inode is gone and the tree is waiting to be reclaimed.
    pub zombie: bool,
}

impl Tree {
    /// The run covering `fofs`, and which structure found it.
    ///
    /// The one-entry front cache is checked first because a sequential read
    /// asks for consecutive offsets of the same run, and answering those from
    /// the map would walk it once per block.
    /// # C: O(log runs)
    pub fn lookup(&self, fofs: u32) -> Option<(u32, Hit)> {
        if let Some(k) = self.cached {
            if self.nodes.get(&k).is_some_and(|n| n.ei.covers(fofs)) { return Some((k, Hit::Cached)); }
        }
        let (&k, n) = self.nodes.range(..=fofs).next_back()?;
        if n.ei.covers(fofs) { Some((k, Hit::Tree)) } else { None }
    }

    /// The run before `fofs`, which a new run may extend. # C: O(log runs)
    pub fn prev_key(&self, fofs: u32) -> Option<u32> {
        self.nodes.range(..fofs).next_back().map(|(&k, _)| k)
    }

    /// The run after `fofs`, which a new run may be extended by. # C: O(log runs)
    pub fn next_key(&self, fofs: u32) -> Option<u32> {
        self.nodes.range(fofs.saturating_add(1)..).next().map(|(&k, _)| k)
    }

    /// Raise the remembered longest run, for the read cache only.
    ///
    /// The age cache has no such shortcut: an age is not a thing one long run
    /// can answer for, because the whole point of the figure is that it
    /// differs along the file.
    /// # C: O(1)
    pub fn try_update_largest(&mut self, ei: &Info, kind: Kind) {
        if kind != Kind::Read || ei.len <= self.largest.len { return; }
        self.largest = *ei;
        self.largest_updated = true;
    }

    /// Forget the remembered longest run when a change overlaps it.
    ///
    /// The run is remembered past its own entry, so a write inside it would
    /// otherwise be answered from a shortcut describing blocks the file no
    /// longer has.
    /// # C: O(1)
    pub fn drop_largest(&mut self, fofs: u32, len: u32) {
        if fofs < self.largest.fofs + self.largest.len && fofs + len > self.largest.fofs {
            self.largest.len = 0;
            self.largest_updated = true;
        }
    }
}

/// Everything one of the two caches holds, across every inode.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Per {
    /// One tree per inode that has any.
    pub trees: BTreeMap<u32, Tree>,
    /// Every run of every inode, by how recently it was used.
    pub lru: BTreeMap<u64, (u32, u32)>,
    /// Inodes whose tree outlived the inode, in the order they died — the
    /// first thing a shrink pass frees, because nothing will ask for them.
    pub zombies: VecDeque<u32>,
    /// Stamps handed out so far, which is what makes the order total.
    clock: u64,
}

impl Per {
    /// # C: O(1)
    pub fn new() -> Per { Per::default() }

    /// Runs held across every inode. # C: O(1)
    pub fn node_count(&self) -> u64 { self.lru.len() as u64 }

    /// Trees held, live and zombie together. # C: O(1)
    pub fn tree_count(&self) -> u64 { self.trees.len() as u64 }

    /// Trees whose inode is gone. # C: O(1)
    pub fn zombie_count(&self) -> u64 { self.zombies.len() as u64 }

    /// Take the tree for `ino`, creating an empty one. A tree that was a
    /// zombie comes back to life, which is what makes reopening an inode
    /// cheap. # C: O(log inodes)
    pub fn grab(&mut self, ino: u32) -> &mut Tree {
        if let Some(t) = self.trees.get(&ino) {
            if t.zombie {
                if let Some(i) = self.zombies.iter().position(|&z| z == ino) { self.zombies.remove(i); }
            }
        }
        let t = self.trees.entry(ino).or_default();
        t.zombie = false;
        t
    }

    /// Add a run to an inode's tree and to the head of the recently-used
    /// order. # C: O(log runs)
    pub fn attach(&mut self, ino: u32, ei: Info) {
        self.clock += 1;
        let stamp = self.clock;
        let Some(t) = self.trees.get_mut(&ino) else { return };
        t.nodes.insert(ei.fofs, Node { ei, stamp });
        // A run just inserted is the run about to be asked for: the write that
        // created it is normally followed by the read that wants it.
        t.cached = Some(ei.fofs);
        self.lru.insert(stamp, (ino, ei.fofs));
    }

    /// Drop a run from both. # C: O(log runs)
    pub fn detach(&mut self, ino: u32, fofs: u32) {
        let Some(t) = self.trees.get_mut(&ino) else { return };
        let Some(n) = t.nodes.remove(&fofs) else { return };
        if t.cached == Some(fofs) { t.cached = None; }
        self.lru.remove(&n.stamp);
    }

    /// Move a run to a new first file block, which a split or a merge does.
    /// # C: O(log runs)
    pub fn rekey(&mut self, ino: u32, from: u32, to: u32) {
        if from == to { return; }
        let Some(t) = self.trees.get_mut(&ino) else { return };
        let Some(n) = t.nodes.remove(&from) else { return };
        if t.cached == Some(from) { t.cached = Some(to); }
        self.lru.insert(n.stamp, (ino, to));
        t.nodes.insert(to, n);
    }

    /// Say a run was just used: it goes to the recent end of the order and
    /// becomes the tree's one-entry front cache. # C: O(log runs)
    pub fn touch(&mut self, ino: u32, fofs: u32) {
        self.clock += 1;
        let stamp = self.clock;
        let Some(t) = self.trees.get_mut(&ino) else { return };
        let Some(n) = t.nodes.get_mut(&fofs) else { return };
        let old = n.stamp;
        n.stamp = stamp;
        t.cached = Some(fofs);
        self.lru.remove(&old);
        self.lru.insert(stamp, (ino, fofs));
    }

    /// One run of one inode's tree. # C: O(log runs)
    pub fn ei(&self, ino: u32, k: u32) -> Option<Info> {
        self.trees.get(&ino)?.nodes.get(&k).map(|n| n.ei)
    }

    /// Replace one run's fields, leaving where it sits alone. # C: O(log runs)
    pub fn set_ei(&mut self, ino: u32, k: u32, ei: Info) {
        if let Some(t) = self.trees.get_mut(&ino) {
            if let Some(n) = t.nodes.get_mut(&k) { n.ei = ei; }
        }
    }

    /// Runs one inode holds. # C: O(log inodes)
    pub fn count(&self, ino: u32) -> usize {
        self.trees.get(&ino).map_or(0, |t| t.nodes.len())
    }

    /// The run after `k` in one inode's tree. # C: O(log runs)
    pub fn next_after(&self, ino: u32, k: u32) -> Option<u32> {
        self.trees.get(&ino)?.next_key(k)
    }

    /// Offer a run as the inode's longest. # C: O(log inodes)
    pub fn note_largest(&mut self, ino: u32, ei: &Info, kind: Kind) {
        if let Some(t) = self.trees.get_mut(&ino) { t.try_update_largest(ei, kind); }
    }

    /// The inode's longest remembered run. # C: O(log inodes)
    pub fn largest(&self, ino: u32) -> Info {
        self.trees.get(&ino).map_or(Info::default(), |t| t.largest)
    }

    /// Forget the longest run and say so. # C: O(log inodes)
    pub fn clear_largest(&mut self, ino: u32) {
        if let Some(t) = self.trees.get_mut(&ino) { t.largest.len = 0; t.largest_updated = true; }
    }

    /// Whether the longest run changed since this was last asked, clearing the
    /// mark. # C: O(log inodes)
    pub fn take_largest_updated(&mut self, ino: u32) -> bool {
        match self.trees.get_mut(&ino) {
            Some(t) if t.largest_updated => { t.largest_updated = false; true }
            _ => false,
        }
    }

    /// Free every run of one inode's tree, leaving the tree itself.
    /// # C: O(runs)
    pub fn free_nodes(&mut self, ino: u32, upto: usize) -> usize {
        let keys: alloc::vec::Vec<u32> = match self.trees.get(&ino) {
            Some(t) => t.nodes.keys().copied().take(upto).collect(),
            None => return 0,
        };
        let n = keys.len();
        for k in keys { self.detach(ino, k); }
        n
    }

    /// Give up on an inode's tree entirely. # C: O(runs)
    pub fn remove_tree(&mut self, ino: u32) {
        self.free_nodes(ino, usize::MAX);
        self.trees.remove(&ino);
        if let Some(i) = self.zombies.iter().position(|&z| z == ino) { self.zombies.remove(i); }
    }

    /// Park an inode's tree for reclaim rather than freeing it now: the inode
    /// may be opened again, and rebuilding the runs costs a walk of the node
    /// tree per run. # C: O(1)
    pub fn make_zombie(&mut self, ino: u32) {
        let Some(t) = self.trees.get_mut(&ino) else { return };
        if t.zombie { return; }
        t.zombie = true;
        self.zombies.push_back(ino);
    }

    /// Free up to `nr` runs, zombies first.
    ///
    /// Zombies before live runs is the whole ordering rule: a zombie's runs
    /// can never be asked for again, so freeing a live run before them would
    /// cost a lookup to save nothing.
    /// # C: O(nr log runs)
    pub fn shrink(&mut self, nr: usize) -> usize {
        let mut done = 0usize;
        while done < nr {
            let Some(&ino) = self.zombies.front() else { break };
            done += self.free_nodes(ino, nr - done);
            if self.trees.get(&ino).is_some_and(|t| !t.nodes.is_empty()) { return done; }
            self.zombies.pop_front();
            self.trees.remove(&ino);
            done += 1;
        }
        while done < nr {
            let Some((&stamp, &(ino, fofs))) = self.lru.iter().next() else { break };
            self.lru.remove(&stamp);
            if let Some(t) = self.trees.get_mut(&ino) {
                t.nodes.remove(&fofs);
                if t.cached == Some(fofs) { t.cached = None; }
            }
            done += 1;
        }
        done
    }
}

#[cfg(test)]
#[path = "../tests/extcache/tree.rs"]
mod tests;
