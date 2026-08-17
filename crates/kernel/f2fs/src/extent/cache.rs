//! Both caches a mount keeps, and everything a caller does to them.
//!
//! One mechanism, two instances. The read cache and the age cache differ in
//! what an entry MEANS and in what makes two entries one, and in nothing else:
//! the tree, the mount-wide order of last use, the invalidate-split-merge
//! algorithm and the reclaim pass are shared, so a fix to any of them is a fix
//! to both. Two separate implementations of one algorithm are two answers that
//! can disagree, and the one that disagrees is the one nobody is testing.
//!
//! Nothing here reads or writes a medium, and nothing here knows what an inode
//! is. A caller states the facts that gate caching and supplies the runs; this
//! decides what is remembered and what is answered. That is what makes the
//! whole mechanism checkable without a volume behind it.

use alloc::collections::BTreeSet;
use core::mem::size_of;

use super::age;
use super::info::{Gate, Hit, Info, Kind, Lookup};
use super::limits::*;
use super::tree::{Node, Per, Tree};
use super::update::{self, Outcome};

/// The two caches, their shared reclaim order, and the knobs over them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Caches {
    per: [Per; Kind::ALL.len()],
    /// Inodes declared not worth read-caching.
    no_extent: BTreeSet<u32>,
    read_enabled: bool,
    age_enabled: bool,
    max_read_extent_count: u32,
    last_age_weight: u32,
    hot_data_age_threshold: u32,
    warm_data_age_threshold: u32,
}

impl Caches {
    /// The caches a mount starts with, per what it was mounted asking for.
    /// # C: O(1)
    pub fn new(read_enabled: bool, age_enabled: bool) -> Caches {
        Caches {
            per: [Per::new(), Per::new()],
            no_extent: BTreeSet::new(),
            read_enabled, age_enabled,
            max_read_extent_count: DEF_MAX_READ_EXTENT_COUNT,
            last_age_weight: LAST_AGE_WEIGHT,
            hot_data_age_threshold: DEF_HOT_DATA_AGE_THRESHOLD,
            warm_data_age_threshold: DEF_WARM_DATA_AGE_THRESHOLD,
        }
    }

    /// Whether an inode of this shape may have a tree of this kind at all,
    /// which is decided once and does not change while it is open. # C: O(1)
    pub fn init_may_tree(&self, kind: Kind, g: Gate) -> bool {
        match kind {
            Kind::Read => self.read_enabled && g.is_reg,
            Kind::BlockAge => self.age_enabled && (g.is_reg || g.is_dir),
        }
    }

    /// Whether an inode of this shape may be cached RIGHT NOW.
    ///
    /// Beyond the fixed gate: a file already given up on is not read-cached; a
    /// compressed file has no file-offset-to-block map to cache unless the
    /// volume can never be written; and a file marked cold has an age that
    /// says nothing, because it was placed by its name rather than by its use.
    /// # C: O(log inodes)
    pub fn may_tree(&self, kind: Kind, ino: u32, g: Gate) -> bool {
        if !self.init_may_tree(kind, g) { return false; }
        match kind {
            Kind::Read => {
                if self.no_extent.contains(&ino) { return false; }
                !(g.compressed && !g.readonly_volume)
            }
            Kind::BlockAge => !g.compressed && !g.cold,
        }
    }

    /// Start a read tree for an inode, seeded with the one run the inode
    /// itself stores.
    ///
    /// Returns whether the caller must CLEAR that stored run: an inode that
    /// may not be cached must not carry a run either, because the run is what
    /// a later mount would seed from.
    /// # C: O(log inodes)
    pub fn init_read_tree(&mut self, ino: u32, g: Gate, i_ext: Option<Info>) -> bool {
        if !self.may_tree(Kind::Read, ino, g) {
            self.no_extent.insert(ino);
            return i_ext.is_some_and(|e| e.len != 0);
        }
        let per = &mut self.per[Kind::Read.index()];
        per.grab(ino);
        let seeded = per.count(ino) != 0;
        if let Some(ei) = i_ext {
            if !seeded && ei.len != 0 {
                per.attach(ino, ei);
                per.note_largest(ino, &ei, Kind::Read);
            }
        }
        false
    }

    /// Start an age tree for an inode. Nothing seeds it: an age is not stored
    /// with the inode, so a fresh mount starts every file ageless.
    /// # C: O(log inodes)
    pub fn init_age_tree(&mut self, ino: u32, g: Gate) {
        if !self.init_may_tree(Kind::BlockAge, g) { return; }
        self.per[Kind::BlockAge.index()].grab(ino);
    }

    /// Both trees for one inode, as instantiating it does. # C: O(log inodes)
    pub fn init_trees(&mut self, ino: u32, g: Gate, i_ext: Option<Info>) -> bool {
        let clear = self.init_read_tree(ino, g, i_ext);
        self.init_age_tree(ino, g);
        clear
    }

    /// The run answering file block `fofs`, and which structure gave it.
    ///
    /// The longest remembered run is tried first and costs nothing: it is one
    /// comparison against a value the inode carries, and on a file written
    /// once and read many times it answers everything.
    /// # C: O(log runs)
    pub fn lookup(&mut self, kind: Kind, ino: u32, fofs: u32) -> Lookup {
        if !self.per[kind.index()].trees.contains_key(&ino) { return Lookup::NoTree; }
        if kind == Kind::Read {
            let largest = self.per[kind.index()].largest(ino);
            if largest.covers(fofs) { return Lookup::Found(largest, Hit::Largest); }
        }
        let found = self.per[kind.index()].trees[&ino].lookup(fofs);
        let Some((k, how)) = found else { return Lookup::Miss };
        let ei = self.per[kind.index()].trees[&ino].nodes[&k].ei;
        self.per[kind.index()].touch(ino, k);
        Lookup::Found(ei, how)
    }

    /// The read cache's answer for one file block. # C: O(log runs)
    pub fn lookup_block(&mut self, ino: u32, fofs: u32) -> Lookup {
        self.lookup(Kind::Read, ino, fofs)
    }

    /// Take a change to a range of one file into one of the caches.
    ///
    /// The give-up decision is applied here rather than returned: a caller
    /// that had to remember to act on it is a caller that will forget, and the
    /// inode would go on being cached under a rule that had already fired.
    /// # C: O(runs overlapping the range)
    pub fn update_range(&mut self, kind: Kind, ino: u32, ei: Info) -> Outcome {
        let given_up = self.no_extent.contains(&ino);
        let max = self.max_read_extent_count;
        let out = update::update_range(&mut self.per[kind.index()], ino, ei, kind, given_up, max);
        if out.gave_up {
            self.no_extent.insert(ino);
            self.per[Kind::Read.index()].free_nodes(ino, usize::MAX);
        }
        out
    }

    /// Whether an inode has been declared not worth read-caching. # C: O(log inodes)
    pub fn no_extent(&self, ino: u32) -> bool { self.no_extent.contains(&ino) }

    /// Give up on an inode's caches without giving up on the inode.
    ///
    /// What a truncate to nothing, or a write path that cannot describe what
    /// it did, asks for: everything remembered about this file's layout is
    /// wrong and none of it may answer again.
    /// # C: O(runs)
    pub fn drop_trees(&mut self, ino: u32) {
        if self.per[Kind::Read.index()].trees.contains_key(&ino) {
            self.no_extent.insert(ino);
            self.per[Kind::Read.index()].clear_largest(ino);
            self.per[Kind::Read.index()].free_nodes(ino, usize::MAX);
        }
        self.per[Kind::BlockAge.index()].free_nodes(ino, usize::MAX);
    }

    /// Let go of an inode.
    ///
    /// A tree whose inode still has a name is PARKED rather than freed: the
    /// inode will very likely be opened again, and rebuilding its runs costs a
    /// walk of the node tree for each one. A tree whose last name is gone is
    /// freed outright, because nothing can ask for it.
    /// # C: O(runs)
    pub fn destroy(&mut self, ino: u32, nlink: u32) {
        for kind in Kind::ALL {
            let per = &mut self.per[kind.index()];
            if !per.trees.contains_key(&ino) { continue; }
            if nlink > 0 && per.count(ino) != 0 { per.make_zombie(ino); } else { per.remove_tree(ino); }
        }
        if nlink == 0 { self.no_extent.remove(&ino); }
    }

    /// Free up to `nr` cached runs, parked trees first. # C: O(nr log runs)
    pub fn shrink(&mut self, kind: Kind, nr: usize) -> usize {
        let enabled = match kind { Kind::Read => self.read_enabled, Kind::BlockAge => self.age_enabled };
        if !enabled { return 0; }
        self.per[kind.index()].shrink(nr)
    }

    /// One shrink pass of the size the mount asks for. # C: O(nr log runs)
    pub fn shrink_default(&mut self, kind: Kind) -> usize {
        let nr = match kind {
            Kind::Read => READ_EXTENT_CACHE_SHRINK_NUMBER,
            Kind::BlockAge => AGE_EXTENT_CACHE_SHRINK_NUMBER,
        };
        self.shrink(kind, nr)
    }

    /// The longest run an inode's read tree has held. # C: O(log inodes)
    pub fn largest(&self, ino: u32) -> Option<Info> {
        let ei = self.per[Kind::Read.index()].largest(ino);
        if ei.len == 0 { None } else { Some(ei) }
    }

    /// Trees held, parked ones included. # C: O(1)
    pub fn tree_count(&self, kind: Kind) -> u64 { self.per[kind.index()].tree_count() }

    /// Trees whose inode is gone. # C: O(1)
    pub fn zombie_count(&self, kind: Kind) -> u64 { self.per[kind.index()].zombie_count() }

    /// Runs held across every inode. # C: O(1)
    pub fn node_count(&self, kind: Kind) -> u64 { self.per[kind.index()].node_count() }

    /// What one cache is holding, in bytes.
    ///
    /// Measured from the structures that exist HERE rather than from the
    /// shapes another implementation would hold: the figure is what this mount
    /// can be asked to give back under memory pressure, and a number computed
    /// from anything else would not be that.
    /// # C: O(1)
    pub fn mem_bytes(&self, kind: Kind) -> u64 {
        let per = &self.per[kind.index()];
        per.tree_count() * size_of::<Tree>() as u64
            + per.node_count() * (size_of::<Node>() + size_of::<u32>()) as u64
    }

    /// The age a block should be recorded with, and the allocation count it is
    /// measured against.
    ///
    /// Returns the lookup as well, because consulting the age tree is itself a
    /// cache lookup and the mount counts it as one — a figure that left these
    /// out would report a hit ratio over only the reads.
    /// # C: O(log runs)
    pub fn new_block_age(&mut self, ino: u32, fofs: u32, newly_allocated: bool,
                         cur_blocks: u64, i_size: u64, block_bits: u32)
        -> (Option<(u64, u64)>, Lookup) {
        if age::is_unaged_tail(i_size, fofs, block_bits, newly_allocated) {
            return (None, Lookup::NoTree);
        }
        let found = self.lookup(Kind::BlockAge, ino, fofs);
        if let Some((tei, _)) = found.found() {
            let cur_age = age::interval(cur_blocks, tei.last_blocks);
            let aged = if tei.age != 0 {
                age::calculate_block_age(cur_age, tei.age, self.last_age_weight)
            } else {
                cur_age
            };
            return (Some((aged, cur_blocks)), found);
        }
        // Nothing recorded: either the block is being written for the first
        // time, or its age was reclaimed. Both start the count again from now,
        // which is the honest answer — an age nobody measured is not old.
        (Some((0, cur_blocks)), found)
    }

    /// How a block's age classifies it, which is what picks the log it is
    /// written to. # C: O(1)
    pub fn temperature(&self, age: u64) -> Temperature {
        if age < u64::from(self.hot_data_age_threshold) { Temperature::Hot }
        else if age < u64::from(self.warm_data_age_threshold) { Temperature::Warm }
        else { Temperature::Cold }
    }

    /// # C: O(1)
    pub fn max_read_extent_count(&self) -> u32 { self.max_read_extent_count }
    /// # C: O(1)
    pub fn set_max_read_extent_count(&mut self, v: u32) { self.max_read_extent_count = v; }
    /// # C: O(1)
    pub fn last_age_weight(&self) -> u32 { self.last_age_weight }
    /// # C: O(1)
    pub fn set_last_age_weight(&mut self, v: u32) { self.last_age_weight = v; }
    /// # C: O(1)
    pub fn hot_data_age_threshold(&self) -> u32 { self.hot_data_age_threshold }
    /// # C: O(1)
    pub fn set_hot_data_age_threshold(&mut self, v: u32) { self.hot_data_age_threshold = v; }
    /// # C: O(1)
    pub fn warm_data_age_threshold(&self) -> u32 { self.warm_data_age_threshold }
    /// # C: O(1)
    pub fn set_warm_data_age_threshold(&mut self, v: u32) { self.warm_data_age_threshold = v; }
    /// Whether the mount keeps a read extent cache at all. # C: O(1)
    pub fn read_enabled(&self) -> bool { self.read_enabled }
    /// Whether the mount keeps a block-age extent cache at all. # C: O(1)
    pub fn age_enabled(&self) -> bool { self.age_enabled }

    /// One cache's state, for a test that needs to look inside. # C: O(1)
    #[cfg(test)]
    pub(crate) fn per(&self, kind: Kind) -> &Per { &self.per[kind.index()] }
}

/// What a block's age makes it, which decides the log it is written to.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Temperature { Hot, Warm, Cold }

#[cfg(test)]
#[path = "../tests/extcache/cache.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/extcache/model.rs"]
mod model;
