//! Ids the cache is holding, and the two states one can be in.
//!
//! An id leaves the cache in two steps, not one, and the gap between them is
//! the whole reason this is not a set. `alloc` hands an id out and moves it to
//! PREALLOC: it is no longer available to anybody else, but nothing on the
//! medium says so yet. Only when the caller has written the node does the id
//! become genuinely used (`alloc_done`, which forgets it); if the caller fails
//! part-way, the id was never used and goes back (`alloc_failed`). A cache
//! that dropped the id at `alloc` would leak it on every failed create, and
//! one that kept it free would hand the same id to two files.
//!
//! Order is FIFO and that is deliberate. Handing back the id that was freed
//! longest ago leaves the recently-freed ones alone, which keeps a node's
//! table entry stable across the window a reader may still be holding it.
//!
//! `available_nids` is not the free count. It is how many ids the volume can
//! still hand out at all — the table's size less what is already a live node —
//! whereas the free count is how many of those this cache happens to be
//! remembering. A mount that has scanned nothing has a full `available_nids`
//! and an empty cache.

use alloc::collections::BTreeMap;

use crate::uapi::RESERVED_NODE_NUM;

use super::bitmap::Bitmaps;
use super::limits::{ENTRY_BYTES, FREE_NID_SHARE_SHIFT, MAX_FREE_NIDS, MEM_PAGE_SHIFT,
                    RAM_THRESH_BASE, SHRINK_NID_BATCH_SIZE, DEF_RAM_THRESHOLD};

/// What the cache is holding an id for.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NidState {
    /// Nothing is using it and it may be handed out.
    Free,
    /// Handed out, and the caller has not yet said whether it stuck.
    Prealloc,
}

impl NidState {
    /// The counter this state is tallied in. # C: O(1)
    pub fn index(self) -> usize {
        match self { NidState::Free => 0, NidState::Prealloc => 1 }
    }
}

/// How many states there are, and therefore how many tallies.
pub const NID_STATES: usize = 2;

/// One id the cache is holding.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct Entry {
    state: NidState,
    /// Where the id sits in the order free ones are handed out in. Only
    /// meaningful while the state is `Free`.
    seq: u64,
}

/// A table entry that cannot be believed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Corrupt {
    /// A stored entry carries the address that means "allocated but not yet
    /// written". That address never reaches the table: it exists only in
    /// memory between a reservation and the write that fulfils it, so a table
    /// holding one has been damaged.
    ReservedAddr,
    /// The block is too short to hold the entry the walk asked for.
    ShortBlock,
}

/// The ids one mount is remembering.
pub struct FreeNids {
    /// The share of memory the cache may take, in percent.
    pub ram_thresh: u32,
    /// Number of NAT pages to prefetch after a free-NID scan. Linux exposes
    /// this as `ra_nid_pages`; zero disables the advisory prefetch.
    pub ra_nid_pages: u32,
    /// Share of the node table that may be dirty before the caches are worth a
    /// checkpoint on their own, in percent. Live rather than a constant because a
    /// volume with a large table and steady traffic wants it lower and a small
    /// one wants it higher, and only a checkpoint retires the entries.
    pub dirty_nats_ratio: u32,
    entries: BTreeMap<u32, Entry>,
    /// The free ids by the order they became free, oldest first. A second map
    /// rather than a queue because an id can also leave the free set from the
    /// middle — a scan finding it used — and a queue makes that a walk.
    order: BTreeMap<u64, u32>,
    next_seq: u64,
    nid_cnt: [u32; NID_STATES],
    available_nids: u32,
    next_scan_nid: u32,
    pub(super) bits: Bitmaps,
}

impl FreeNids {
    /// A cache that has scanned nothing, for a volume whose cursor and
    /// remaining-id count the checkpoint states. # C: O(1)
    pub fn new(next_scan_nid: u32, available_nids: u32) -> Self {
        Self {
            ram_thresh: DEF_RAM_THRESHOLD,
            ra_nid_pages: 0,
            dirty_nats_ratio: super::limits::DEF_DIRTY_NATS_RATIO,
            entries: BTreeMap::new(),
            order: BTreeMap::new(),
            next_seq: 0,
            nid_cnt: [0; NID_STATES],
            available_nids,
            next_scan_nid,
            bits: Bitmaps::new(),
        }
    }

    /// Remember `nid` as free, and count it against what the volume has left.
    ///
    /// `build` says the caller is folding in what a table read found, in which
    /// case an id the table calls used, or one already remembered, is refused
    /// — the answer is what the caller learns from, so it is returned rather
    /// than dropped. `nat_free` is the caller's view of the table: `None` when
    /// it has no entry to offer.
    /// # C: O(log ids)
    pub fn add(&mut self, nid: u32, max_nid: u32, build: bool, nat_free: Option<bool>) -> bool {
        self.add_inner(nid, max_nid, build, nat_free, true)
    }

    /// The same, without counting it against the volume's remaining ids or
    /// touching the free map.
    ///
    /// The two callers that want this are re-reading what is already recorded
    /// — the journal, and the free map itself — so counting there would count
    /// the same id twice.
    /// # C: O(log ids)
    pub fn add_no_update(&mut self, nid: u32, max_nid: u32, build: bool,
                         nat_free: Option<bool>) -> bool {
        self.add_inner(nid, max_nid, build, nat_free, false)
    }

    /// # C: O(log ids)
    fn add_inner(&mut self, nid: u32, max_nid: u32, build: bool, nat_free: Option<bool>,
                 update: bool) -> bool {
        // The reserved ids at the bottom of the table name the node and meta
        // inodes and the root, and no id at or past the table's end names
        // anything at all.
        if nid < RESERVED_NODE_NUM || nid >= max_nid { return false; }
        let mut inserted = false;
        let recognised = if build {
            match (nat_free, self.entries.get(&nid)) {
                // The table says something lives here; the read that produced
                // that is fresher than anything this cache believes.
                (Some(false), _) => false,
                // Already held. Free means the caller's answer is still yes,
                // handed out means no — either way nothing changes.
                (_, Some(e)) => e.state == NidState::Free,
                _ => { inserted = true; true }
            }
        } else {
            if self.entries.contains_key(&nid) { true } else { inserted = true; true }
        };
        if inserted { self.insert_free(nid); }
        if update {
            self.bits.update(nid, recognised, build);
            if !build { self.available_nids = self.available_nids.saturating_add(1); }
        }
        recognised
    }

    /// Forget `nid`, if the cache is holding it as free.
    ///
    /// An id that has been handed out is left alone: the caller that took it
    /// is still deciding, and dropping the record here would lose the ability
    /// to give it back.
    /// # C: O(log ids)
    pub fn remove(&mut self, nid: u32) {
        if let Some(e) = self.entries.get(&nid).copied() {
            if e.state == NidState::Free { self.detach(nid, e); }
        }
    }

    /// Hand out the id that has been free longest.
    ///
    /// `None` when the volume has no ids left at all, or when the cache is
    /// empty and needs a table walk first — the two are distinguished by
    /// [`Self::available_nids`], because the second is temporary and the first
    /// is not.
    /// # C: O(log ids)
    pub fn alloc(&mut self) -> Option<u32> {
        if self.available_nids == 0 { return None; }
        let (&seq, &nid) = self.order.iter().next()?;
        self.order.remove(&seq);
        let e = self.entries.get_mut(&nid)?;
        e.state = NidState::Prealloc;
        self.nid_cnt[NidState::Free.index()] -= 1;
        self.nid_cnt[NidState::Prealloc.index()] += 1;
        self.available_nids -= 1;
        self.bits.update(nid, false, false);
        Some(nid)
    }

    /// The id handed out is now a live node: forget it. # C: O(log ids)
    pub fn alloc_done(&mut self, nid: u32) {
        if let Some(e) = self.entries.get(&nid).copied() {
            if e.state == NidState::Prealloc { self.detach(nid, e); }
        }
    }

    /// The id handed out was not used after all.
    ///
    /// It goes back to the TAIL of the free order rather than the head: an id
    /// that has just been in a caller's hands is the one most likely to be
    /// referred to by something that has not noticed the failure, so it is the
    /// last that should be handed out again. When the cache is already over
    /// its memory budget the id is dropped instead — the volume's count of
    /// remaining ids still comes back, so nothing is lost but the memory of
    /// where it was.
    /// # C: O(log ids)
    pub fn alloc_failed(&mut self, nid: u32, avail_ram_pages: u64) {
        if nid == 0 { return; }
        let Some(e) = self.entries.get(&nid).copied() else { return };
        if e.state != NidState::Prealloc { return; }
        if self.available_free_memory(avail_ram_pages) {
            let seq = self.next_seq;
            self.next_seq += 1;
            self.entries.insert(nid, Entry { state: NidState::Free, seq });
            self.order.insert(seq, nid);
            self.nid_cnt[NidState::Prealloc.index()] -= 1;
            self.nid_cnt[NidState::Free.index()] += 1;
        } else {
            self.entries.remove(&nid);
            self.nid_cnt[NidState::Prealloc.index()] -= 1;
        }
        self.available_nids = self.available_nids.saturating_add(1);
        self.bits.update(nid, true, false);
    }

    /// Drop up to `nr` free ids, oldest first, but never below the ceiling the
    /// cache is allowed to keep without shrinking. Returns how many went.
    ///
    /// Ids that have been handed out are never dropped: a caller is holding
    /// each one and will come back to say what happened to it.
    /// # C: O(dropped * log ids)
    pub fn shrink(&mut self, nr: usize) -> usize {
        if self.free_count() <= MAX_FREE_NIDS { return 0; }
        let mut left = nr;
        let mut gone = 0usize;
        while left > 0 && self.free_count() > MAX_FREE_NIDS {
            let mut batch = SHRINK_NID_BATCH_SIZE;
            let before = gone;
            while left > 0 && batch > 0 && self.free_count() > MAX_FREE_NIDS {
                let Some((&seq, &nid)) = self.order.iter().next() else { break };
                let e = Entry { state: NidState::Free, seq };
                self.detach(nid, e);
                left -= 1;
                batch -= 1;
                gone += 1;
            }
            if gone == before { break; }
        }
        gone
    }

    /// Whether the cache has room to remember more.
    ///
    /// The budget is a share of a share: the caller states what memory is
    /// available, `ram_thresh` says what portion of it the mount's caches may
    /// take between them, and this cache gets a quarter of that.
    /// # C: O(1)
    pub fn available_free_memory(&self, avail_ram_pages: u64) -> bool {
        let held = u64::from(self.free_count()) * ENTRY_BYTES as u64;
        let pages = held >> MEM_PAGE_SHIFT;
        let budget = (avail_ram_pages * u64::from(self.ram_thresh) / RAM_THRESH_BASE)
            >> FREE_NID_SHARE_SHIFT;
        pages < budget
    }

    /// Whether the cache is thin enough that a table walk is worth its reads.
    /// # C: O(1)
    pub fn need_build(&self) -> bool {
        self.free_count() < crate::uapi::NAT_ENTRY_PER_BLOCK as u32
    }

    /// Ids remembered as free. # C: O(1)
    pub fn free_count(&self) -> u32 { self.nid_cnt[NidState::Free.index()] }

    /// Ids handed out whose caller has not yet reported back. # C: O(1)
    pub fn alloc_count(&self) -> u32 { self.nid_cnt[NidState::Prealloc.index()] }

    /// Ids the volume can still hand out at all. # C: O(1)
    pub fn available_nids(&self) -> u32 { self.available_nids }

    /// Set what the volume has left, for a caller that has recounted its live
    /// nodes. # C: O(1)
    pub fn set_available_nids(&mut self, n: u32) { self.available_nids = n; }

    /// Where the next table walk starts. # C: O(1)
    pub fn next_scan_nid(&self) -> u32 { self.next_scan_nid }

    /// # C: O(1)
    pub fn set_next_scan_nid(&mut self, nid: u32) { self.next_scan_nid = nid; }

    /// Whether the table block at `ofs` has been read. # C: O(log blocks)
    pub fn block_scanned(&self, ofs: u32) -> bool { self.bits.scanned(ofs) }

    /// What the cache is holding, for the mount's memory report. # C: O(1)
    pub fn mem_bytes(&self) -> u64 {
        self.entries.len() as u64 * ENTRY_BYTES as u64 + self.bits.mem_bytes()
    }

    /// What state the cache holds `nid` in, if any. # C: O(log ids)
    pub fn state_of(&self, nid: u32) -> Option<NidState> {
        self.entries.get(&nid).map(|e| e.state)
    }

    /// The free ids, oldest first. # C: O(free ids)
    pub fn free_order(&self) -> alloc::vec::Vec<u32> {
        self.order.values().copied().collect()
    }

    /// # C: O(log ids)
    fn insert_free(&mut self, nid: u32) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.entries.insert(nid, Entry { state: NidState::Free, seq });
        self.order.insert(seq, nid);
        self.nid_cnt[NidState::Free.index()] += 1;
    }

    /// Drop a held id, whichever state it is in. # C: O(log ids)
    fn detach(&mut self, nid: u32, e: Entry) {
        if e.state == NidState::Free { self.order.remove(&e.seq); }
        self.entries.remove(&nid);
        let i = e.state.index();
        self.nid_cnt[i] = self.nid_cnt[i].saturating_sub(1);
    }
}

#[cfg(test)]
#[path = "../tests/freenid/state.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/freenid/equiv.rs"]
mod equiv_tests;
