//! Linux `struct ipc_ids` — the per-namespace identifier space shared by every
//! SysV object class (`ipc/util.c`).
//!
//! Reproduces the real encoding rather than a monotonic counter: slots are
//! allocated cyclically, `seq` advances whenever allocation wraps back to a
//! low index, and the identifier handed to userspace is
//! `(seq << IPCMNI_SHIFT) | idx`. `lookup_checked` therefore rejects a stale
//! id whose slot has since been recycled (`ipc_checkid` → `EINVAL`), and the
//! `*_STAT` commands can address objects by raw index the way `ipcs(1)` does.

use alloc::sync::Arc;
use alloc::vec::Vec;
use namespace_identity::NamespaceId;

use super::limits::{IPCMNI, IPCMNI_IDX_MASK, IPCMNI_SHIFT};

/// Sequence numbers wrap at the width left over above the index bits.
const SEQ_MAX: u16 = ((1u32 << (31 - IPCMNI_SHIFT)) - 1) as u16;
/// Linux `ipc_min_cycle` — the floor on the cyclic allocation window, so ids
/// are not reused immediately after a removal.
const IPC_MIN_CYCLE: usize = 16;

struct Slot<T> {
    obj: Option<Arc<T>>,
}

/// One namespace's identifier space for a single object class.
struct NsIds<T> {
    ns: NamespaceId,
    slots: Vec<Slot<T>>,
    in_use: usize,
    seq: u16,
    last_idx: i64,
    max_idx: i64,
}

/// Every namespace's identifier spaces for one object class. Callers wrap this
/// in the class's own lock; nothing here takes a lock of its own.
pub struct IpcIds<T> {
    spaces: Vec<NsIds<T>>,
}

impl<T> IpcIds<T> {
    /// # C: O(1)
    pub const fn new() -> Self { Self { spaces: Vec::new() } }

    fn space(&mut self, ns: NamespaceId) -> &mut NsIds<T> {
        if let Some(i) = self.spaces.iter().position(|s| s.ns == ns) { return &mut self.spaces[i]; }
        self.spaces.push(NsIds { ns, slots: Vec::new(), in_use: 0, seq: 0, last_idx: -1, max_idx: -1 });
        let last = self.spaces.len() - 1;
        &mut self.spaces[last]
    }

    fn space_ref(&self, ns: NamespaceId) -> Option<&NsIds<T>> { self.spaces.iter().find(|s| s.ns == ns) }

    /// Reserve an index for a new object, returning `(idx, seq, id)`. `None`
    /// once `limit` objects already exist in this namespace (Linux `-ENOSPC`).
    /// The caller must follow with [`install`] using the returned index.
    /// # C: O(IPCMNI) worst case, O(1) typical
    pub fn alloc_idx(&mut self, ns: NamespaceId, limit: usize) -> Option<(usize, u16, i32)> {
        let s = self.space(ns);
        let limit = limit.min(IPCMNI);
        if s.in_use >= limit { return None; }
        let window = core::cmp::min(core::cmp::max(s.in_use * 3 / 2, IPC_MIN_CYCLE), limit);
        let start = (s.last_idx + 1).max(0) as usize;
        let mut idx = None;
        for probe in 0..window {
            let cand = (start + probe) % window;
            if cand >= s.slots.len() { s.slots.resize_with(cand + 1, || Slot { obj: None }); }
            if s.slots[cand].obj.is_none() { idx = Some(cand); break; }
        }
        // The cyclic window is a reuse-delay heuristic, not a capacity bound:
        // Linux widens it as `in_use` grows, so a full window simply means
        // scan the whole space before declaring ENOSPC.
        let idx = match idx {
            Some(i) => i,
            None => {
                let mut found = None;
                for cand in 0..limit {
                    if cand >= s.slots.len() { s.slots.resize_with(cand + 1, || Slot { obj: None }); }
                    if s.slots[cand].obj.is_none() { found = Some(cand); break; }
                }
                found?
            }
        };
        if (idx as i64) <= s.last_idx {
            s.seq = if s.seq >= SEQ_MAX { 0 } else { s.seq + 1 };
        }
        s.last_idx = idx as i64;
        let id = ((s.seq as i32) << IPCMNI_SHIFT) | (idx as i32);
        Some((idx, s.seq, id))
    }

    /// Publish the object into the index reserved by [`alloc_idx`]. # C: O(1)
    pub fn install(&mut self, ns: NamespaceId, idx: usize, obj: Arc<T>) {
        let s = self.space(ns);
        if idx >= s.slots.len() { s.slots.resize_with(idx + 1, || Slot { obj: None }); }
        s.slots[idx].obj = Some(obj);
        s.in_use += 1;
        if (idx as i64) > s.max_idx { s.max_idx = idx as i64; }
    }

    /// Linux `ipc_obtain_object_check`: index the id, then require the id's
    /// sequence half to match the slot's. # C: O(1)
    pub fn lookup_checked(&self, ns: NamespaceId, id: i32, seq_of: impl Fn(&T) -> u16) -> Option<Arc<T>> {
        if id < 0 { return None; }
        let s = self.space_ref(ns)?;
        let idx = (id & IPCMNI_IDX_MASK) as usize;
        let obj = s.slots.get(idx)?.obj.as_ref()?;
        if seq_of(obj) != ((id >> IPCMNI_SHIFT) as u16) { return None; }
        Some(obj.clone())
    }

    /// Linux `ipc_obtain_object_idr`: `*_STAT` addresses by raw index and does
    /// NOT check the sequence half. # C: O(1)
    pub fn lookup_idx(&self, ns: NamespaceId, idx: i32) -> Option<Arc<T>> {
        if idx < 0 { return None; }
        let s = self.space_ref(ns)?;
        s.slots.get(idx as usize)?.obj.clone()
    }

    /// Linux `ipc_findkey`. `IPC_PRIVATE` never matches. # C: O(max_idx)
    pub fn lookup_key(&self, ns: NamespaceId, key: i32, key_of: impl Fn(&T) -> i32) -> Option<Arc<T>> {
        if key == super::limits::IPC_PRIVATE { return None; }
        let s = self.space_ref(ns)?;
        s.slots.iter().filter_map(|sl| sl.obj.as_ref()).find(|o| key_of(o) == key).cloned()
    }

    /// Linux `ipc_rmid`. # C: O(max_idx) when the top index is freed
    pub fn remove(&mut self, ns: NamespaceId, id: i32) -> Option<Arc<T>> {
        let s = self.space(ns);
        let idx = (id & IPCMNI_IDX_MASK) as usize;
        let obj = s.slots.get_mut(idx)?.obj.take()?;
        s.in_use -= 1;
        if (idx as i64) == s.max_idx {
            let mut i = s.max_idx - 1;
            while i >= 0 && s.slots[i as usize].obj.is_none() { i -= 1; }
            s.max_idx = i;
        }
        Some(obj)
    }

    /// Drop an entire namespace's objects, returning them so the caller can run
    /// the class's wake-everyone teardown outside the registry lock. # C: O(max_idx)
    pub fn drain_namespace(&mut self, ns: NamespaceId) -> Vec<Arc<T>> {
        let mut out = Vec::new();
        if let Some(pos) = self.spaces.iter().position(|s| s.ns == ns) {
            let s = self.spaces.swap_remove(pos);
            for slot in s.slots { if let Some(o) = slot.obj { out.push(o); } }
        }
        out
    }

    /// Linux `ipc_get_maxidx` — highest live index, `-1` when empty. # C: O(1)
    pub fn max_idx(&self, ns: NamespaceId) -> i64 { self.space_ref(ns).map(|s| s.max_idx).unwrap_or(-1) }

    /// Linux `ids->in_use`. # C: O(1)
    pub fn in_use(&self, ns: NamespaceId) -> usize { self.space_ref(ns).map(|s| s.in_use).unwrap_or(0) }

    /// Every live object in the namespace, ascending by index. # C: O(max_idx)
    pub fn all(&self, ns: NamespaceId) -> Vec<Arc<T>> {
        match self.space_ref(ns) {
            None => Vec::new(),
            Some(s) => s.slots.iter().filter_map(|sl| sl.obj.clone()).collect(),
        }
    }
}

#[cfg(test)]
mod tests;
