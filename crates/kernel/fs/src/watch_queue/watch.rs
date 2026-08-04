// The watch list an object carries: which queues are watching it, under which
// watchpoint id, and the add/remove rules.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use super::queue::{self, WatchQueue};
use super::uapi::*;

/// One watchpoint: a queue, the object it watches, and the id the caller chose
/// to recognise it by in the records it receives.
#[derive(Clone)]
pub struct Watch {
    pub queue: Arc<WatchQueue>,
    /// The watched object's identity — a key serial, for a key watch.
    pub id: u64,
    /// The caller's watchpoint id, already shifted into its `info` position.
    pub info_id: u32,
}

/// Every watch on one object (Linux `key->watchers`).
#[derive(Clone, Default)]
pub struct WatchList {
    pub watches: Vec<Watch>,
}

impl WatchList {
    /// # C: O(1)
    pub fn new() -> Self { Self { watches: Vec::new() } }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.watches.is_empty() }

    /// Add a watchpoint.
    ///
    /// One queue may watch one object ONCE: a second watch from the same queue
    /// on the same object is EBUSY, not a silently ignored duplicate that
    /// would deliver every event twice. # C: O(watches)
    pub fn add(&mut self, queue: Arc<WatchQueue>, id: u64, watch_id: i32) -> Result<(), Errno> {
        if self.watches.iter().any(|w| w.id == id && Arc::ptr_eq(&w.queue, &queue)) {
            return Err(Errno::Ebusy);
        }
        let info_id = (watch_id as u32) << WATCH_INFO_ID_SHIFT;
        self.watches.push(Watch { queue, id, info_id });
        self.watches.last().expect("the watch was just pushed").queue.add_watched_key(id as i32);
        Ok(())
    }

    /// Remove the watchpoint this queue holds on `id`, telling the queue the
    /// object is gone.
    ///
    /// Removing a watch that is not there is EBADSLT — a caller that thinks it
    /// is watching something it is not has a bug, and reporting success would
    /// hide it. # C: O(watches)
    pub fn remove(&mut self, queue: &Arc<WatchQueue>, id: u64) -> Result<(), Errno> {
        let idx = self.watches.iter().position(|w| w.id == id && Arc::ptr_eq(&w.queue, queue))
            .ok_or(Errno::Ebadslt)?;
        let w = self.watches.remove(idx);
        w.queue.remove_watched_key(id as i32);
        w.queue.post(&queue::removal_record(w.id, w.info_id));
        Ok(())
    }

    /// Remove every watch, telling each queue the object is gone. This is what
    /// runs when the watched object itself dies. # C: O(watches)
    pub fn remove_all(&mut self) {
        for w in core::mem::take(&mut self.watches) {
            w.queue.remove_watched_key(w.id as i32);
            w.queue.post(&queue::removal_record(w.id, w.info_id));
        }
    }

    /// Remove this queue's watch without posting to it: its pipe is gone.
    /// # C: O(watches)
    pub fn detach_queue(&mut self, queue: &Arc<WatchQueue>, id: u64) {
        if let Some(idx) = self.watches.iter().position(|w| w.id == id && Arc::ptr_eq(&w.queue, queue)) {
            self.watches.remove(idx);
        }
    }

    /// Post a key-change record to every queue watching this object.
    ///
    /// The watchpoint id is stamped per watch, so two watchers of the same key
    /// each recognise the record by the id THEY chose. # C: O(watches)
    pub fn post_key_event(&self, subtype: u32, key_id: i32, aux: u32) {
        for w in &self.watches {
            w.queue.post(&queue::key_notification(subtype, key_id, aux, w.info_id));
        }
    }
}
