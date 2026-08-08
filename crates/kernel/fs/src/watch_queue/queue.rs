// The queue itself: the notes a notification pipe holds, the depth rule, and
// the loss accounting that tells a reader it missed something.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use sync::{Spinlock, LockClass};
use syscall::errno::Errno;

use super::filter::Filter;
use super::uapi::*;

/// Lock class for a watch queue. Taken standalone: a poster copies the record
/// in and releases it before waking anybody, and a reader copies records out
/// and releases it before touching user memory. # C: O(1)
pub struct WatchQueueClass;
impl LockClass for WatchQueueClass {
    fn rank() -> u16 { 35 }
    fn name() -> &'static str { "WatchQueue" }
}

/// A queued note and whether a loss happened immediately after it.
struct Note {
    bytes: Vec<u8>,
    /// A record was dropped while this one was the newest. The reader learns
    /// about it only once it has consumed this note, so the loss is reported
    /// in the place in the stream where it happened.
    loss_follows: bool,
}

/// Mutable queue state.
struct State {
    notes: VecDeque<Note>,
    /// Depth in notes. Zero until the caller sets it, and a queue with no
    /// depth accepts nothing — which is a LOSS for every notification, not a
    /// silent discard.
    capacity: usize,
    /// A loss the reader has not been told about yet.
    note_loss: bool,
    filter: Option<Filter>,
}

/// The watch queue behind one notification pipe.
pub struct WatchQueue {
    state: Spinlock<State, WatchQueueClass>,
    /// Key serials this queue currently watches. The queue owns this reverse
    /// membership so closing its pipe can unlink exactly these watches.
    watched_keys: Spinlock<Vec<i32>, WatchQueueClass>,
    /// Wakes whoever is blocked reading the pipe this queue belongs to. Held
    /// as a callback so the queue itself knows nothing about pipes — a queue
    /// driven by the hosted tests simply has none.
    waker: Spinlock<Option<Waker>, WatchQueueClass>,
}

/// The "a record arrived" callback a notification pipe installs.
pub type Waker = alloc::boxed::Box<dyn Fn() + Send + Sync>;

impl Default for WatchQueue { fn default() -> Self { Self::new() } }

impl WatchQueue {
    /// # C: O(1)
    pub fn new() -> Self {
        Self {
            state: Spinlock::new(State {
                notes: VecDeque::new(), capacity: 0, note_loss: false, filter: None,
            }),
            watched_keys: Spinlock::new(Vec::new()),
            waker: Spinlock::new(None),
        }
    }

    /// Record one key watch held by this queue. # C: O(watches)
    pub(crate) fn add_watched_key(&self, serial: i32) {
        let mut keys = self.watched_keys.lock();
        if !keys.contains(&serial) { keys.push(serial); }
    }

    /// Forget one key watch removed through `KEYCTL_WATCH_KEY`. # C: O(watches)
    pub(crate) fn remove_watched_key(&self, serial: i32) {
        let mut keys = self.watched_keys.lock();
        if let Some(idx) = keys.iter().position(|&key| key == serial) { keys.remove(idx); }
    }

    /// Take every key watch for queue teardown. # C: O(watches)
    pub(crate) fn take_watched_keys(&self) -> Vec<i32> {
        core::mem::take(&mut *self.watched_keys.lock())
    }

    /// Is a depth already set? The depth is settable ONCE: resizing a queue
    /// underneath a reader would drop notifications it was never told it lost.
    /// # C: O(1)
    pub fn is_sized(&self) -> bool { self.state.lock().capacity != 0 }

    /// Publish a depth of `pages` whole pages of notes. The caller has already
    /// admitted the request and reserved the memory it charges. # C: O(1)
    pub fn commit_size(&self, pages: usize) -> usize {
        let mut g = self.state.lock();
        g.capacity = pages * WATCH_QUEUE_NOTES_PER_PAGE;
        g.capacity
    }

    /// `IOC_WATCH_QUEUE_SET_SIZE` with no memory reservation behind it — the
    /// depth-only form the hosted tests drive. # C: O(1)
    pub fn set_size(&self, nr_notes: usize) -> Result<usize, Errno> {
        let pages = admit_set_size(nr_notes, self.is_sized())?;
        Ok(self.commit_size(pages))
    }

    /// The depth in notes; zero when it has never been set. # C: O(1)
    pub fn capacity(&self) -> usize { self.state.lock().capacity }

    /// Install the wake callback for the pipe this queue backs. # C: O(1)
    pub fn set_waker(&self, w: Waker) { *self.waker.lock() = Some(w); }

    /// `IOC_WATCH_QUEUE_SET_FILTER`. `None` removes the filter. # C: O(1)
    pub fn set_filter(&self, filter: Option<Filter>) { self.state.lock().filter = filter; }

    /// # C: O(1)
    pub fn filter(&self) -> Option<Filter> { self.state.lock().filter.clone() }

    /// Number of notes waiting. # C: O(1)
    pub fn len(&self) -> usize { self.state.lock().notes.len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.state.lock().notes.is_empty() }

    /// Is there anything for a reader to collect — a note, or a loss it has
    /// not been told about? # C: O(1)
    pub fn readable(&self) -> bool {
        let g = self.state.lock();
        !g.notes.is_empty() || g.note_loss
    }

    /// Post a record. Returns whether it was queued; a refusal is recorded as
    /// a loss the reader will be told about in sequence, never dropped
    /// silently. # C: O(1)
    pub fn post(&self, record: &[u8]) -> bool {
        let queued = self.post_locked(record);
        // The wake happens with the queue lock released and AFTER the record
        // is visible, so a reader that armed itself under that lock cannot
        // miss it. A record that was NOT queued still wakes: it left a loss
        // behind, and a reader blocked on an empty queue must be told about
        // that too.
        if let Some(w) = self.waker.lock().as_ref() { w(); }
        queued
    }

    fn post_locked(&self, record: &[u8]) -> bool {
        let mut g = self.state.lock();
        if let Some(f) = &g.filter {
            let (ty, subtype, info) = decode_header(record);
            if !f.accepts(ty, subtype, info) {
                // A filtered-out record is not a loss: the reader asked not to
                // be told, so telling it that something was withheld would
                // defeat the filter.
                return false;
            }
        }
        if g.notes.len() >= g.capacity {
            match g.notes.back_mut() {
                Some(last) => last.loss_follows = true,
                // Nothing is queued to hang the marker on — with no depth at
                // all, that is every notification — so the reader is told at
                // its next read.
                None => g.note_loss = true,
            }
            return false;
        }
        g.notes.push_back(Note { bytes: record.to_vec(), loss_follows: false });
        true
    }

    /// Read, or — finding nothing — run `arm` while still holding the queue
    /// lock so the caller can enqueue itself for a wake without racing a
    /// poster. `Ok(None)` means nothing was waiting and `arm` has run.
    /// # C: O(records)
    pub fn read_or_arm<F: FnOnce()>(&self, buf_len: usize, arm: F)
        -> Result<Option<Vec<u8>>, Errno>
    {
        // One critical section: a poster cannot slip in between finding the
        // queue empty and enqueueing for the wake.
        let g = self.state.lock();
        if g.notes.is_empty() && !g.note_loss {
            arm();
            return Ok(None);
        }
        drop(g);
        self.read(buf_len).map(Some)
    }

    /// Collect whole records into `buf`, newest last.
    ///
    /// Records are never split: a buffer too small for the FIRST record to be
    /// returned is ENOBUFS rather than a truncated record the reader would
    /// mis-parse. A pending loss is reported first, as an eight-byte meta
    /// record, so the gap appears at the point in the stream where it
    /// happened. Returns 0 when nothing is waiting. # C: O(records)
    pub fn read(&self, buf_len: usize) -> Result<Vec<u8>, Errno> {
        let mut g = self.state.lock();
        let mut out: Vec<u8> = Vec::new();
        if g.note_loss {
            if buf_len < WATCH_HEADER_SIZE { return Err(Errno::Enobufs); }
            out.extend_from_slice(&loss_record());
            g.note_loss = false;
        }
        while let Some(front) = g.notes.front() {
            if out.len() + front.bytes.len() > buf_len {
                if out.is_empty() { return Err(Errno::Enobufs); }
                break;
            }
            let note = g.notes.pop_front().expect("the front was just observed");
            out.extend_from_slice(&note.bytes);
            if note.loss_follows {
                // The gap is reported by the NEXT read, which is where it sits
                // in the stream.
                g.note_loss = true;
                break;
            }
        }
        Ok(out)
    }
}

/// Build a `struct watch_notification` header. `len` is the whole record's
/// length in bytes, which is what a reader uses to step to the next one.
/// # C: O(1)
pub fn header(ty: u32, subtype: u32, len: usize, info_extra: u32) -> [u8; WATCH_HEADER_SIZE] {
    let w0 = (ty & WATCH_TYPE_MASK) | (subtype << WATCH_SUBTYPE_SHIFT);
    let info = (len as u32 & WATCH_INFO_LENGTH) | info_extra;
    let mut out = [0u8; WATCH_HEADER_SIZE];
    out[..4].copy_from_slice(&w0.to_ne_bytes());
    out[4..].copy_from_slice(&info.to_ne_bytes());
    out
}

/// `(type, subtype, info)` of an encoded record. # C: O(1)
pub fn decode_header(record: &[u8]) -> (u32, u32, u32) {
    let w0 = u32::from_ne_bytes([record[0], record[1], record[2], record[3]]);
    let info = u32::from_ne_bytes([record[4], record[5], record[6], record[7]]);
    (w0 & WATCH_TYPE_MASK, w0 >> WATCH_SUBTYPE_SHIFT, info)
}

/// The record that tells a reader notifications were dropped. # C: O(1)
pub fn loss_record() -> [u8; WATCH_HEADER_SIZE] {
    header(WATCH_TYPE_META, WATCH_META_LOSS_NOTIFICATION, WATCH_HEADER_SIZE, 0)
}

/// `struct key_notification`: the header, the key the event happened to, and
/// one word of per-subtype auxiliary data — the linked key's serial for a
/// link/unlink, the instantiation error for an instantiate. # C: O(1)
pub fn key_notification(subtype: u32, key_id: i32, aux: u32, info_id: u32)
    -> [u8; KEY_NOTIFICATION_SIZE]
{
    let mut out = [0u8; KEY_NOTIFICATION_SIZE];
    out[..WATCH_HEADER_SIZE].copy_from_slice(
        &header(WATCH_TYPE_KEY_NOTIFY, subtype, KEY_NOTIFICATION_SIZE, info_id));
    out[8..12].copy_from_slice(&(key_id as u32).to_ne_bytes());
    out[12..].copy_from_slice(&aux.to_ne_bytes());
    out
}

/// `struct watch_notification_removal`: sent to a watcher when the object it
/// watched goes away, so a queue never silently stops producing. # C: O(1)
pub fn removal_record(id: u64, info_id: u32) -> [u8; WATCH_REMOVAL_SIZE] {
    let mut out = [0u8; WATCH_REMOVAL_SIZE];
    out[..WATCH_HEADER_SIZE].copy_from_slice(
        &header(WATCH_TYPE_META, WATCH_META_REMOVAL_NOTIFICATION, WATCH_REMOVAL_SIZE, info_id));
    out[8..].copy_from_slice(&id.to_ne_bytes());
    out
}

/// `IOC_WATCH_QUEUE_SET_SIZE` admission, in the reference's order: a queue that
/// already has its notes is EBUSY whatever depth was asked for, and only then
/// is the depth itself ranged. Answers the whole PAGES the depth rounds up to,
/// which is both the depth actually published and the memory charged for it.
/// # C: O(1)
pub fn admit_set_size(nr_notes: usize, already_sized: bool) -> Result<usize, Errno> {
    if already_sized { return Err(Errno::Ebusy); }
    if nr_notes < 1 || nr_notes > WATCH_QUEUE_MAX_NOTES { return Err(Errno::Einval); }
    Ok(nr_notes.div_ceil(WATCH_QUEUE_NOTES_PER_PAGE))
}
