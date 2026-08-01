// The watch list: who is watching what, under which id, and what a watcher is
// told when the object goes away.

use alloc::sync::Arc;

use super::*;
use crate::watch_queue::queue::WatchQueue;
use crate::watch_queue::watch::WatchList;
use syscall::errno::Errno;

fn queue() -> Arc<WatchQueue> {
    let q = Arc::new(WatchQueue::new());
    q.set_size(8).expect("a valid depth");
    q
}

// One queue may watch one object once; a second watch would deliver every
// event twice.
#[test]
fn a_queue_watches_an_object_once() {
    let mut wl = WatchList::new();
    let (a, b) = (queue(), queue());
    assert_eq!(wl.add(a.clone(), 7, 1), Ok(()));
    assert_eq!(wl.add(a.clone(), 7, 2), Err(Errno::Ebusy),
        "the same queue on the same object, even under a different watchpoint id");
    assert_eq!(wl.add(b.clone(), 7, 1), Ok(()), "a different queue may watch the same object");
    assert_eq!(wl.add(a.clone(), 8, 1), Ok(()), "the same queue may watch a different object");
    assert_eq!(wl.watches.len(), 3);
}

// Removing a watch that is not there is EBADSLT — a caller whose bookkeeping
// disagrees with the kernel's needs to see it.
#[test]
fn removing_an_absent_watch_is_ebadslt() {
    let mut wl = WatchList::new();
    let (a, b) = (queue(), queue());
    assert_eq!(wl.remove(&a, 7), Err(Errno::Ebadslt));
    wl.add(a.clone(), 7, 3).expect("added");
    assert_eq!(wl.remove(&b, 7), Err(Errno::Ebadslt), "another queue's watch is not this one's");
    assert_eq!(wl.remove(&a, 9), Err(Errno::Ebadslt), "another object's watch is not this one's");
    assert_eq!(wl.remove(&a, 7), Ok(()));
    assert!(wl.is_empty());
}

// Removing a watch tells the queue, so a reader is never left waiting for
// events from something it no longer watches.
#[test]
fn removal_posts_a_meta_record_naming_the_object() {
    let mut wl = WatchList::new();
    let q = queue();
    wl.add(q.clone(), 0x2a, 5).expect("added");
    wl.remove(&q, 0x2a).expect("removed");
    let out = q.read(64).expect("room");
    let recs = records(&out);
    assert_eq!(recs.len(), 1);
    let (ty, subtype, info) = head(recs[0]);
    assert_eq!((ty, subtype), (WATCH_TYPE_META, WATCH_META_REMOVAL_NOTIFICATION));
    assert_eq!(info & WATCH_INFO_LENGTH, WATCH_REMOVAL_SIZE as u32);
    assert_eq!((info & WATCH_INFO_ID) >> WATCH_INFO_ID_SHIFT, 5, "the watchpoint id the caller chose");
    assert_eq!(u64::from_ne_bytes(recs[0][8..16].try_into().expect("eight bytes")), 0x2a);
}

// The object dying removes every watch and tells every watcher.
#[test]
fn destroying_the_object_tells_every_watcher() {
    let mut wl = WatchList::new();
    let (a, b) = (queue(), queue());
    wl.add(a.clone(), 11, 1).expect("added");
    wl.add(b.clone(), 11, 2).expect("added");
    wl.remove_all();
    assert!(wl.is_empty());
    for (q, id) in [(&a, 1u32), (&b, 2u32)] {
        let out = q.read(64).expect("room");
        let recs = records(&out);
        assert_eq!(head(recs[0]).1, WATCH_META_REMOVAL_NOTIFICATION);
        assert_eq!((head(recs[0]).2 & WATCH_INFO_ID) >> WATCH_INFO_ID_SHIFT, id);
    }
}

// An event reaches every watcher, each stamped with the id THAT watcher chose,
// so two watchers of one key each recognise their own records.
#[test]
fn an_event_is_stamped_per_watcher() {
    let mut wl = WatchList::new();
    let (a, b) = (queue(), queue());
    wl.add(a.clone(), 99, 0x11).expect("added");
    wl.add(b.clone(), 99, 0x22).expect("added");
    wl.post_key_event(NOTIFY_KEY_LINKED, 99, 0x4242);
    for (q, id) in [(&a, 0x11u32), (&b, 0x22u32)] {
        let out = q.read(64).expect("room");
        let recs = records(&out);
        assert_eq!(head(recs[0]).0, WATCH_TYPE_KEY_NOTIFY);
        assert_eq!(head(recs[0]).1, NOTIFY_KEY_LINKED);
        assert_eq!((head(recs[0]).2 & WATCH_INFO_ID) >> WATCH_INFO_ID_SHIFT, id);
        assert_eq!(key_fields(recs[0]), (99, 0x4242));
    }
}
