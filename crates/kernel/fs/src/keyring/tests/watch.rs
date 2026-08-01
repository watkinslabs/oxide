// `KEYCTL_WATCH_KEY` and the events a watcher actually receives. These drive
// the real ops, so an op that changes a key without notifying shows up here as
// a missing record rather than as machinery nothing calls.

use alloc::sync::Arc;

use super::*;
use super::super::ops::watch as opwatch;
use super::super::ops::*;
use crate::watch_queue::*;

fn queue() -> Arc<WatchQueue> {
    let q = Arc::new(WatchQueue::new());
    q.set_size(32).expect("a valid depth");
    q
}

/// Every record waiting on the queue, split by its declared length.
fn drain(q: &WatchQueue) -> Vec<Vec<u8>> {
    let buf = q.read(4096).expect("room for everything queued");
    let mut out = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let info = u32::from_ne_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);
        let len = (info & WATCH_INFO_LENGTH) as usize;
        out.push(buf[i..i + len].to_vec());
        i += len;
    }
    out
}

/// `(type, subtype)` of a record.
fn kind(r: &[u8]) -> (u32, u32) {
    let w0 = u32::from_ne_bytes([r[0], r[1], r[2], r[3]]);
    (w0 & WATCH_TYPE_MASK, w0 >> WATCH_SUBTYPE_SHIFT)
}
/// `(key, aux)` of a key-change record.
fn fields(r: &[u8]) -> (i32, u32) {
    (i32::from_ne_bytes([r[8], r[9], r[10], r[11]]),
     u32::from_ne_bytes([r[12], r[13], r[14], r[15]]))
}
/// The subtypes of a batch of records, in order.
fn subtypes(recs: &[Vec<u8>]) -> Vec<u32> { recs.iter().map(|r| kind(r).1).collect() }

// The watchpoint-id rule, applied before anything is looked up.
#[test]
fn watch_id_admission() {
    assert_eq!(opwatch::vet_watch_id(-1), Ok(()), "-1 removes a watch");
    assert_eq!(opwatch::vet_watch_id(0), Ok(()));
    assert_eq!(opwatch::vet_watch_id(0xff), Ok(()));
    assert_eq!(opwatch::vet_watch_id(0x100), Err(Errno::Einval),
        "the record carries eight bits of watchpoint id, so a larger one could not be delivered");
    assert_eq!(opwatch::vet_watch_id(-2), Err(Errno::Einval));
    let t = ctx(1740, 7740);
    join_session(&t, None);
    let k = add_key_core(&t, "user", "w-id", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(opwatch::watch_key_core(&t, k, queue(), 0x100), einval());
}

// Watching costs VIEW permission, and a key that cannot be viewed cannot be
// watched.
#[test]
fn watching_needs_view_permission() {
    let t = ctx(1741, 7741);
    join_session(&t, None);
    let k = add_key_core(&t, "user", "w-perm", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    force_perm(k, KEY_POS_VIEW);
    assert_eq!(opwatch::watch_key_core(&t, k, queue(), 0), 0);
    force_perm(k, 0);
    assert_eq!(opwatch::watch_key_core(&t, k, queue(), 0), eacces());
    assert_eq!(opwatch::watch_key_core(&t, 0x7fff_0002, queue(), 0), enokey());
}

// A queue watches a key once, and removing a watch it does not hold is
// EBADSLT.
#[test]
fn add_and_remove_bookkeeping() {
    let t = ctx(1742, 7742);
    join_session(&t, None);
    let k = add_key_core(&t, "user", "w-book", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    let q = queue();
    assert_eq!(opwatch::watch_key_core(&t, k, q.clone(), 1), 0);
    assert_eq!(opwatch::watch_key_core(&t, k, q.clone(), 2), err(Errno::Ebusy));
    assert_eq!(opwatch::watch_key_core(&t, k, q.clone(), -1), 0);
    assert_eq!(opwatch::watch_key_core(&t, k, q.clone(), -1), err(Errno::Ebadslt));
    // The removal itself is announced, so the watcher knows why the records
    // stopped.
    assert_eq!(subtypes(&drain(&q)), alloc::vec![WATCH_META_REMOVAL_NOTIFICATION]);
}

// The single-key events: update, revoke, and the attribute changes.
#[test]
fn single_key_events_reach_the_watcher() {
    let t = ctx(1743, 7743);
    join_session(&t, None);
    let k = add_key_core(&t, "user", "w-events", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    let q = queue();
    assert_eq!(opwatch::watch_key_core(&t, k, q.clone(), 3), 0);

    assert_eq!(update_core(&t, k, alloc::vec![2, 2], true), 0);
    assert_eq!(setperm_core(&t, k, KEY_POS_ALL | KEY_USR_ALL), 0);
    assert_eq!(set_timeout_core(&t, k, 60), 0);
    assert_eq!(chown_core(&t, k, 7743, u32::MAX), 0);
    assert_eq!(revoke_core(&t, k), 0);

    let recs = drain(&q);
    assert_eq!(subtypes(&recs), alloc::vec![
        NOTIFY_KEY_UPDATED, NOTIFY_KEY_SETATTR, NOTIFY_KEY_SETATTR, NOTIFY_KEY_SETATTR,
        NOTIFY_KEY_REVOKED]);
    for r in &recs {
        assert_eq!(kind(r).0, WATCH_TYPE_KEY_NOTIFY);
        assert_eq!(fields(r).0, k, "every record names the key it happened to");
        let info = u32::from_ne_bytes([r[4], r[5], r[6], r[7]]);
        assert_eq!((info & WATCH_INFO_ID) >> WATCH_INFO_ID_SHIFT, 3);
    }
}

// A keyring's watcher hears about its MEMBERSHIP: the event belongs to the
// ring and names the key that joined or left.
#[test]
fn keyring_membership_events_name_the_key_involved() {
    let t = ctx(1744, 7744);
    let sess = join_session(&t, None) as i32;
    let ring = add_key_core(&t, "keyring", "w-ring", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING) as i32;
    let k = add_key_core(&t, "user", "w-member", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    let q = queue();
    assert_eq!(opwatch::watch_key_core(&t, ring, q.clone(), 4), 0);

    assert_eq!(link_core(&t, k, ring), 0);
    assert_eq!(unlink_core(&t, k, ring), 0);
    assert_eq!(link_core(&t, k, ring), 0);
    assert_eq!(clear_core(&t, ring), 0);

    let recs = drain(&q);
    assert_eq!(subtypes(&recs), alloc::vec![
        NOTIFY_KEY_LINKED, NOTIFY_KEY_UNLINKED, NOTIFY_KEY_LINKED, NOTIFY_KEY_CLEARED]);
    assert_eq!(fields(&recs[0]), (ring, k as u32), "the event is the RING's, and names the key");
    assert_eq!(fields(&recs[1]), (ring, k as u32));
    assert_eq!(fields(&recs[3]), (ring, 0), "a clear names no single key");
    assert!(sess != ring);
}

// A key being destroyed tells its watchers the object is gone.
#[test]
fn destroying_a_watched_key_announces_the_removal() {
    let t = ctx(1745, 7745);
    join_session(&t, None);
    let ring = add_key_core(&t, "keyring", "w-gc-ring", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING) as i32;
    let k = add_key_core(&t, "user", "w-gc", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(link_core(&t, k, ring), 0);
    let q = queue();
    assert_eq!(opwatch::watch_key_core(&t, k, q.clone(), 6), 0);
    // Unlink from both keyrings: the last link going away collects the key.
    assert_eq!(unlink_core(&t, k, ring), 0);
    assert_eq!(unlink_core(&t, k, KEY_SPEC_SESSION_KEYRING), 0);
    assert!(STORE.lock().keys.get(&k).is_none(), "the key was collected");
    let recs = drain(&q);
    assert_eq!(kind(recs.last().expect("at least the removal")),
        (WATCH_TYPE_META, WATCH_META_REMOVAL_NOTIFICATION));
}

// Two watchers of the same key each see the event under their own id, and a
// watcher that has removed its watch sees nothing more.
#[test]
fn watchers_are_independent() {
    let t = ctx(1746, 7746);
    join_session(&t, None);
    let k = add_key_core(&t, "user", "w-two", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    let (a, b) = (queue(), queue());
    assert_eq!(opwatch::watch_key_core(&t, k, a.clone(), 0x10), 0);
    assert_eq!(opwatch::watch_key_core(&t, k, b.clone(), 0x20), 0);
    assert_eq!(update_core(&t, k, alloc::vec![9], true), 0);
    assert_eq!(opwatch::watch_key_core(&t, k, b.clone(), -1), 0);
    assert_eq!(revoke_core(&t, k), 0);

    assert_eq!(subtypes(&drain(&a)), alloc::vec![NOTIFY_KEY_UPDATED, NOTIFY_KEY_REVOKED]);
    assert_eq!(subtypes(&drain(&b)), alloc::vec![NOTIFY_KEY_UPDATED, WATCH_META_REMOVAL_NOTIFICATION],
        "a queue that stopped watching hears nothing after its removal record");
}

// A key with no watchers costs nothing: the common case must not build records
// nobody receives.
#[test]
fn an_unwatched_key_produces_nothing() {
    let t = ctx(1747, 7747);
    join_session(&t, None);
    let k = add_key_core(&t, "user", "w-none", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(update_core(&t, k, alloc::vec![2], true), 0);
    assert_eq!(revoke_core(&t, k), 0);
    assert!(STORE.lock().keys.get(&k).expect("still present").watchers.is_empty());
}

// The advertised capability bit and the command must agree.
#[test]
fn capability_bit_tracks_the_implementation() {
    let caps = super::super::keyctl::keyrings_capabilities();
    assert_eq!(caps[1] & KEYCTL_CAPS1_NOTIFICATIONS != 0, opwatch::SUPPORTED);
    // With all three families implemented, every optional bit this kernel
    // knows about is now set.
    assert_ne!(caps[0] & KEYCTL_CAPS0_DIFFIE_HELLMAN, 0);
    assert_ne!(caps[0] & KEYCTL_CAPS0_PUBLIC_KEY, 0);
}
