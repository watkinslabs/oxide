// `notify_key` — the ONE place a key event becomes a notification record.
//
// Every op that changes a key calls through here rather than posting records
// itself, so "what does a watcher see" is answered in one place and an op that
// forgets to notify is a missing call site, not a second encoding of the same
// event.

use super::store::Store;
use crate::watch_queue::{NOTIFY_KEY_CLEARED, NOTIFY_KEY_INSTANTIATED, NOTIFY_KEY_INVALIDATED,
    NOTIFY_KEY_LINKED, NOTIFY_KEY_REVOKED, NOTIFY_KEY_SETATTR, NOTIFY_KEY_UNLINKED,
    NOTIFY_KEY_UPDATED};

/// Post an event about `serial` to everything watching it.
///
/// The auxiliary word is per-subtype: the linked or unlinked key's serial for
/// a keyring event, the instantiation error for a rejected key, zero
/// otherwise. Nothing happens when the key has no watchers, which is the
/// common case. # C: O(watches)
pub fn notify_key(g: &Store, serial: i32, subtype: u32, aux: u32) {
    if let Some(k) = g.keys.get(&serial) {
        if k.watchers.is_empty() { return; }
        k.watchers.post_key_event(subtype, serial, aux);
    }
}

/// The key was given its payload. `aux` carries the error a rejected key was
/// given, so a watcher learns the request failed and why. # C: O(watches)
pub fn instantiated(g: &Store, serial: i32, error: u32) {
    notify_key(g, serial, NOTIFY_KEY_INSTANTIATED, error);
}

/// The key's payload was replaced. # C: O(watches)
pub fn updated(g: &Store, serial: i32) { notify_key(g, serial, NOTIFY_KEY_UPDATED, 0); }

/// A key was linked into a KEYRING: the event belongs to the ring, and the
/// auxiliary word names the key that joined it. # C: O(watches)
pub fn linked(g: &Store, ring: i32, key: i32) {
    notify_key(g, ring, NOTIFY_KEY_LINKED, key as u32);
}

/// A key left a keyring. # C: O(watches)
pub fn unlinked(g: &Store, ring: i32, key: i32) {
    notify_key(g, ring, NOTIFY_KEY_UNLINKED, key as u32);
}

/// A keyring lost every member at once. # C: O(watches)
pub fn cleared(g: &Store, ring: i32) { notify_key(g, ring, NOTIFY_KEY_CLEARED, 0); }

/// # C: O(watches)
pub fn revoked(g: &Store, serial: i32) { notify_key(g, serial, NOTIFY_KEY_REVOKED, 0); }

/// # C: O(watches)
pub fn invalidated(g: &Store, serial: i32) { notify_key(g, serial, NOTIFY_KEY_INVALIDATED, 0); }

/// Ownership, permissions or expiry changed — one subtype for all three,
/// because what a watcher can do about any of them is the same: look again.
/// # C: O(watches)
pub fn setattr(g: &Store, serial: i32) { notify_key(g, serial, NOTIFY_KEY_SETATTR, 0); }
