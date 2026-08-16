// Control-event queue behind SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS. One bounded
// ring per card carries element notifications; each open description keeps a
// sequence cursor, so a dup shares the cursor and a separate open does not.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as EventLockClass};

use crate::elem::ElemId;

/// Events retained per card before the oldest is dropped.
pub const RING_DEPTH: usize = 64;

#[derive(Clone)]
pub struct Event {
    pub seq: u64,
    pub mask: u32,
    pub numid: u32,
    pub id: ElemId,
}

struct CardEvents {
    owner: crate::SoundOwnerKey,
    next_seq: u64,
    ring: VecDeque<Event>,
}

static EVENTS: Spinlock<Vec<CardEvents>, EventLockClass> = Spinlock::new(Vec::new());

/// Queue one element event, dropping the oldest when the ring is full — the
/// bounded-queue behaviour ALSA's control core has.
/// # C: O(cards)
pub fn push(owner: crate::SoundOwnerKey, mask: u32, numid: u32, id: &ElemId) {
    let mut guard = EVENTS.lock();
    let card = match guard.iter_mut().position(|card| card.owner == owner) {
        Some(index) => &mut guard[index],
        None => {
            guard.push(CardEvents { owner, next_seq: 1, ring: VecDeque::new() });
            let last = guard.len() - 1;
            &mut guard[last]
        }
    };
    let seq = card.next_seq;
    card.next_seq = seq.wrapping_add(1);
    if card.ring.len() == RING_DEPTH { card.ring.pop_front(); }
    card.ring.push_back(Event { seq, mask, numid, id: *id });
}

/// Sequence number a reader subscribing now should start from: only events
/// queued after the subscription are delivered. # C: O(cards)
pub fn latest_seq(owner: crate::SoundOwnerKey) -> u64 {
    EVENTS.lock().iter().find(|card| card.owner == owner).map(|card| card.next_seq.wrapping_sub(1)).unwrap_or(0)
}

/// Oldest queued event with `seq > cursor`. # C: O(cards + RING_DEPTH)
pub fn next_after(owner: crate::SoundOwnerKey, cursor: u64) -> Option<Event> {
    EVENTS.lock().iter()
        .find(|card| card.owner == owner)?
        .ring.iter().find(|event| event.seq > cursor).cloned()
}

/// Drop the card's queue on removal. # C: O(cards)
pub fn unregister_card(owner: crate::SoundOwnerKey) {
    EVENTS.lock().retain(|card| card.owner != owner);
}

/// `file->private_data` packing: bit 0 subscribed, the rest the read cursor.
/// # C: O(1)
pub fn pack(subscribed: bool, cursor: u64) -> u64 { (cursor << 1) | u64::from(subscribed) }

/// # C: O(1)
pub fn unpack(private: u64) -> (bool, u64) { (private & 1 != 0, private >> 1) }

#[cfg(test)]
#[path = "tests/control_event.rs"]
mod tests;
