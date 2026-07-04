use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as SoundLockClass};

struct SoundCard {
    owner: u32,
    card: u32,
    nodes: Vec<Arc<drv::Device>>,
}

const NO_CARD_OWNER: u32 = u32::MAX;

static CARDS: Spinlock<Vec<SoundCard>, SoundLockClass> = Spinlock::new(Vec::new());

/// Register the ALSA (primary) + OSS (emulation) nodes for a probed card.
/// Called from the sound card driver's probe after it has installed ops.
/// # C: O(depth)
pub fn register_card(owner: u32) -> bool {
    if crate::ops::ops_for(owner).is_none() { return false; }
    if !reserve_card(owner) { return false; }
    let card = match card_number(owner) {
        Some(card) => card,
        None => return false,
    };
    if CARDS.lock().iter().any(|record| record.owner == owner && !record.nodes.is_empty()) { return true; }
    let has_playback = crate::ops::pcm_caps(owner).is_some();
    let has_capture = crate::ops::cap_caps(owner).is_some();
    if has_playback { crate::pcm::register_card(owner); }
    if has_capture { crate::capture::register_card(owner); }
    if has_playback || has_capture { crate::oss::register_card(owner); }
    devfs::register_dir("/dev/snd");
    let Some(published) = crate::device::publish_card_nodes(owner, card, has_playback, has_capture) else {
        rollback_card_registration(owner);
        return false;
    };
    let mut published = Some(published);
    {
        let mut cards = CARDS.lock();
        let Some(record) = cards.iter_mut().find(|record| record.owner == owner) else {
            drop(cards);
            if let Some(nodes) = published.take() {
                crate::device::rollback_published_nodes(&nodes);
            }
            rollback_card_registration(owner);
            return false;
        };
        if record.nodes.is_empty() {
            record.nodes = published.take().unwrap_or_default();
        }
    }
    if let Some(nodes) = published {
        crate::device::rollback_published_nodes(&nodes);
        rollback_card_registration(owner);
    }
    true
}

fn rollback_card_registration(owner: u32) {
    crate::control::unregister_card(owner);
    crate::oss::unregister_card(owner);
    crate::capture::unregister_card(owner);
    crate::pcm::unregister_card(owner);
    let _ = crate::ops::clear(owner);
    let mut cards = CARDS.lock();
    if let Some(idx) = cards.iter().position(|record| record.owner == owner && record.nodes.is_empty()) {
        cards.remove(idx);
    }
}

/// Reserve a stable ALSA card number before the transport probe allocates or
/// publishes userspace-visible sound state. Same-owner calls are idempotent.
/// # C: O(cards)
pub fn reserve_card(owner: u32) -> bool {
    if owner == NO_CARD_OWNER { return false; }
    let mut cards = CARDS.lock();
    if cards.iter().any(|record| record.owner == owner) { return true; }
    let mut card = 0u32;
    while cards.iter().any(|record| record.card == card) {
        card = card.checked_add(1).expect("sound card number overflow");
    }
    cards.push(SoundCard { owner, card, nodes: Vec::new() });
    true
}

/// Cancel a reserved-but-unpublished card number. This is the probe-failure
/// path before ALSA/OSS nodes have been made visible.
/// # C: O(cards)
pub fn cancel_card_reservation(owner: u32) -> bool {
    let mut cards = CARDS.lock();
    let Some(idx) = cards.iter().position(|record| record.owner == owner && record.nodes.is_empty()) else {
        return false;
    };
    cards.remove(idx);
    true
}

/// Stable card number assigned to `owner`.
/// # C: O(cards)
pub fn card_number(owner: u32) -> Option<u32> {
    CARDS.lock().iter().find(|record| record.owner == owner).map(|record| record.card)
}

/// First registered sound-card owner. Kept for diagnostics that still need a
/// default card, not for data-path dispatch.
/// # C: O(1)
pub fn owner() -> Option<u32> {
    CARDS.lock().first().map(|record| record.owner)
}

/// Remove ALSA/OSS nodes for the card being removed.
/// # C: O(nodes * depth)
pub fn unregister_card(owner: u32) -> bool {
    let record = {
        let mut cards = CARDS.lock();
        let Some(idx) = cards.iter().position(|record| record.owner == owner) else {
            return false;
        };
        cards.remove(idx)
    };
    for node in record.nodes.iter().rev() {
        drv::device_del(node);
    }
    crate::control::unregister_card(owner);
    crate::oss::unregister_card(owner);
    crate::capture::unregister_card(owner);
    crate::pcm::unregister_card(owner);
    let _ = crate::ops::clear(owner);
    true
}
