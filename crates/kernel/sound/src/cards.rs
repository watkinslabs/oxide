use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as SoundLockClass};

struct SoundCard {
    owner: SoundOwnerKey,
    card: u32,
    publishing: bool,
    nodes: Vec<Arc<drv::Device>>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct SoundOwnerKey(u32);

impl SoundOwnerKey {
    /// Build from a driver-owned stable sound endpoint key. # C: O(1)
    pub fn from_raw(raw: u32) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    /// Raw key for driver-local reverse lookup and hosted assertions. # C: O(1)
    pub fn raw(self) -> u32 { self.0 }
}

static CARDS: Spinlock<Vec<SoundCard>, SoundLockClass> = Spinlock::new(Vec::new());

enum PublishClaim {
    Start(u32),
    AlreadyDone,
    Busy,
    Missing,
}

/// Register the ALSA (primary) + OSS (emulation) nodes for a probed card.
/// Called from the sound card driver's probe after it has installed ops.
/// # C: O(depth)
pub fn register_card(owner: SoundOwnerKey) -> bool {
    if crate::ops::ops_for(owner).is_none() { return false; }
    if !reserve_card(owner) { return false; }
    let card = match claim_publication(owner) {
        PublishClaim::Start(card) => card,
        PublishClaim::AlreadyDone => return true,
        PublishClaim::Busy | PublishClaim::Missing => return false,
    };
    let pcm_devices = crate::ops::pcm_devices(owner);
    let has_playback = (0..pcm_devices).any(|device| crate::ops::pcm_caps_for(owner, device).is_some());
    let has_capture = (0..pcm_devices).any(|device| crate::ops::cap_caps_for(owner, device).is_some());
    if has_playback { crate::pcm::register_card(owner); }
    if has_capture { crate::capture::register_card(owner); }
    if has_playback || has_capture { crate::oss::register_card(owner); }
    devfs::register_dir("/dev/snd");
    let Some(published) = crate::device::publish_card_nodes(owner, card, pcm_devices) else {
        rollback_card_registration(owner);
        return false;
    };
    if let Err(nodes) = commit_publication(owner, published) {
        crate::device::rollback_published_nodes(&nodes);
        rollback_card_registration(owner);
        return false;
    }
    true
}

fn claim_publication(owner: SoundOwnerKey) -> PublishClaim {
    let mut cards = CARDS.lock();
    let Some(record) = cards.iter_mut().find(|record| record.owner == owner) else {
        return PublishClaim::Missing;
    };
    if !record.nodes.is_empty() {
        return PublishClaim::AlreadyDone;
    }
    if record.publishing {
        return PublishClaim::Busy;
    }
    record.publishing = true;
    PublishClaim::Start(record.card)
}

fn commit_publication(owner: SoundOwnerKey, nodes: Vec<Arc<drv::Device>>) -> Result<(), Vec<Arc<drv::Device>>> {
    let mut cards = CARDS.lock();
    let Some(record) = cards
        .iter_mut()
        .find(|record| record.owner == owner && record.publishing && record.nodes.is_empty()) else {
            return Err(nodes);
        };
    record.nodes = nodes;
    record.publishing = false;
    Ok(())
}

fn rollback_card_registration(owner: SoundOwnerKey) {
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
pub fn reserve_card(owner: SoundOwnerKey) -> bool {
    let mut cards = CARDS.lock();
    if cards.iter().any(|record| record.owner == owner) { return true; }
    let mut card = 0u32;
    while cards.iter().any(|record| record.card == card) {
        card = card.checked_add(1).expect("sound card number overflow");
    }
    cards.push(SoundCard { owner, card, publishing: false, nodes: Vec::new() });
    true
}

/// Cancel a reserved-but-unpublished card number. This is the probe-failure
/// path before ALSA/OSS nodes have been made visible.
/// # C: O(cards)
pub fn cancel_card_reservation(owner: SoundOwnerKey) -> bool {
    let mut cards = CARDS.lock();
    let Some(idx) = cards.iter().position(|record| record.owner == owner && !record.publishing && record.nodes.is_empty()) else {
        return false;
    };
    cards.remove(idx);
    true
}

/// Stable card number assigned to `owner`.
/// # C: O(cards)
pub fn card_number(owner: SoundOwnerKey) -> Option<u32> {
    CARDS.lock().iter().find(|record| record.owner == owner).map(|record| record.card)
}

/// First registered sound-card owner. Kept for diagnostics that still need a
/// default card, not for data-path dispatch.
/// # C: O(1)
pub fn owner() -> Option<SoundOwnerKey> {
    CARDS.lock().first().map(|record| record.owner)
}

/// Remove ALSA/OSS nodes for the card being removed.
/// # C: O(nodes * depth)
pub fn unregister_card(owner: SoundOwnerKey) -> bool {
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
