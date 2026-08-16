use alloc::vec::Vec;
use sync::{Spinlock, TaskList as L};

pub(crate) struct Oss {
    pub owner: crate::SoundOwnerKey,
    pub rate: u8,
    pub format: u32,
    pub channels: u8,
    pub subdivision: u8,
    pub fragshift: u8,
    pub maxfrags: u16,
    pub running: bool,
    pub cap_running: bool,
}

pub(crate) static OSS: Spinlock<Vec<Oss>, L> = Spinlock::new(Vec::new());

/// # C: O(cards)
pub(crate) fn initial(owner: crate::SoundOwnerKey) -> Oss {
    let (rate, format, channels) = crate::oss::oss_params::initial_params(owner);
    Oss { owner, rate, format, channels, subdivision: 0, fragshift: 0, maxfrags: 2, running: false, cap_running: false }
}

/// # C: O(cards)
pub(crate) fn register_card(owner: crate::SoundOwnerKey) {
    let mut guard = OSS.lock();
    if !guard.iter().any(|o| o.owner == owner) {
        guard.push(initial(owner));
    }
}

/// # C: O(cards)
pub(crate) fn unregister_card(owner: crate::SoundOwnerKey) {
    crate::oss::oss_ioctl::reset(owner);
    let mut guard = OSS.lock();
    guard.retain(|o| o.owner != owner);
}

#[cfg(test)]
/// # C: O(cards)
pub(crate) fn registered_count() -> usize {
    OSS.lock().len()
}

#[cfg(test)]
/// # C: O(cards)
pub(crate) fn has_card(owner: crate::SoundOwnerKey) -> bool {
    OSS.lock().iter().any(|o| o.owner == owner)
}
