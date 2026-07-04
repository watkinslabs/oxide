use alloc::vec::Vec;
use sync::{Spinlock, TaskList as L};

pub(crate) struct Pcm {
    pub owner: u32,
    pub state: u32,
    pub format: u32,
    pub rate: u32,
    pub channels: u32,
    pub frame_bytes: u32,
    pub period_frames: u32,
    pub buffer_frames: u32,
    pub start_threshold: u64,
    pub appl_ptr: u64,
    pub hw_ptr: u64,
}

pub(crate) static PCM: Spinlock<Vec<Pcm>, L> = Spinlock::new(Vec::new());

pub(crate) fn initial(owner: u32) -> Pcm {
    Pcm {
        owner, state: crate::uapi::STATE_OPEN, format: crate::uapi::FMT_S16_LE, rate: 44100, channels: 2,
        frame_bytes: 4, period_frames: 512, buffer_frames: 1024, start_threshold: 1, appl_ptr: 0, hw_ptr: 0,
    }
}

pub(crate) fn register_card(owner: u32) {
    let mut guard = PCM.lock();
    if !guard.iter().any(|p| p.owner == owner) {
        guard.push(initial(owner));
    }
}

pub(crate) fn unregister_card(owner: u32) {
    let mut guard = PCM.lock();
    guard.retain(|p| p.owner != owner);
}

pub(crate) fn is_registered(owner: u32) -> bool {
    PCM.lock().iter().any(|p| p.owner == owner)
}

#[cfg(test)]
pub(crate) fn registered_count() -> usize {
    PCM.lock().len()
}

#[cfg(test)]
pub(crate) fn has_card(owner: u32) -> bool {
    is_registered(owner)
}
