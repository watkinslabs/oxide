//! Sound-card driver operations consumed by the ALSA/OSS core.
//!
//! The sound core owns user-visible ALSA/OSS state and device nodes. The
//! concrete card driver installs this table from probe, matching Linux's
//! `snd_pcm_ops` split without creating a crate cycle.

use sync::{Spinlock, TaskList as OpsLockClass};
use alloc::vec::Vec;

pub type Caps = Option<(u64, u64, u8, u8)>;

pub struct SoundOps {
    pub config: fn(u32) -> Option<(u32, u32, u32, u32)>,
    pub pcm_caps: fn(u32) -> Caps,
    pub cap_caps: fn(u32) -> Caps,
    pub period_bytes: fn(u32) -> usize,
    pub pcm_hw_params: fn(u32, u8, u8, u8, u32, u32) -> bool,
    pub pcm_prepare: fn(u32) -> bool,
    pub pcm_trigger: fn(u32, bool) -> bool,
    pub pcm_hw_free: fn(u32) -> bool,
    pub pcm_submit: fn(u32, &[u8]) -> usize,
    pub cap_hw_params: fn(u32, u8, u8, u8, u32, u32) -> bool,
    pub cap_prepare: fn(u32) -> bool,
    pub cap_trigger: fn(u32, bool) -> bool,
    pub cap_hw_free: fn(u32) -> bool,
    pub pcm_recv: fn(u32, &mut [u8]) -> usize,
}

#[derive(Copy, Clone)]
struct OpsBinding {
    owner: u32,
    ops: &'static SoundOps,
}

static OPS: Spinlock<Vec<OpsBinding>, OpsLockClass> = Spinlock::new(Vec::new());

pub fn register(owner: u32, ops: &'static SoundOps) -> bool {
    if crate::card_number(owner).is_none() {
        return false;
    }
    let mut guard = OPS.lock();
    if let Some(binding) = guard.iter_mut().find(|binding| binding.owner == owner) {
        binding.ops = ops;
    } else {
        guard.push(OpsBinding { owner, ops });
    }
    true
}

pub fn clear(owner: u32) -> bool {
    let mut guard = OPS.lock();
    let before = guard.len();
    guard.retain(|binding| binding.owner != owner);
    guard.len() != before
}

pub fn ops_for(owner: u32) -> Option<&'static SoundOps> {
    OPS.lock()
        .iter()
        .find(|binding| binding.owner == owner && crate::card_number(owner).is_some())
        .map(|binding| binding.ops)
}

pub fn ops() -> Option<&'static SoundOps> {
    ops_for(crate::owner()?)
}

pub fn config() -> Option<(u32, u32, u32, u32)> {
    let owner = crate::owner()?;
    ops_for(owner).and_then(|ops| (ops.config)(owner))
}

pub fn pcm_caps(owner: u32) -> Caps {
    ops_for(owner).and_then(|ops| (ops.pcm_caps)(owner))
}

pub fn cap_caps(owner: u32) -> Caps {
    ops_for(owner).and_then(|ops| (ops.cap_caps)(owner))
}

pub fn period_bytes(owner: u32) -> Option<usize> {
    ops_for(owner).map(|ops| (ops.period_bytes)(owner)).filter(|bytes| *bytes != 0)
}

pub fn pcm_hw_params(owner: u32, rate: u8, format: u8, channels: u8, period_bytes: u32, buffer_bytes: u32) -> bool {
    ops_for(owner).map(|ops| (ops.pcm_hw_params)(owner, rate, format, channels, period_bytes, buffer_bytes)).unwrap_or(false)
}

pub fn pcm_prepare(owner: u32) -> bool {
    ops_for(owner).map(|ops| (ops.pcm_prepare)(owner)).unwrap_or(false)
}

pub fn pcm_trigger(owner: u32, start: bool) -> bool {
    ops_for(owner).map(|ops| (ops.pcm_trigger)(owner, start)).unwrap_or(false)
}

pub fn pcm_hw_free(owner: u32) -> bool {
    ops_for(owner).map(|ops| (ops.pcm_hw_free)(owner)).unwrap_or(false)
}

pub fn pcm_submit(owner: u32, bytes: &[u8]) -> usize {
    ops_for(owner).map(|ops| (ops.pcm_submit)(owner, bytes)).unwrap_or(0)
}

pub fn cap_hw_params(owner: u32, rate: u8, format: u8, channels: u8, period_bytes: u32, buffer_bytes: u32) -> bool {
    ops_for(owner).map(|ops| (ops.cap_hw_params)(owner, rate, format, channels, period_bytes, buffer_bytes)).unwrap_or(false)
}

pub fn cap_prepare(owner: u32) -> bool {
    ops_for(owner).map(|ops| (ops.cap_prepare)(owner)).unwrap_or(false)
}

pub fn cap_trigger(owner: u32, start: bool) -> bool {
    ops_for(owner).map(|ops| (ops.cap_trigger)(owner, start)).unwrap_or(false)
}

pub fn cap_hw_free(owner: u32) -> bool {
    ops_for(owner).map(|ops| (ops.cap_hw_free)(owner)).unwrap_or(false)
}

pub fn pcm_recv(owner: u32, out: &mut [u8]) -> usize {
    ops_for(owner).map(|ops| (ops.pcm_recv)(owner, out)).unwrap_or(0)
}
