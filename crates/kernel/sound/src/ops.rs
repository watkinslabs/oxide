//! Sound-card driver operations consumed by the ALSA/OSS core.
//!
//! The sound core owns user-visible ALSA/OSS state and device nodes. The
//! concrete card driver installs this table from probe, matching Linux's
//! `snd_pcm_ops` split without creating a crate cycle.

use sync::{Spinlock, TaskList as OpsLockClass};

pub type Caps = Option<(u64, u64, u8, u8)>;

pub struct SoundOps {
    pub config: fn() -> Option<(u32, u32, u32, u32)>,
    pub pcm_caps: fn() -> Caps,
    pub cap_caps: fn() -> Caps,
    pub period_bytes: fn() -> usize,
    pub pcm_hw_params: fn(u8, u8, u8, u32, u32) -> bool,
    pub pcm_prepare: fn() -> bool,
    pub pcm_trigger: fn(bool) -> bool,
    pub pcm_hw_free: fn() -> bool,
    pub pcm_submit: fn(&[u8]) -> usize,
    pub cap_hw_params: fn(u8, u8, u8, u32, u32) -> bool,
    pub cap_prepare: fn() -> bool,
    pub cap_trigger: fn(bool) -> bool,
    pub cap_hw_free: fn() -> bool,
    pub pcm_recv: fn(&mut [u8]) -> usize,
}

#[derive(Copy, Clone)]
struct OpsBinding {
    owner: u32,
    ops: &'static SoundOps,
}

static OPS: Spinlock<Option<OpsBinding>, OpsLockClass> = Spinlock::new(None);

pub fn register(owner: u32, ops: &'static SoundOps) -> bool {
    if crate::owner() != Some(owner) {
        return false;
    }
    *OPS.lock() = Some(OpsBinding { owner, ops });
    true
}

pub fn clear(owner: u32) -> bool {
    let mut guard = OPS.lock();
    let Some(binding) = *guard else {
        return false;
    };
    if binding.owner != owner {
        return false;
    }
    *guard = None;
    true
}

pub fn ops_for(owner: u32) -> Option<&'static SoundOps> {
    let binding = (*OPS.lock())?;
    if binding.owner == owner && crate::owner() == Some(owner) {
        Some(binding.ops)
    } else {
        None
    }
}

pub fn ops() -> Option<&'static SoundOps> {
    ops_for(crate::owner()?)
}

pub fn config() -> Option<(u32, u32, u32, u32)> {
    ops().and_then(|ops| (ops.config)())
}

pub fn pcm_caps(owner: u32) -> Caps {
    ops_for(owner).and_then(|ops| (ops.pcm_caps)())
}

pub fn cap_caps(owner: u32) -> Caps {
    ops_for(owner).and_then(|ops| (ops.cap_caps)())
}

pub fn period_bytes(owner: u32) -> usize {
    ops_for(owner).map(|ops| (ops.period_bytes)()).unwrap_or(2048)
}

pub fn pcm_hw_params(owner: u32, rate: u8, format: u8, channels: u8, period_bytes: u32, buffer_bytes: u32) -> bool {
    ops_for(owner).map(|ops| (ops.pcm_hw_params)(rate, format, channels, period_bytes, buffer_bytes)).unwrap_or(false)
}

pub fn pcm_prepare(owner: u32) -> bool {
    ops_for(owner).map(|ops| (ops.pcm_prepare)()).unwrap_or(false)
}

pub fn pcm_trigger(owner: u32, start: bool) -> bool {
    ops_for(owner).map(|ops| (ops.pcm_trigger)(start)).unwrap_or(false)
}

pub fn pcm_hw_free(owner: u32) -> bool {
    ops_for(owner).map(|ops| (ops.pcm_hw_free)()).unwrap_or(false)
}

pub fn pcm_submit(owner: u32, bytes: &[u8]) -> usize {
    ops_for(owner).map(|ops| (ops.pcm_submit)(bytes)).unwrap_or(0)
}

pub fn cap_hw_params(owner: u32, rate: u8, format: u8, channels: u8, period_bytes: u32, buffer_bytes: u32) -> bool {
    ops_for(owner).map(|ops| (ops.cap_hw_params)(rate, format, channels, period_bytes, buffer_bytes)).unwrap_or(false)
}

pub fn cap_prepare(owner: u32) -> bool {
    ops_for(owner).map(|ops| (ops.cap_prepare)()).unwrap_or(false)
}

pub fn cap_trigger(owner: u32, start: bool) -> bool {
    ops_for(owner).map(|ops| (ops.cap_trigger)(start)).unwrap_or(false)
}

pub fn cap_hw_free(owner: u32) -> bool {
    ops_for(owner).map(|ops| (ops.cap_hw_free)()).unwrap_or(false)
}

pub fn pcm_recv(owner: u32, out: &mut [u8]) -> usize {
    ops_for(owner).map(|ops| (ops.pcm_recv)(out)).unwrap_or(0)
}
