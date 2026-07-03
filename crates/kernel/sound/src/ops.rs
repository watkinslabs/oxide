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

static OPS: Spinlock<Option<&'static SoundOps>, OpsLockClass> = Spinlock::new(None);

pub fn register(ops: &'static SoundOps) {
    *OPS.lock() = Some(ops);
}

pub fn clear() {
    *OPS.lock() = None;
}

pub fn ops() -> Option<&'static SoundOps> {
    *OPS.lock()
}

pub fn config() -> Option<(u32, u32, u32, u32)> {
    ops().and_then(|ops| (ops.config)())
}

pub fn pcm_caps() -> Caps {
    ops().and_then(|ops| (ops.pcm_caps)())
}

pub fn cap_caps() -> Caps {
    ops().and_then(|ops| (ops.cap_caps)())
}

pub fn period_bytes() -> usize {
    ops().map(|ops| (ops.period_bytes)()).unwrap_or(2048)
}

pub fn pcm_hw_params(rate: u8, format: u8, channels: u8, period_bytes: u32, buffer_bytes: u32) -> bool {
    ops().map(|ops| (ops.pcm_hw_params)(rate, format, channels, period_bytes, buffer_bytes)).unwrap_or(false)
}

pub fn pcm_prepare() -> bool {
    ops().map(|ops| (ops.pcm_prepare)()).unwrap_or(false)
}

pub fn pcm_trigger(start: bool) -> bool {
    ops().map(|ops| (ops.pcm_trigger)(start)).unwrap_or(false)
}

pub fn pcm_hw_free() -> bool {
    ops().map(|ops| (ops.pcm_hw_free)()).unwrap_or(false)
}

pub fn pcm_submit(bytes: &[u8]) -> usize {
    ops().map(|ops| (ops.pcm_submit)(bytes)).unwrap_or(0)
}

pub fn cap_hw_params(rate: u8, format: u8, channels: u8, period_bytes: u32, buffer_bytes: u32) -> bool {
    ops().map(|ops| (ops.cap_hw_params)(rate, format, channels, period_bytes, buffer_bytes)).unwrap_or(false)
}

pub fn cap_prepare() -> bool {
    ops().map(|ops| (ops.cap_prepare)()).unwrap_or(false)
}

pub fn cap_trigger(start: bool) -> bool {
    ops().map(|ops| (ops.cap_trigger)(start)).unwrap_or(false)
}

pub fn cap_hw_free() -> bool {
    ops().map(|ops| (ops.cap_hw_free)()).unwrap_or(false)
}

pub fn pcm_recv(out: &mut [u8]) -> usize {
    ops().map(|ops| (ops.pcm_recv)(out)).unwrap_or(0)
}
