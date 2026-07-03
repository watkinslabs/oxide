//! Sound-card driver operations consumed by the ALSA/OSS core.
//!
//! The sound core owns user-visible ALSA/OSS state and device nodes. The
//! concrete card driver installs this table from probe, matching Linux's
//! `snd_pcm_ops` split without creating a crate cycle.

use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Spinlock, TaskList as OpsLockClass};

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

struct OpsRegistration {
    owner:   u64,
    card_id: Option<u32>,
    ops:     &'static SoundOps,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OpsEndpoint {
    pub(crate) owner: u64,
}

static OPS: Spinlock<alloc::vec::Vec<OpsRegistration>, OpsLockClass> =
    Spinlock::new(alloc::vec::Vec::new());
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

pub fn register(ops: &'static SoundOps) -> Option<OpsEndpoint> {
    let mut owner;
    loop {
        owner = NEXT_OWNER.fetch_add(1, Ordering::AcqRel);
        if owner != 0 {
            break;
        }
    }
    OPS.lock().push(OpsRegistration { owner, card_id: None, ops });
    Some(OpsEndpoint { owner })
}

pub fn clear(endpoint: OpsEndpoint) -> bool {
    let mut active = OPS.lock();
    let Some(idx) = active.iter().position(|reg| reg.owner == endpoint.owner) else {
        return false;
    };
    active.remove(idx);
    true
}

#[cfg(test)]
pub(crate) fn clear_for_tests() {
    OPS.lock().clear();
}

pub fn is_owner(endpoint: OpsEndpoint) -> bool {
    OPS.lock().iter().any(|reg| reg.owner == endpoint.owner)
}

pub fn bind_card(endpoint: OpsEndpoint, card_id: u32) -> bool {
    let mut active = OPS.lock();
    if active.iter().any(|reg| reg.card_id == Some(card_id)) {
        return false;
    }
    match active.iter_mut().find(|reg| reg.owner == endpoint.owner) {
        Some(reg) if reg.card_id.is_none() => {
            reg.card_id = Some(card_id);
            true
        }
        Some(reg) => reg.card_id == Some(card_id),
        None => false,
    }
}

pub fn ops(card_id: u32) -> Option<&'static SoundOps> {
    OPS.lock()
        .iter()
        .find(|reg| reg.card_id == Some(card_id))
        .map(|reg| reg.ops)
}

pub fn config(card_id: u32) -> Option<(u32, u32, u32, u32)> {
    ops(card_id).and_then(|ops| (ops.config)(card_id))
}

pub fn pcm_caps(card_id: u32) -> Caps {
    ops(card_id).and_then(|ops| (ops.pcm_caps)(card_id))
}

pub fn cap_caps(card_id: u32) -> Caps {
    ops(card_id).and_then(|ops| (ops.cap_caps)(card_id))
}

pub fn period_bytes(card_id: u32) -> usize {
    ops(card_id).map(|ops| (ops.period_bytes)(card_id)).unwrap_or(2048)
}

pub fn pcm_hw_params(card_id: u32, rate: u8, format: u8, channels: u8, period_bytes: u32, buffer_bytes: u32) -> bool {
    ops(card_id).map(|ops| (ops.pcm_hw_params)(card_id, rate, format, channels, period_bytes, buffer_bytes)).unwrap_or(false)
}

pub fn pcm_prepare(card_id: u32) -> bool {
    ops(card_id).map(|ops| (ops.pcm_prepare)(card_id)).unwrap_or(false)
}

pub fn pcm_trigger(card_id: u32, start: bool) -> bool {
    ops(card_id).map(|ops| (ops.pcm_trigger)(card_id, start)).unwrap_or(false)
}

pub fn pcm_hw_free(card_id: u32) -> bool {
    ops(card_id).map(|ops| (ops.pcm_hw_free)(card_id)).unwrap_or(false)
}

pub fn pcm_submit(card_id: u32, bytes: &[u8]) -> usize {
    ops(card_id).map(|ops| (ops.pcm_submit)(card_id, bytes)).unwrap_or(0)
}

pub fn cap_hw_params(card_id: u32, rate: u8, format: u8, channels: u8, period_bytes: u32, buffer_bytes: u32) -> bool {
    ops(card_id).map(|ops| (ops.cap_hw_params)(card_id, rate, format, channels, period_bytes, buffer_bytes)).unwrap_or(false)
}

pub fn cap_prepare(card_id: u32) -> bool {
    ops(card_id).map(|ops| (ops.cap_prepare)(card_id)).unwrap_or(false)
}

pub fn cap_trigger(card_id: u32, start: bool) -> bool {
    ops(card_id).map(|ops| (ops.cap_trigger)(card_id, start)).unwrap_or(false)
}

pub fn cap_hw_free(card_id: u32) -> bool {
    ops(card_id).map(|ops| (ops.cap_hw_free)(card_id)).unwrap_or(false)
}

pub fn pcm_recv(card_id: u32, out: &mut [u8]) -> usize {
    ops(card_id).map(|ops| (ops.pcm_recv)(card_id, out)).unwrap_or(0)
}
