use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Spinlock, TaskList as SoundLockClass};

use crate::{cancel_card_reservation, card_number, owner, register_card, reserve_card, unregister_card};
use crate::{capture, ops, oss, pcm, uapi};

mod timestamp;

const CARD0_NODE_COUNT: usize = 9;
const CARD1_NODE_COUNT: usize = 6;

static TEST_LOCK: AtomicU32 = AtomicU32::new(0);
static ADDED: Spinlock<Vec<(String, Option<(u32, u32)>, bool)>, SoundLockClass> = Spinlock::new(Vec::new());
static REMOVED: Spinlock<Vec<String>, SoundLockClass> = Spinlock::new(Vec::new());
static ROUTED: Spinlock<Vec<crate::SoundOwnerKey>, SoundLockClass> = Spinlock::new(Vec::new());

/// Exclusive ownership of the card registry, the operations table and the
/// process-global devtmpfs hooks. Everything a sound test touches is one
/// kernel-wide set, so a case that registers or clears operations while
/// another is counting published nodes changes what that one sees.
pub(crate) struct TestGuard;

impl Drop for TestGuard {
    fn drop(&mut self) {
        TEST_LOCK.store(0, Ordering::Release);
    }
}

pub(crate) fn test_guard() -> TestGuard {
    while TEST_LOCK.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_err() {
        core::hint::spin_loop();
    }
    TestGuard
}

fn cfg(_owner: crate::SoundOwnerKey) -> Option<(u32, u32, u32, u32)> { Some((0, 0, 0, 0)) }
fn caps(_owner: crate::SoundOwnerKey) -> ops::Caps { Some((0, 0, 1, 2)) }
fn no_caps(_owner: crate::SoundOwnerKey) -> ops::Caps { None }
fn period(_owner: crate::SoundOwnerKey) -> usize { 2048 }
fn hw_params(_owner: crate::SoundOwnerKey, _format: u32, _rate_hz: u32, _channels: u8, _period_bytes: u32, _buffer_bytes: u32) -> bool { true }
fn ident(_owner: crate::SoundOwnerKey) -> crate::CardIdentity {
    crate::CardIdentity::new(b"test", b"test-drv", b"Test Card", b"Test Card at test bus", b"Test Mixer", b"TEST:0001", b"Test PCM")
}
fn limits(_owner: crate::SoundOwnerKey) -> ops::HwLimits { (4096, 16384) }
fn info_flags(_owner: crate::SoundOwnerKey) -> u32 { 0 }
fn pause(_owner: crate::SoundOwnerKey, _pause: bool) -> bool { true }
fn no_pointer(_owner: crate::SoundOwnerKey) -> Option<u64> { None }
fn yes(_owner: crate::SoundOwnerKey) -> bool { true }
fn no(_owner: crate::SoundOwnerKey) -> bool { false }
fn trigger(_owner: crate::SoundOwnerKey, _start: bool) -> bool { true }
fn fail_trigger(_owner: crate::SoundOwnerKey, _start: bool) -> bool { false }
fn submit(_owner: crate::SoundOwnerKey, b: &[u8]) -> usize { b.len() }
fn recv(_owner: crate::SoundOwnerKey, b: &mut [u8]) -> usize { b.len() }
fn route_cfg(owner: crate::SoundOwnerKey) -> Option<(u32, u32, u32, u32)> { ROUTED.lock().push(owner); Some((0, 0, 0, 0)) }
fn route_caps(owner: crate::SoundOwnerKey) -> ops::Caps { ROUTED.lock().push(owner); Some((1u64 << crate::uapi::FMT_S16_LE, 1u64 << 6, 1, 2)) }
fn route_period(owner: crate::SoundOwnerKey) -> usize { ROUTED.lock().push(owner); 2048 }
fn route_yes(owner: crate::SoundOwnerKey) -> bool { ROUTED.lock().push(owner); true }
fn route_trigger(owner: crate::SoundOwnerKey, _start: bool) -> bool { ROUTED.lock().push(owner); true }
fn route_submit(owner: crate::SoundOwnerKey, b: &[u8]) -> usize { ROUTED.lock().push(owner); b.len() }
fn route_recv(owner: crate::SoundOwnerKey, b: &mut [u8]) -> usize { ROUTED.lock().push(owner); b.len() }
fn route_hw_params(owner: crate::SoundOwnerKey, _format: u32, _rate_hz: u32, _channels: u8, _period_bytes: u32, _buffer_bytes: u32) -> bool {
    ROUTED.lock().push(owner);
    true
}

static TEST_OPS: ops::SoundOps = ops::SoundOps {
    identity: ident, hw_limits: limits, info_flags: info_flags, pcm_pause: pause, pcm_drain: yes, pcm_pointer: no_pointer, cap_pointer: no_pointer,
    config: cfg, pcm_caps: caps, cap_caps: caps, period_bytes: period,
    pcm_hw_params: hw_params, pcm_prepare: yes, pcm_trigger: trigger, pcm_hw_free: yes, pcm_submit: submit,
    cap_hw_params: hw_params, cap_prepare: yes, cap_trigger: trigger, cap_hw_free: yes, pcm_recv: recv,
};

fn multi_devices(_owner: crate::SoundOwnerKey) -> u32 { 2 }
fn multi_caps(owner: crate::SoundOwnerKey, device: ops::PcmDevice) -> ops::Caps {
    if device < 2 { caps(owner) } else { None }
}
fn multi_hw_limits(owner: crate::SoundOwnerKey, _device: ops::PcmDevice) -> ops::HwLimits { limits(owner) }
fn multi_info_flags(owner: crate::SoundOwnerKey, _device: ops::PcmDevice) -> u32 { info_flags(owner) }
fn multi_period(owner: crate::SoundOwnerKey, _device: ops::PcmDevice) -> usize { period(owner) }
fn multi_hw_params(owner: crate::SoundOwnerKey, _device: ops::PcmDevice, format: u32, rate: u32, channels: u8, period_bytes: u32, buffer_bytes: u32) -> bool {
    hw_params(owner, format, rate, channels, period_bytes, buffer_bytes)
}
fn multi_prepare(owner: crate::SoundOwnerKey, _device: ops::PcmDevice) -> bool { yes(owner) }
fn multi_trigger(owner: crate::SoundOwnerKey, _device: ops::PcmDevice, start: bool) -> bool { trigger(owner, start) }
fn multi_pause(owner: crate::SoundOwnerKey, _device: ops::PcmDevice, paused: bool) -> bool { pause(owner, paused) }
fn multi_drain(owner: crate::SoundOwnerKey, _device: ops::PcmDevice) -> bool { yes(owner) }
fn multi_pointer(owner: crate::SoundOwnerKey, _device: ops::PcmDevice) -> Option<u64> { no_pointer(owner) }
fn multi_hw_free(owner: crate::SoundOwnerKey, _device: ops::PcmDevice) -> bool { yes(owner) }
fn multi_submit(owner: crate::SoundOwnerKey, _device: ops::PcmDevice, bytes: &[u8]) -> usize { submit(owner, bytes) }
fn multi_recv(owner: crate::SoundOwnerKey, _device: ops::PcmDevice, bytes: &mut [u8]) -> usize { recv(owner, bytes) }
fn multi_mmap(_owner: crate::SoundOwnerKey, _device: ops::PcmDevice, _capture: bool, _offset: u64) -> Option<u64> { None }
fn multi_mmap_commit(_owner: crate::SoundOwnerKey, _device: ops::PcmDevice, _capture: bool, _appl: u64, hw: u64, _frame_bytes: u32, _buffer_frames: u32) -> Option<u64> { Some(hw) }

static MULTI_DEVICE_OPS: ops::PcmDeviceOps = ops::PcmDeviceOps {
    pcm_devices: multi_devices,
    pcm_caps: multi_caps,
    cap_caps: multi_caps,
    hw_limits: multi_hw_limits,
    info_flags: multi_info_flags,
    period_bytes: multi_period,
    pcm_hw_params: multi_hw_params,
    pcm_prepare: multi_prepare,
    pcm_trigger: multi_trigger,
    pcm_pause: multi_pause,
    pcm_drain: multi_drain,
    pcm_pointer: multi_pointer,
    pcm_hw_free: multi_hw_free,
    pcm_submit: multi_submit,
    cap_hw_params: multi_hw_params,
    cap_prepare: multi_prepare,
    cap_trigger: multi_trigger,
    cap_pointer: multi_pointer,
    cap_hw_free: multi_hw_free,
    pcm_recv: multi_recv,
    pcm_mmap_frame: multi_mmap,
    pcm_mmap_commit: multi_mmap_commit,
};

static PLAYBACK_ONLY_OPS: ops::SoundOps = ops::SoundOps {
    identity: ident, hw_limits: limits, info_flags: info_flags, pcm_pause: pause, pcm_drain: yes, pcm_pointer: no_pointer, cap_pointer: no_pointer,
    config: cfg, pcm_caps: caps, cap_caps: no_caps, period_bytes: period,
    pcm_hw_params: hw_params, pcm_prepare: yes, pcm_trigger: trigger, pcm_hw_free: yes, pcm_submit: submit,
    cap_hw_params: hw_params, cap_prepare: yes, cap_trigger: trigger, cap_hw_free: yes, pcm_recv: recv,
};

static CAPTURE_ONLY_OPS: ops::SoundOps = ops::SoundOps {
    identity: ident, hw_limits: limits, info_flags: info_flags, pcm_pause: pause, pcm_drain: yes, pcm_pointer: no_pointer, cap_pointer: no_pointer,
    config: cfg, pcm_caps: no_caps, cap_caps: caps, period_bytes: period,
    pcm_hw_params: hw_params, pcm_prepare: yes, pcm_trigger: trigger, pcm_hw_free: yes, pcm_submit: submit,
    cap_hw_params: hw_params, cap_prepare: yes, cap_trigger: trigger, cap_hw_free: yes, pcm_recv: recv,
};

static NO_PCM_OPS: ops::SoundOps = ops::SoundOps {
    identity: ident, hw_limits: limits, info_flags: info_flags, pcm_pause: pause, pcm_drain: yes, pcm_pointer: no_pointer, cap_pointer: no_pointer,
    config: cfg, pcm_caps: no_caps, cap_caps: no_caps, period_bytes: period,
    pcm_hw_params: hw_params, pcm_prepare: yes, pcm_trigger: trigger, pcm_hw_free: yes, pcm_submit: submit,
    cap_hw_params: hw_params, cap_prepare: yes, cap_trigger: trigger, cap_hw_free: yes, pcm_recv: recv,
};

static FAIL_STOP_FREE_OPS: ops::SoundOps = ops::SoundOps {
    identity: ident, hw_limits: limits, info_flags: info_flags, pcm_pause: pause, pcm_drain: yes, pcm_pointer: no_pointer, cap_pointer: no_pointer,
    config: cfg, pcm_caps: caps, cap_caps: caps, period_bytes: period,
    pcm_hw_params: hw_params, pcm_prepare: yes, pcm_trigger: fail_trigger, pcm_hw_free: no, pcm_submit: submit,
    cap_hw_params: hw_params, cap_prepare: yes, cap_trigger: fail_trigger, cap_hw_free: no, pcm_recv: recv,
};

static ROUTE_OPS: ops::SoundOps = ops::SoundOps {
    identity: ident, hw_limits: limits, info_flags: info_flags, pcm_pause: pause, pcm_drain: yes, pcm_pointer: no_pointer, cap_pointer: no_pointer,
    config: route_cfg, pcm_caps: route_caps, cap_caps: route_caps, period_bytes: route_period,
    pcm_hw_params: route_hw_params, pcm_prepare: route_yes, pcm_trigger: route_trigger, pcm_hw_free: route_yes,
    pcm_submit: route_submit, cap_hw_params: route_hw_params, cap_prepare: route_yes, cap_trigger: route_trigger,
    cap_hw_free: route_yes, pcm_recv: route_recv,
};

fn add_hook(class: &str, name: &str, dt: Option<(u32, u32)>, factory: Option<drv::NodeFactory>) {
    if class == "sound" {
        ADDED.lock().push((String::from(name), dt, factory.is_some()));
    }
}

fn del_hook(name: &str) {
    REMOVED.lock().push(String::from(name));
}

fn has_node(nodes: &[(String, Option<(u32, u32)>, bool)], name: &str, dev_t: (u32, u32)) -> bool {
    nodes.iter().any(|node| node == &(String::from(name), Some(dev_t), true))
}

fn has_name(nodes: &[(String, Option<(u32, u32)>, bool)], name: &str) -> bool {
    nodes.iter().any(|node| node.0 == name)
}

fn test_err(e: syscall::errno::Errno) -> i64 { -(e.as_i32() as i64) }
fn put_u32(buf: &mut [u8], off: usize, value: u32) { buf[off..off + 4].copy_from_slice(&value.to_le_bytes()); }
fn put_u64(buf: &mut [u8], off: usize, value: u64) { buf[off..off + 8].copy_from_slice(&value.to_le_bytes()); }
fn get_u64(buf: &[u8], off: usize) -> u64 { u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()) }
fn key(raw: u32) -> crate::SoundOwnerKey { crate::SoundOwnerKey::from_raw(raw).unwrap() }

mod identity;
mod pcm_info;


#[path = "sound_tests.rs"]
mod behavior;
