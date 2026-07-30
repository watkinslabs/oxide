#[cfg(not(target_os = "oxide-kernel"))]
use core::sync::atomic::{AtomicU64, Ordering};

use crate::packet::InputValue;
use crate::registry::VirtioInputDev;
use crate::uapi::{
    EV_KEY, EV_REP, KEY_RELEASED, KEY_REPEAT, REP_DELAY, REP_PERIOD,
};
const MSEC_NS: u64 = 1_000_000;

#[cfg(not(target_os = "oxide-kernel"))]
static HOST_NOW_NS: AtomicU64 = AtomicU64::new(0);

fn now_ns() -> u64 {
    #[cfg(target_os = "oxide-kernel")]
    {
        timekeeper::monotonic_ns()
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
        HOST_NOW_NS.load(Ordering::Relaxed)
    }
}

fn repeat_arg(dev: &VirtioInputDev) -> usize {
    ((dev.input_id as u64) << 32 | u64::from(dev.device_key.raw())) as usize
}

fn repeat_identity(arg: usize) -> (virtio::VirtioChildDeviceKey, u32) {
    let raw = arg as u64;
    (
        virtio::VirtioChildDeviceKey::from_raw(raw as u32),
        (raw >> 32) as u32,
    )
}

fn state_bit(bits: &[u8], code: u16) -> bool {
    let code = code as usize;
    bits.get(code / 8).is_some_and(|byte| byte & (1u8 << (code % 8)) != 0)
}

fn repeat_enabled(dev: &VirtioInputDev) -> bool {
    state_bit(&dev.ev_bits, EV_REP)
        && dev.repeat[REP_DELAY as usize] != 0
        && dev.repeat[REP_PERIOD as usize] != 0
}

fn arm(dev: &mut VirtioInputDev, delay_ms: u32) {
    disarm(dev);
    if delay_ms == 0 { return; }
    let deadline = now_ns().saturating_add(u64::from(delay_ms).saturating_mul(MSEC_NS));
    dev.repeat_timer = Some(timer::register_oneshot(deadline, repeat_arg(dev), repeat_fire));
}

fn disarm(dev: &mut VirtioInputDev) {
    if let Some(id) = dev.repeat_timer.take() {
        let _ = timer::unregister_oneshot(id);
    }
}

/// # C: O(packet values)
pub(crate) fn accepted_packet(dev: &mut VirtioInputDev, values: &[InputValue]) {
    for value in values {
        if value.ev_type != EV_KEY || value.value == KEY_REPEAT { continue; }
        if value.value == KEY_RELEASED {
            if dev.repeat_key == Some(value.code) {
                cancel(dev);
            }
        } else if repeat_enabled(dev) {
            dev.repeat_key = Some(value.code);
            arm(dev, dev.repeat[REP_DELAY as usize]);
        }
    }
}

/// # C: O(1)
pub(crate) fn cancel(dev: &mut VirtioInputDev) {
    disarm(dev);
    dev.repeat_key = None;
}

fn repeat_fire(arg: usize) {
    let (device_key, input_id) = repeat_identity(arg);
    let dispatch = {
        let mut devices = crate::registry::DEVICES.lock();
        let Some(dev) = devices.iter_mut().find(|dev| {
            dev.device_key == device_key && dev.input_id == input_id
        }) else {
            return;
        };
        dev.repeat_timer = None;
        let Some(code) = dev.repeat_key else { return; };
        if !state_bit(&dev.key_state.bits, code) { return; }
        let Some(accepted) = dev.accept_event(EV_KEY, code, KEY_REPEAT) else { return; };
        let _ = dev.stage_accepted(EV_KEY, code, accepted);
        let values = dev.flush_synthetic_report().unwrap_or_default();
        let dispatch = (dev.evdev_id, dev.is_pointer, values);
        let period = dev.repeat[REP_PERIOD as usize];
        if period != 0 {
            arm(dev, period);
        }
        dispatch
    };
    crate::registry::dispatch_values(dispatch.0, dispatch.1, &dispatch.2);
}

#[cfg(test)]
/// # C: O(1)
pub(crate) fn set_now_for_tests(now_ns: u64) {
    HOST_NOW_NS.store(now_ns, Ordering::Relaxed);
}
