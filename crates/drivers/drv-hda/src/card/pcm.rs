use super::*;

fn hex4(value: u32, out: &mut [u8; 4]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = DIGITS[((value >> (12 - 4 * index)) & 0xf) as usize];
    }
}

fn identity(owner: sound::SoundOwnerKey) -> sound::CardIdentity {
    let vendor = with_device(owner, |device| device.vendor_id).unwrap_or(0);
    let mut components = [0u8; 13];
    components[..4].copy_from_slice(b"HDA:");
    let mut digits = [0u8; 4];
    hex4(vendor >> 16, &mut digits);
    components[4..8].copy_from_slice(&digits);
    hex4(vendor & 0xffff, &mut digits);
    components[8..12].copy_from_slice(&digits);
    sound::CardIdentity::new(b"HDA", b"HDA-Intel", b"HD-Audio Generic",
                             b"HD-Audio Generic at PCI", b"HD-Audio Generic",
                             &components[..12], b"HD-Audio Analog")
}

fn caps(owner: sound::SoundOwnerKey, playback: bool, device_number: u32) -> sound::ops::Caps {
    with_device(owner, |device| {
        device.hda.pcm_caps(device_number, playback)
    })?
}

fn pcm_caps(owner: sound::SoundOwnerKey) -> sound::ops::Caps { caps(owner, true, 0) }
fn cap_caps(owner: sound::SoundOwnerKey) -> sound::ops::Caps { caps(owner, false, 0) }

fn pcm_devices(owner: sound::SoundOwnerKey) -> u32 {
    with_device(owner, |device| device.hda.pcm_devices()).unwrap_or(0)
}

fn pcm_caps_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> sound::ops::Caps { caps(owner, true, device) }
fn cap_caps_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> sound::ops::Caps {
    caps(owner, false, device)
}

fn hw_limits(_owner: sound::SoundOwnerKey) -> sound::ops::HwLimits {
    (stream::MAX_PERIOD_BYTES, stream::BUFFER_BYTES)
}

fn hw_limits_for(_owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> sound::ops::HwLimits { hw_limits(_owner) }

/// The stream engine can be halted and restarted without losing its ring
/// position, which is exactly what SNDRV_PCM_IOCTL_PAUSE asks for.
fn info_flags(_owner: sound::SoundOwnerKey) -> u32 { sound::uapi::PCM_INFO_PAUSE }
fn info_flags_for(_owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> u32 { info_flags(_owner) }

fn period_bytes(_owner: sound::SoundOwnerKey) -> usize { stream::MAX_PERIOD_BYTES as usize }
fn period_bytes_for(_owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> usize { period_bytes(_owner) }

fn config(_owner: sound::SoundOwnerKey) -> Option<(u32, u32, u32, u32)> { None }

fn pcm_hw_params(owner: sound::SoundOwnerKey, format: u32, rate_hz: u32, channels: u8,
                 period_bytes: u32, _buffer_bytes: u32) -> bool {
    pcm_hw_params_for(owner, 0, format, rate_hz, channels, period_bytes, _buffer_bytes)
}

fn pcm_hw_params_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice,
                     format: u32, rate_hz: u32, channels: u8, period_bytes: u32,
                     _buffer_bytes: u32) -> bool {
    with_device(owner, |state| state.hda.prepare_playback(device, format, rate_hz, channels, period_bytes))
        .unwrap_or(false)
}

fn cap_hw_params(owner: sound::SoundOwnerKey, format: u32, rate_hz: u32, channels: u8,
                 period_bytes: u32, _buffer_bytes: u32) -> bool {
    cap_hw_params_for(owner, 0, format, rate_hz, channels, period_bytes, _buffer_bytes)
}

fn cap_hw_params_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice,
                     format: u32, rate_hz: u32, channels: u8, period_bytes: u32,
                     _buffer_bytes: u32) -> bool {
    with_device(owner, |state| state.hda.prepare_capture(device, format, rate_hz, channels, period_bytes))
        .unwrap_or(false)
}

fn pcm_prepare(owner: sound::SoundOwnerKey) -> bool {
    pcm_prepare_for(owner, 0)
}

fn pcm_prepare_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> bool {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.playback.get_mut(device as usize) else { return false; };
        let regs = device_state.hda.regs;
        stream.stop(&regs);
        stream.write_off = 0;
        stream.laps = 0;
        stream.last_position = 0;
        stream.silence();
        true
    }).unwrap_or(false)
}

fn cap_prepare(owner: sound::SoundOwnerKey) -> bool {
    cap_prepare_for(owner, 0)
}

fn cap_prepare_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> bool {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.capture.get_mut(device as usize) else { return false; };
        let regs = device_state.hda.regs;
        stream.stop(&regs);
        stream.write_off = 0;
        stream.laps = 0;
        stream.last_position = 0;
        true
    }).unwrap_or(false)
}

fn pcm_trigger(owner: sound::SoundOwnerKey, start: bool) -> bool {
    pcm_trigger_for(owner, 0, start)
}

fn pcm_trigger_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice, start: bool) -> bool {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.playback.get_mut(device as usize) else { return false; };
        let regs = device_state.hda.regs;
        if start { stream.start(&regs) } else { stream.stop(&regs) }
        true
    }).unwrap_or(false)
}

fn cap_trigger(owner: sound::SoundOwnerKey, start: bool) -> bool {
    cap_trigger_for(owner, 0, start)
}

fn cap_trigger_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice, start: bool) -> bool {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.capture.get_mut(device as usize) else { return false; };
        let regs = device_state.hda.regs;
        if start { stream.start(&regs) } else { stream.stop(&regs) }
        true
    }).unwrap_or(false)
}

fn pcm_pause(owner: sound::SoundOwnerKey, pause: bool) -> bool {
    pcm_pause_for(owner, 0, pause)
}

fn pcm_pause_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice, pause: bool) -> bool {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.playback.get_mut(device as usize) else { return false; };
        let regs = device_state.hda.regs;
        if pause { stream.pause(&regs) } else { stream.start(&regs) }
        true
    }).unwrap_or(false)
}

/// Wait for the hardware to consume what the ring already holds. # C: O(buffer)
fn pcm_drain(owner: sound::SoundOwnerKey) -> bool {
    pcm_drain_for(owner, 0)
}

fn pcm_drain_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> bool {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.playback.get_mut(device as usize) else { return false; };
        let regs = device_state.hda.regs;
        let size = stream.geometry.buffer_bytes();
        if size == 0 || !stream.running { return true; }
        let deadline = crate::platform::now_ns() + 1_000_000_000;
        while stream.position(&regs) != stream.write_off {
            if crate::platform::now_ns() >= deadline { break; }
            crate::platform::udelay(100);
        }
        true
    }).unwrap_or(false)
}

fn pcm_pointer(owner: sound::SoundOwnerKey) -> Option<u64> {
    pcm_pointer_for(owner, 0)
}

fn pcm_pointer_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> Option<u64> {
    with_device(owner, |device_state| {
        let stream = device_state.hda.playback.get_mut(device as usize)?;
        let regs = device_state.hda.regs;
        Some(stream.frames(&regs))
    })?
}

fn cap_pointer(owner: sound::SoundOwnerKey) -> Option<u64> {
    cap_pointer_for(owner, 0)
}

fn cap_pointer_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> Option<u64> {
    with_device(owner, |device_state| {
        let stream = device_state.hda.capture.get_mut(device as usize)?;
        let regs = device_state.hda.regs;
        Some(stream.frames(&regs))
    })?
}

fn pcm_hw_free(owner: sound::SoundOwnerKey) -> bool {
    pcm_hw_free_for(owner, 0)
}

fn pcm_hw_free_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> bool {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.playback.get_mut(device as usize) else { return false; };
        let regs = device_state.hda.regs;
        stream.stop(&regs);
        device_state.hda.release(device, true);
        true
    }).unwrap_or(false)
}

fn cap_hw_free(owner: sound::SoundOwnerKey) -> bool {
    cap_hw_free_for(owner, 0)
}

fn cap_hw_free_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> bool {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.capture.get_mut(device as usize) else { return false; };
        let regs = device_state.hda.regs;
        stream.stop(&regs);
        device_state.hda.release(device, false);
        true
    }).unwrap_or(false)
}

fn pcm_submit(owner: sound::SoundOwnerKey, bytes: &[u8]) -> usize {
    pcm_submit_for(owner, 0, bytes)
}

fn pcm_submit_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice, bytes: &[u8]) -> usize {
    // A stream in flight is the one path guaranteed to run often, so it is
    // where a jack change is noticed while audio is playing.
    service_jacks(owner);
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.playback.get_mut(device as usize) else { return 0; };
        let regs = device_state.hda.regs;
        stream.write(&regs, bytes)
    }).unwrap_or(0)
}

fn pcm_recv(owner: sound::SoundOwnerKey, out: &mut [u8]) -> usize {
    pcm_recv_for(owner, 0, out)
}

fn pcm_recv_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice, out: &mut [u8]) -> usize {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.capture.get_mut(device as usize) else { return 0; };
        let regs = device_state.hda.regs;
        stream.read(&regs, out)
    }).unwrap_or(0)
}

fn pcm_mmap_frame(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice, capture: bool, offset: u64) -> Option<u64> {
    with_device(owner, |device_state| {
        let stream = if capture { device_state.hda.capture.get(device as usize) }
                     else { device_state.hda.playback.get(device as usize) }?;
        let size = u64::from(stream.geometry.buffer_bytes());
        if offset & (hal::PAGE_SIZE_BYTES - 1) != 0 || offset >= size || size - offset < hal::PAGE_SIZE_BYTES { return None; }
        Some(stream.buffer_pa + offset)
    })?
}

fn pcm_mmap_commit(_owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice, _capture: bool,
                   _appl: u64, hw: u64, _frame_bytes: u32, _buffer_frames: u32) -> Option<u64> { Some(hw) }

/// The sound core's view of this card. # C: O(1)
pub static SOUND_OPS: sound::ops::SoundOps = sound::ops::SoundOps {
    identity,
    config,
    pcm_caps,
    cap_caps,
    hw_limits,
    info_flags,
    period_bytes,
    pcm_hw_params,
    pcm_prepare,
    pcm_trigger,
    pcm_pause,
    pcm_drain,
    pcm_pointer,
    pcm_hw_free,
    pcm_submit,
    cap_hw_params,
    cap_prepare,
    cap_trigger,
    cap_pointer,
    cap_hw_free,
    pcm_recv,
};

/// Per-PCM-device operations. The legacy table above remains the device-zero
/// compatibility surface for OSS; ALSA nodes use this table so every route
/// owns an independent stream descriptor and converter binding.
pub static PCM_DEVICE_OPS: sound::ops::PcmDeviceOps = sound::ops::PcmDeviceOps {
    pcm_devices,
    pcm_caps: pcm_caps_for,
    cap_caps: cap_caps_for,
    hw_limits: hw_limits_for,
    info_flags: info_flags_for,
    period_bytes: period_bytes_for,
    pcm_hw_params: pcm_hw_params_for,
    pcm_prepare: pcm_prepare_for,
    pcm_trigger: pcm_trigger_for,
    pcm_pause: pcm_pause_for,
    pcm_drain: pcm_drain_for,
    pcm_pointer: pcm_pointer_for,
    pcm_hw_free: pcm_hw_free_for,
    pcm_submit: pcm_submit_for,
    cap_hw_params: cap_hw_params_for,
    cap_prepare: cap_prepare_for,
    cap_trigger: cap_trigger_for,
    cap_pointer: cap_pointer_for,
    cap_hw_free: cap_hw_free_for,
    pcm_recv: pcm_recv_for,
    pcm_mmap_frame,
    pcm_mmap_commit,
};


