use super::*;

pub(super) fn frame_bytes(format: u8, channels: u8) -> usize {
    let bps = match format {
        VIRTIO_SND_PCM_FMT_S16 | VIRTIO_SND_PCM_FMT_U16 => 2,
        _ => 1,
    };
    bps * channels.max(1) as usize
}

pub fn output_stream() -> Option<u32> { active_ctx(&CTX.lock()).and_then(|c| c.out_stream) }

pub fn pcm_caps(owner: u32) -> Option<(u64, u64, u8, u8)> {
    active_ctx_for(&CTX.lock(), owner).and_then(|c| {
        c.out_stream?;
        Some((c.out_formats, c.out_rates, c.out_ch_min, c.out_ch_max))
    })
}

pub fn period_bytes(_owner: u32) -> usize { PERIOD_BYTES }

pub fn playback_ready() -> (bool, bool, bool) {
    let g = CTX.lock();
    match active_ctx(&g) {
        Some(c) => (true, c.out_stream.is_some(), c.txq.is_some()),
        None => (false, false, false),
    }
}

pub fn pcm_state() -> PcmState {
    active_ctx(&CTX.lock()).map(|c| c.pcm_state).unwrap_or(PcmState::Idle)
}

pub fn configured() -> Option<(u8, u8, u8, u32)> {
    active_ctx(&CTX.lock()).map(|c| (c.cfg_rate, c.cfg_format, c.cfg_channels, c.cfg_period_bytes))
}

pub fn frame_size() -> usize {
    active_ctx(&CTX.lock()).map(|c| frame_bytes(c.cfg_format, c.cfg_channels)).unwrap_or(4)
}

pub fn cap_caps(owner: u32) -> Option<(u64, u64, u8, u8)> {
    active_ctx_for(&CTX.lock(), owner).and_then(|c| {
        c.in_stream?;
        Some((c.in_formats, c.in_rates, c.in_ch_min, c.in_ch_max))
    })
}

pub fn input_stream() -> Option<u32> { active_ctx(&CTX.lock()).and_then(|c| c.in_stream) }

pub fn cap_state() -> PcmState {
    active_ctx(&CTX.lock()).map(|c| c.cap_state).unwrap_or(PcmState::Idle)
}

pub fn capture_ready() -> (bool, bool, bool) {
    let g = CTX.lock();
    match active_ctx(&g) {
        Some(c) => (true, c.in_stream.is_some(), c.rxq.is_some()),
        None => (false, false, false),
    }
}

pub fn cap_frame_size() -> usize {
    active_ctx(&CTX.lock()).map(|c| frame_bytes(c.cap_format, c.cap_channels)).unwrap_or(4)
}
