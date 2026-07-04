use core::sync::atomic::Ordering;

use virtio::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};

use crate::{
    active_ctx, active_ctx_for, active_ctx_mut, active_ctx_mut_for, submit_ctl, Ctx, PcmState,
    CTX, PLAYBACK_RATE_HZ, REQ_OFF, SND_HDR_SIZE, TX_POLL_BUDGET, VIRTIO_SND_PCM_FMT_S16,
    VIRTIO_SND_PCM_FMT_U16, VIRTIO_SND_PCM_RATE_44100, VIRTIO_SND_R_PCM_PREPARE,
    VIRTIO_SND_R_PCM_RELEASE, VIRTIO_SND_R_PCM_SET_PARAMS, VIRTIO_SND_R_PCM_START,
    VIRTIO_SND_R_PCM_STOP, VIRTIO_SND_S_OK,
};

mod accessors;
pub use accessors::{
    cap_caps, cap_frame_size, cap_state, capture_ready, configured, frame_size, input_stream,
    output_stream, pcm_caps, pcm_state, period_bytes, playback_ready,
};

mod playback;
pub use playback::{beep, beep_diag, pcm_hw_free, pcm_hw_params, pcm_prepare, pcm_submit, pcm_trigger};
pub(crate) use playback::{pcm_ctl, PERIOD_BYTES};

mod capture;
pub use capture::{cap_hw_free, cap_hw_params, cap_prepare, cap_trigger, pcm_recv};
