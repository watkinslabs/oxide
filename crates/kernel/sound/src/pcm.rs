// Module manifest:
// - `pcm_state`: owner-keyed playback runtime registry.
// - `pcm_refine`: hw_params mask/interval refinement and format/rate helpers.
// - `pcm_ioctl`: playback ioctl/data-path handling built on the shared state.

#[path = "pcm_state.rs"] mod pcm_state;
#[path = "pcm_refine.rs"] mod pcm_refine;
#[path = "pcm_ioctl.rs"] mod pcm_ioctl;

pub(crate) use pcm_state::{register_card, unregister_card};
#[cfg(test)] pub(crate) use pcm_state::{has_card, registered_count};
pub(crate) use pcm_refine::{fmt_alsa_to_virtio, rate_hz_to_enum, refine_params};
pub use pcm_ioctl::{handle, write_bytes};
