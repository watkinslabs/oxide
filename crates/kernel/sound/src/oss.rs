// Module manifest:
// - `oss_state`: owner-keyed OSS runtime registry and lazy-arm flags.
// - `oss_params`: format/rate/caps/fragment geometry helpers.
// - `oss_ioctl`: `/dev/dsp` and `/dev/mixer` data path + ioctl handling.
// - inline tests: OSS fragment/reset behavior.

#[path = "oss_state.rs"] mod oss_state;
#[path = "oss_params.rs"] mod oss_params;
#[path = "oss_ioctl.rs"] mod oss_ioctl;

pub(crate) use oss_state::{register_card, unregister_card};
#[cfg(test)] pub(crate) use oss_state::{has_card, registered_count};
pub use oss_ioctl::{handle, read, write};

#[cfg(test)]
#[path = "oss/tests.rs"]
mod tests;
