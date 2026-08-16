#![no_std]
extern crate alloc;

// Module manifest:
// - `cards`: card-number reservation, publication, teardown.
// - `device`: /dev/snd and OSS inode/node routing, shared file ops.
// - `format`: ALSA sample-format/rate math shared by every card driver.
// - `identity`: driver-supplied card identity strings in ALSA field widths.
// - `elem`: driver-registered control (mixer/jack) element registry.
// - `pcm_info`: the one writer for `struct snd_pcm_info`.
// - `pcm`,`capture`,`control`,`oss`,`ops`,`uapi`: ALSA/OSS functional groups.
// - `tests`: sound-crate integration tests for publication and routing.

mod cards;
mod device;
mod ids;
mod pcm_info;
pub mod uapi;
pub mod format;
pub mod identity;
pub mod elem;
pub mod ops;
mod pcm;
mod capture;
pub mod control;
mod oss;

pub use cards::{cancel_card_reservation, card_number, owner, register_card, reserve_card, unregister_card, SoundOwnerKey};
pub use device::handle_ioctl;
pub use identity::CardIdentity;

#[cfg(test)]
mod tests;
