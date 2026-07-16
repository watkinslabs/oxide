#![no_std]
extern crate alloc;

// Module manifest:
// - `cards`: card-number reservation, publication, teardown.
// - `device`: /dev/snd and OSS inode/node routing, shared file ops.
// - `pcm`,`capture`,`control`,`oss`,`ops`,`uapi`: ALSA/OSS functional groups.
// - `tests`: sound-crate integration tests for publication and routing.

mod cards;
mod device;
mod ids;
mod uapi;
pub mod ops;
mod pcm;
mod capture;
mod control;
mod oss;

pub use cards::{cancel_card_reservation, card_number, owner, register_card, reserve_card, unregister_card, SoundOwnerKey};
pub use device::handle_ioctl;

#[cfg(test)]
mod tests;
