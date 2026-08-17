// Inline encryption tests.
//
// - `dun`      — the counter and the contiguity rule the merge decision rests on.
// - `key`      — what makes a key valid, per kind.
// - `profile`  — capability claims, keyslots, and the wrapped-key refusals.
// - `medium`   — what actually lands on the device. The load-bearing one.

#[path = "tests/dun.rs"] mod dun;
#[path = "tests/key.rs"] mod key;
#[path = "tests/profile.rs"] mod profile;
#[path = "tests/medium.rs"] mod medium;

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::crypto::key::{Key, KeyType};
use crate::crypto::mode::Mode;

/// A raw key of the mode's exact size, filled with a recognisable pattern.
/// # C: O(key size)
pub fn raw_key(mode: Mode, seed: u8, dus: u32) -> Arc<Key> {
    let bytes: Vec<u8> =
        (0..mode.params().key_size).map(|i| seed.wrapping_add(i as u8).wrapping_mul(7)).collect();
    Arc::new(Key::new(&bytes, KeyType::Raw, mode, 8, dus).unwrap())
}
