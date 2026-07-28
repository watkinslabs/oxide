// SipHash-2-4, the keyed short-input PRF. Port of Linux `lib/siphash.c` +
// `include/linux/siphash.h` (Jason A. Donenfeld), byte-for-byte compatible:
// the same key and input produce the same 64-bit output as the kernel's.
//
// Module manifest:
//   `permute` — the ARX round, the four IV constants, preamble/postamble.
//   `bytes`   — `siphash(&[u8], &Key)` over an arbitrary buffer.
//   `words`   — the `siphash_Nu64` / `siphash_Nu32` fixed-arity fast paths.
//
// Why a keyed PRF and not a plain hash: every consumer here (TCP initial
// sequence numbers, ephemeral-port offsets) must be unpredictable to an
// off-path attacker who knows the *input* — the 4-tuple is public. An unkeyed
// hash of public data is public. Security rests entirely on the key staying
// secret, so keys come from `crng` and never from a clock or a counter.
//
// Not a hashtable hash. `hsiphash`/SipHash-1-3 are deliberately absent: they
// are the "insecure PRF, hashtable use only" half of the Linux file, and
// offering them next to this one invites a security consumer to pick the
// cheap one by mistake.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

mod bytes;
mod permute;
mod words;

pub use bytes::siphash;
pub use permute::Key;
pub use words::{siphash_1u32, siphash_1u64, siphash_2u32, siphash_2u64, siphash_3u32,
                siphash_3u64, siphash_4u32, siphash_4u64};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
