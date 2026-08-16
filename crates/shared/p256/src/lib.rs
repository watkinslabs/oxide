#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! NIST P-256 (secp256r1) scalar arithmetic and ECDH.
//!
//! Module manifest:
//! - `params`: the field prime, the group order, the curve constants and the
//!   base point, all in the Montgomery representation the field uses.
//! - `field`: arithmetic modulo the field prime, Montgomery form, branch-free.
//! - `point`: projective points and the complete addition law, which has no
//!   exceptional cases so no input can steer it down a different path.
//! - `scalar`: the constant-time double-and-add-always ladder.
//! - `ecdh`: key validation, key generation from caller-supplied entropy, and
//!   the shared secret.
//!
//! Byte order at this boundary is big-endian — the order the curve standards
//! print coordinates in. A protocol that carries them least-significant-first
//! reverses at its own edge.
//!
//! Timing: the ladder performs the same operation sequence for every scalar,
//! the field operations are branch-free, and selection is by arithmetic mask.
//! Field inversion is a fixed addition chain over the public exponent.

pub mod params;
pub mod field;
pub mod point;
pub mod scalar;
pub mod ecdh;

pub use ecdh::{PublicKey, SecretKey, SharedSecret, ECDH_COORD_LEN, ECDH_PUBKEY_LEN};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
