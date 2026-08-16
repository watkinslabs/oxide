//! Key validation, key generation and the shared secret.
//!
//! Entropy is a parameter, never fetched from a global source: a caller that
//! knows which pool a key must come from is the only one that can be right
//! about it, and a test needs to supply a known value.

use crate::field::Fp;
use crate::params::ELEM_LEN;
use crate::point::{Affine, Point};
use crate::scalar::{Scalar, mul, mul_base};

/// Bytes in one serialised coordinate.
pub const ECDH_COORD_LEN: usize = ELEM_LEN;

/// Bytes in an uncompressed public key: the two coordinates, no prefix.
pub const ECDH_PUBKEY_LEN: usize = 2 * ECDH_COORD_LEN;

/// A validated peer or local public key.
#[derive(Copy, Clone, Debug)]
pub struct PublicKey(Affine);

/// A private scalar known to be a usable key.
#[derive(Copy, Clone, Debug)]
pub struct SecretKey(Scalar);

/// The x coordinate of the shared point, big-endian.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SharedSecret(pub [u8; ECDH_COORD_LEN]);

impl PublicKey {
    /// Validate an uncompressed key: both coordinates must be reduced
    /// residues and the pair must satisfy the curve equation. A point not on
    /// the curve, or on a different curve sharing the equation's shape, is an
    /// invalid-curve attack and is refused here rather than fed to the ladder.
    /// The identity has no such encoding and fails the equation. # C: O(1)
    pub fn from_bytes(b: &[u8; ECDH_PUBKEY_LEN]) -> Option<PublicKey> {
        let mut xb = [0u8; ECDH_COORD_LEN];
        let mut yb = [0u8; ECDH_COORD_LEN];
        xb.copy_from_slice(&b[..ECDH_COORD_LEN]);
        yb.copy_from_slice(&b[ECDH_COORD_LEN..]);
        let x = Fp::from_bytes_be(&xb)?;
        let y = Fp::from_bytes_be(&yb)?;
        let a = Affine { x, y };
        if !a.on_curve() { return None; }
        Some(PublicKey(a))
    }

    /// Serialise as the two coordinates, big-endian. # C: O(1)
    pub fn to_bytes(&self) -> [u8; ECDH_PUBKEY_LEN] {
        let mut out = [0u8; ECDH_PUBKEY_LEN];
        out[..ECDH_COORD_LEN].copy_from_slice(&self.0.x_bytes());
        out[ECDH_COORD_LEN..].copy_from_slice(&self.0.y_bytes());
        out
    }

    /// The affine point behind the key. # C: O(1)
    pub fn affine(&self) -> &Affine { &self.0 }
}

impl SecretKey {
    /// Take 32 bytes of caller-supplied entropy as a private key, refusing a
    /// value outside the usable range. Refusal means "draw again": that is the
    /// rejection sampling the key-generation standard specifies, and reducing
    /// instead would bias the key. # C: O(1)
    pub fn from_entropy(b: &[u8; ECDH_COORD_LEN]) -> Option<SecretKey> {
        let k = Scalar::from_bytes_be(b);
        if !k.in_range() { return None; }
        Some(SecretKey(k))
    }

    /// The private scalar, big-endian. # C: O(1)
    pub fn to_bytes(&self) -> [u8; ECDH_COORD_LEN] { self.0.to_bytes_be() }

    /// The matching public key. # C: O(1)
    pub fn public_key(&self) -> PublicKey {
        let p = mul_base(&self.0);
        // A key in range never multiplies the base point to the identity, so
        // the affine form always exists.
        PublicKey(p.to_affine().unwrap_or(Affine { x: Fp::zero(), y: Fp::zero() }))
    }

    /// The shared secret with a peer key: the x coordinate of the product.
    /// `None` when the product is the identity, which a validated peer key on
    /// a prime-order curve cannot produce. # C: O(1)
    pub fn diffie_hellman(&self, peer: &PublicKey) -> Option<SharedSecret> {
        let p = mul(&self.0, &Point::from_affine(&peer.0));
        let a = p.to_affine()?;
        Some(SharedSecret(a.x_bytes()))
    }
}
