//! Key agreement against the published vector, key validation refusals, and
//! the debug key pair the pairing specification publishes for its secure
//! connections mode.

use super::{hex, rev};
use crate::ecdh::{ECDH_COORD_LEN, ECDH_PUBKEY_LEN, PublicKey, SecretKey};

fn pubkey(x: &str, y: &str) -> [u8; ECDH_PUBKEY_LEN] {
    let mut b = [0u8; ECDH_PUBKEY_LEN];
    b[..ECDH_COORD_LEN].copy_from_slice(&hex::<ECDH_COORD_LEN>(x));
    b[ECDH_COORD_LEN..].copy_from_slice(&hex::<ECDH_COORD_LEN>(y));
    b
}

// The published key-agreement known-answer vector: one side's private key,
// the public key it must generate, the peer public key, and the shared x
// coordinate. Coordinates and scalars are big-endian.
const A_PRIV: &str = "24d121ebe5cf2d83f6621b6e43843aa38be086c32019da92505303e1c0eab882";
const A_PUB_X: &str = "1a7feb5200bd3c317db670c186a6c7c43bc55f6c6f583cf5b66382773324a15f";
const A_PUB_Y: &str = "6aca436ff77eff023708cc405e7afd6a6a026e4187683877faa944432def09df";
const B_PUB_X: &str = "ccb4da74b1473fea6c709e382dc7aab729b2470319abdd34bda82c93e1a474d9";
const B_PUB_Y: &str = "6463f770202fa4e69f4a38ccc02c492fb132bbaf2261dacb6fdba9aafc7781f3";
const SHARED_X: &str = "ea176f7e6e5726388bfb41ebbac86da5a872d1ffc9473daa58439f340f8cf3c9";

#[test]
fn published_public_key() {
    let a = SecretKey::from_entropy(&hex::<ECDH_COORD_LEN>(A_PRIV)).unwrap();
    assert_eq!(a.public_key().to_bytes(), pubkey(A_PUB_X, A_PUB_Y));
}

#[test]
fn published_shared_secret() {
    let a = SecretKey::from_entropy(&hex::<ECDH_COORD_LEN>(A_PRIV)).unwrap();
    let b = PublicKey::from_bytes(&pubkey(B_PUB_X, B_PUB_Y)).unwrap();
    assert_eq!(a.diffie_hellman(&b).unwrap().0, hex::<ECDH_COORD_LEN>(SHARED_X));
}

#[test]
fn agreement_is_symmetric() {
    // Two locally generated keys must reach the same secret from either side,
    // which the one-sided vector above cannot show.
    let a = SecretKey::from_entropy(&hex::<ECDH_COORD_LEN>(A_PRIV)).unwrap();
    let c = SecretKey::from_entropy(&hex::<ECDH_COORD_LEN>(
        "c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53")).unwrap();
    assert_eq!(a.diffie_hellman(&c.public_key()).unwrap(),
               c.diffie_hellman(&a.public_key()).unwrap());
}

#[test]
fn private_key_round_trips() {
    let b = hex::<ECDH_COORD_LEN>(A_PRIV);
    assert_eq!(SecretKey::from_entropy(&b).unwrap().to_bytes(), b);
}

// The pairing specification publishes a fixed key pair so a debugging tool can
// read a secure-connections exchange. Its private key must generate its
// published public key. Both are printed least-significant-byte-first there,
// which is the reversal this crate's callers perform at their own edge.
const DEBUG_SK_LSB: &str = "bd1a3ccda6b8995899b740eb7b60ff4a503f10d2e3b3c974385fc5a3d4f6493f";
const DEBUG_PK_X_LSB: &str = "e69d350e480103ccdbfdf4ac1191f4efb9a5f9e9a7832c5e2cbe97f2d203b020";
const DEBUG_PK_Y_LSB: &str = "8bd28915d08e1c742430ed8fc24563765c15525abf9a32636deb2a65499c80dc";

#[test]
fn specification_debug_key_pair() {
    let sk = SecretKey::from_entropy(&rev(hex::<ECDH_COORD_LEN>(DEBUG_SK_LSB))).unwrap();
    let expect = pubkey_from_lsb(DEBUG_PK_X_LSB, DEBUG_PK_Y_LSB);
    assert_eq!(sk.public_key().to_bytes(), expect);
    assert!(PublicKey::from_bytes(&expect).is_some());
}

fn pubkey_from_lsb(x: &str, y: &str) -> [u8; ECDH_PUBKEY_LEN] {
    let mut b = [0u8; ECDH_PUBKEY_LEN];
    b[..ECDH_COORD_LEN].copy_from_slice(&rev(hex::<ECDH_COORD_LEN>(x)));
    b[ECDH_COORD_LEN..].copy_from_slice(&rev(hex::<ECDH_COORD_LEN>(y)));
    b
}

#[test]
fn a_key_off_the_curve_is_refused() {
    // Valid x, y taken from the same coordinate: not a curve point.
    let bad = pubkey(A_PUB_X, A_PUB_X);
    assert!(PublicKey::from_bytes(&bad).is_none());
}

#[test]
fn a_flipped_bit_is_refused() {
    let mut b = pubkey(A_PUB_X, A_PUB_Y);
    b[ECDH_PUBKEY_LEN - 1] ^= 1;
    assert!(PublicKey::from_bytes(&b).is_none());
}

#[test]
fn a_coordinate_at_or_above_the_prime_is_refused() {
    let p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
    let all_ones = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    assert!(PublicKey::from_bytes(&pubkey(p, A_PUB_Y)).is_none());
    assert!(PublicKey::from_bytes(&pubkey(A_PUB_X, p)).is_none());
    assert!(PublicKey::from_bytes(&pubkey(all_ones, A_PUB_Y)).is_none());
}

#[test]
fn the_all_zero_encoding_is_refused() {
    assert!(PublicKey::from_bytes(&[0u8; ECDH_PUBKEY_LEN]).is_none());
}

#[test]
fn a_valid_key_round_trips() {
    let b = pubkey(A_PUB_X, A_PUB_Y);
    assert_eq!(PublicKey::from_bytes(&b).unwrap().to_bytes(), b);
}

#[test]
fn private_key_range_is_enforced() {
    let zero = [0u8; ECDH_COORD_LEN];
    assert!(SecretKey::from_entropy(&zero).is_none());
    let n = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    assert!(SecretKey::from_entropy(&hex::<ECDH_COORD_LEN>(n)).is_none());
    let n_minus_1 = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550";
    assert!(SecretKey::from_entropy(&hex::<ECDH_COORD_LEN>(n_minus_1)).is_some());
    let one = "0000000000000000000000000000000000000000000000000000000000000001";
    assert!(SecretKey::from_entropy(&hex::<ECDH_COORD_LEN>(one)).is_some());
    let all_ones = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    assert!(SecretKey::from_entropy(&hex::<ECDH_COORD_LEN>(all_ones)).is_none());
}
