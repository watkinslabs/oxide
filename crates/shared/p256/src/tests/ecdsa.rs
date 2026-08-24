//! ECDSA verification against an independent P-256 signing vector.

use super::hex;
use crate::ecdsa::verify;

const PUB: &str = "97d8fc5f593cc5f1411e884b0b439b14e23cc7ca2e724dfc141d9c8b2a0f3341528f10a567a55978f2859dd53ecf9bd72bf9b7cfa3b1d88dfc280badb479664c";
const DIGEST: &str = "1bcd38ea151f33f0a658c765545da0180feb4e9d396f63cdaa5b7780208851ed";
const R: &str = "fb7831ad3f61540f0fd66d740164c81ffe7915671cebe67c63803f81bab0ec5e";
const S: &str = "9f86d817599f04724628c29e27edd115cb0f30ab50e0da66b3e2cd6f6705b762";

#[test]
fn published_signature_verifies() {
    assert!(verify(&hex::<64>(PUB), &hex::<32>(DIGEST), &hex::<32>(R), &hex::<32>(S)));
}

#[test]
fn changed_digest_is_rejected() {
    let mut digest = hex::<32>(DIGEST);
    digest[0] ^= 1;
    assert!(!verify(&hex::<64>(PUB), &digest, &hex::<32>(R), &hex::<32>(S)));
}

#[test]
fn malformed_public_key_is_rejected() {
    let mut key = hex::<64>(PUB);
    key[0] ^= 1;
    assert!(!verify(&key, &hex::<32>(DIGEST), &hex::<32>(R), &hex::<32>(S)));
}
