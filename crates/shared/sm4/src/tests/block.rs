//! The standard's own worked examples: one block, and the same block encrypted
//! a million times under the same key.

use super::hex;
use crate::Sm4;

/// Key shared by both worked examples.
const EXAMPLE_KEY: &str = "0123456789abcdeffedcba9876543210";

/// Plaintext shared by both worked examples.
const EXAMPLE_PT: &str = "0123456789abcdeffedcba9876543210";

/// Iterations the standard's second worked example runs.
const EXAMPLE2_ITERATIONS: usize = 1_000_000;

#[test]
fn standard_example_single_block() {
    let c = Sm4::new(&hex::<16>(EXAMPLE_KEY));
    let pt = hex::<16>(EXAMPLE_PT);
    let ct = hex::<16>("681edf34d206965e86b3e94f536e4246");
    assert_eq!(c.encrypt(&pt), ct);
}

#[test]
fn standard_example_single_block_round_trip() {
    let c = Sm4::new(&hex::<16>(EXAMPLE_KEY));
    let ct = hex::<16>("681edf34d206965e86b3e94f536e4246");
    assert_eq!(c.decrypt(&ct), hex::<16>(EXAMPLE_PT));
}

#[test]
fn standard_example_million_iterations() {
    let c = Sm4::new(&hex::<16>(EXAMPLE_KEY));
    let mut b = hex::<16>(EXAMPLE_PT);
    for _ in 0..EXAMPLE2_ITERATIONS { c.encrypt_block(&mut b); }
    assert_eq!(b, hex::<16>("595298c7c6fd271f0402f804c33d3f66"));
}

#[test]
fn encrypt_in_place_matches_by_value() {
    let c = Sm4::new(&hex::<16>(EXAMPLE_KEY));
    let mut b = hex::<16>(EXAMPLE_PT);
    let by_value = c.encrypt(&b);
    c.encrypt_block(&mut b);
    assert_eq!(b, by_value);
}
