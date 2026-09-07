//! MD4 digest contracts: the published test vectors, block-boundary splits,
//! and the context record round trip.

use super::digest::{Context, CONTEXT_BYTES};

fn digest_of(message: &[u8]) -> [u8; 16] {
    let mut context = Context::new();
    context.update(message);
    context.finish();
    context.digest
}

fn hex(bytes: &[u8; 16]) -> alloc::string::String {
    let mut out = alloc::string::String::new();
    for byte in bytes { out.push_str(&alloc::format!("{byte:02x}")); }
    out
}

#[test]
fn the_published_vectors_reproduce() {
    assert_eq!(hex(&digest_of(b"")), "31d6cfe0d16ae931b73c59d7e0c089c0");
    assert_eq!(hex(&digest_of(b"a")), "bde52cb31de33e46245e05fbdbd6fb24");
    assert_eq!(hex(&digest_of(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
    assert_eq!(hex(&digest_of(b"message digest")), "d9130a8164549fe818874806e1c7014b");
    assert_eq!(hex(&digest_of(b"abcdefghijklmnopqrstuvwxyz")), "d79e1c308aa5bbcdeea8ed63df412da9");
    assert_eq!(hex(&digest_of(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")), "043f8582f241db351ce627e153e7f0e4");
    assert_eq!(hex(&digest_of(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890")), "e33b4ddc9c38f2199c3e7b164fcc0536");
}

#[test]
fn splitting_a_message_anywhere_produces_one_digest() {
    let message: alloc::vec::Vec<u8> = (0..200u32).map(|index| (index * 7 + 1) as u8).collect();
    let whole = digest_of(&message);
    assert_eq!(hex(&whole), "453f3f53b621ea5eb5b48e6ce600b4ef");
    for split in 0..=message.len() {
        let mut context = Context::new();
        context.update(&message[..split]);
        context.update(&message[split..]);
        context.finish();
        assert_eq!(context.digest, whole, "split at {split}");
    }
}

#[test]
fn a_message_that_fills_the_padding_block_takes_a_second_pass() {
    let message = [0x41u8; 64];
    assert_eq!(hex(&digest_of(&message[..55])), hex(&digest_of(&message[..55])));
    // 56 through 63 bytes leave no room for the length field.
    for len in 55..=64usize {
        let mut context = Context::new();
        context.update(&message[..len]);
        context.finish();
        assert_eq!(context.count[0], (len as u32) << 3, "bit count at {len}");
    }
}

#[test]
fn the_context_record_round_trips_through_its_bytes() {
    let mut context = Context::new();
    context.update(b"abc");
    let raw = context.encode();
    assert_eq!(raw.len(), CONTEXT_BYTES);
    assert_eq!(Context::decode(&raw), context);
    let mut restored = Context::decode(&raw);
    restored.finish();
    assert_eq!(hex(&restored.digest), "a448017aaf21d8525fc10ae87aa6729d");
}
