// HMAC-SHA-512 against the published test vectors (RFC 4231 §4.2-§4.7).
//
// The long-key cases are the ones that matter: they are the only vectors that
// distinguish hashing an over-length key from truncating it, and the only ones
// that fail if the key is padded to the digest width instead of the block.

use super::{hmac_sha512, HmacSha512};

/// Bytes of a hex literal, so a vector reads as it is published. # C: O(n)
fn hex<const N: usize>(s: &str) -> [u8; N] {
    let b = s.as_bytes();
    assert_eq!(b.len(), 2 * N, "hex literal is the wrong width");
    let d = |c: u8| -> u8 {
        match c { b'0'..=b'9' => c - b'0', b'a'..=b'f' => c - b'a' + 10, _ => panic!("hex") }
    };
    let mut out = [0u8; N];
    for i in 0..N { out[i] = (d(b[2 * i]) << 4) | d(b[2 * i + 1]); }
    out
}

fn check(key: &[u8], msg: &[u8], want: &str) {
    assert_eq!(hmac_sha512(key, msg), hex::<64>(want));
}

#[test]
fn rfc4231_case1_twenty_byte_key() {
    check(&[0x0b; 20], b"Hi There",
          "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
}

#[test]
fn rfc4231_case2_short_key() {
    check(b"Jefe", b"what do ya want for nothing?",
          "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
}

#[test]
fn rfc4231_case3_fifty_byte_message() {
    check(&[0xaa; 20], &[0xdd; 50],
          "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39\
bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");
}

#[test]
fn rfc4231_case4_counting_key() {
    let key: [u8; 25] = hex("0102030405060708090a0b0c0d0e0f10111213141516171819");
    check(&key, &[0xcd; 50],
          "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db\
a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd");
}

/// The key is 131 bytes — longer than SHA-512's 128-byte block — so it must be
/// replaced by its own digest. Truncation to 128 bytes gives a different MAC.
#[test]
fn rfc4231_case6_key_longer_than_block_is_hashed() {
    check(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First",
          "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");
}

#[test]
fn rfc4231_case7_long_key_and_long_message() {
    let msg: &[u8] = b"This is a test using a larger than block-size key and \
a larger than block-size data. The key needs to be hashed before being used by \
the HMAC algorithm.";
    assert_eq!(msg.len(), 152);
    check(&[0xaa; 131], msg,
          "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944\
b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58");
}

/// Streaming in pieces is the same MAC as one contiguous message — the shape
/// HKDF needs, since it feeds the info string in fragments.
#[test]
fn streaming_pieces_equal_one_message() {
    let k = HmacSha512::new(b"a key");
    let mut c = k.start();
    c.update(b"abc");
    c.update(b"");
    c.update(b"defgh");
    assert_eq!(c.finish(), k.mac(b"abcdefgh"));
}
