// `KEYCTL_DH_COMPUTE`: which keys it will read, what it refuses, and the
// arithmetic itself against known answers.
//
// The vectors use the published 1536-bit MODP group (RFC 3526 group 5) with
// generator 2 — the smallest modulus this command accepts, so it also pins the
// lower bound.

use super::*;
use super::super::ops::dh;
use super::super::ops::*;

/// RFC 3526 §2, the 1536-bit MODP group prime, as the 192 raw payload bytes a
/// `user` key would hold.
fn modp_1536_p() -> Vec<u8> { unhex(concat!(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74",
    "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437",
    "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed",
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05",
    "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb",
    "9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff")) }

fn unhex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    (0..b.len() / 2).map(|i| nyb(b[i * 2]) << 4 | nyb(b[i * 2 + 1])).collect()
}
fn nyb(c: u8) -> u8 { if c.is_ascii_digit() { c - b'0' } else { c - b'a' + 10 } }
fn hexed(b: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::new();
    for x in b { let _ = write!(s, "{x:02x}"); }
    s
}

/// Add a `user` key holding `payload` and return its serial.
fn user_key(t: &Ctx, desc: &str, payload: Vec<u8>) -> i32 {
    add_key_core(t, "user", desc, payload, true, KEY_SPEC_SESSION_KEYRING) as i32
}

// The three inputs come out of `user` keys the caller can read.
#[test]
fn reads_the_payload_of_a_user_key() {
    let t = ctx(1700, 7700);
    join_session(&t, None);
    let k = user_key(&t, "dh-prime", alloc::vec![1, 2, 3, 4]);
    assert_eq!(dh::dh_data_from_key(&t, k), Ok(alloc::vec![1, 2, 3, 4]));
}

// A serial that names no key is ENOKEY, and so is a key the caller may not
// read: this command never says WHY an input is unusable.
#[test]
fn unusable_input_key_is_enokey() {
    let t = ctx(1701, 7701);
    join_session(&t, None);
    assert_eq!(dh::dh_data_from_key(&t, 0x7fff_0000), Err(enokey()));
    let k = user_key(&t, "dh-secret", alloc::vec![9]);
    force_perm(k, 0);
    assert_eq!(dh::dh_data_from_key(&t, k), Err(enokey()), "no read permission is not distinguishable");
}

// A revoked or expired input key is ENOKEY too — the state error is collapsed
// by the same lookup.
#[test]
fn revoked_input_key_is_enokey() {
    let t = ctx(1702, 7702);
    join_session(&t, None);
    let k = user_key(&t, "dh-revoked", alloc::vec![9]);
    assert_eq!(revoke_core(&t, k), 0);
    assert_eq!(dh::dh_data_from_key(&t, k), Err(enokey()));
}

// A key of the wrong TYPE is EOPNOTSUPP, not ENOKEY: it exists and the caller
// may read it, it simply cannot supply a number. A keyring reads out as its
// member list and a `logon` payload is write-only.
#[test]
fn wrong_key_type_is_eopnotsupp() {
    let t = ctx(1703, 7703);
    let sess = join_session(&t, None) as i32;
    assert_eq!(dh::dh_data_from_key(&t, sess), Err(err(Errno::Eopnotsupp)));
    let l = add_key_core(&t, "logon", "svc:dh", alloc::vec![1, 2], true, KEY_SPEC_SESSION_KEYRING) as i32;
    force_perm(l, KEY_POS_ALL | KEY_USR_ALL);
    assert_eq!(dh::dh_data_from_key(&t, l), Err(err(Errno::Eopnotsupp)));
}

// Parameter admission. Every one of these is EINVAL, and each rejects a
// distinct way of asking for a computation that is not a key agreement.
#[test]
fn parameter_admission() {
    let p = modp_1536_p();
    let g = alloc::vec![2u8];
    let x = alloc::vec![0x11u8; 32];
    assert_eq!(dh::vet_inputs(&p, &g, &x), Ok(()));

    let short = alloc::vec![0xffu8; 191];
    assert_eq!(dh::vet_inputs(&short, &g, &x), Err(Errno::Einval), "a modulus below 1536 bits");
    let padded = { let mut v = alloc::vec![0u8; 100]; v.extend_from_slice(&alloc::vec![0xffu8; 92]); v };
    assert_eq!(padded.len(), 192);
    assert_eq!(dh::vet_inputs(&padded, &g, &x), Ok(()),
        "the width is counted on the payload as supplied, not on the value");
    assert_eq!(dh::vet_inputs(&alloc::vec![0u8; 192], &g, &x), Err(Errno::Einval), "a zero modulus");
    assert_eq!(dh::vet_inputs(&p, &g, &alloc::vec![7u8; 193]), Err(Errno::Einval),
        "a private value wider than the modulus");
    assert_eq!(dh::vet_inputs(&p, &alloc::vec![7u8; 193], &x), Err(Errno::Einval),
        "a base wider than the modulus");
    let huge = alloc::vec![0xffu8; 2049];
    assert_eq!(dh::vet_inputs(&huge, &huge, &huge), Err(Errno::Einval), "past the import ceiling");
}

// The reported output width is the modulus rounded UP to whole limbs, computed
// on the VALUE — so a modulus sent with leading zero bytes does not inflate the
// answer, and a caller that sized its buffer from the length query has room.
#[test]
fn output_width_is_the_modulus_rounded_to_limbs() {
    assert_eq!(dh::output_len(&modp_1536_p()), 192);
    let mut padded = alloc::vec![0u8; 8];
    padded.extend_from_slice(&modp_1536_p());
    assert_eq!(dh::output_len(&padded), 192, "leading zero bytes carry no value");
    let mut odd = alloc::vec![0xffu8; 193];
    odd[0] = 1;
    assert_eq!(dh::output_len(&odd), 200, "193 bytes occupy 25 whole limbs");
}

// The public value for a known private value, and the agreement property both
// sides depend on.
#[test]
fn known_answer_public_value_and_agreement() {
    let p = modp_1536_p();
    let g = alloc::vec![2u8];
    let xa = unhex("feedface1234");
    let ya = dh::compute(&p, &g, &xa).expect("valid parameters");
    assert_eq!(ya.len(), 192);
    assert_eq!(hexed(&ya), concat!(
        "db3ab3d1d0e9c9dc577e60dbfee37c7c18fe48c67062a11e585a49223a5b7433",
        "82a46bd138a1b91de39b0aafca04859216e31ab4c7bc075fecccaba939e895af",
        "b0c06e4b202c3e18428ce5dfde49d605b3744c72b6be529597bd8714de25196e",
        "9e83ee02f96b529358a49953bab6210741a8490e37206337f914adedfb552bc4",
        "d04d6dfbb191586540b06ca2c498f7009da46d2c44f182757bccb97b33d3555a",
        "f2dc80a72aaa45779510e5630a445ee85adfaea0775a0cd442a71567aeb97b21"));

    // The same call computes the shared secret when the base is the peer's
    // public value rather than the generator — one exponentiation, two uses.
    let xb = unhex("0123456789abcdef0123456789abcdef");
    let yb = dh::compute(&p, &g, &xb).expect("valid parameters");
    assert_eq!(dh::compute(&p, &yb, &xa).expect("valid parameters"),
               dh::compute(&p, &ya, &xb).expect("valid parameters"),
               "both sides derive the same shared secret");
}

// Counter-mode derivation over (shared secret || otherinfo). The counter is a
// 32-bit big-endian value starting at ONE, and the last block is truncated to
// the requested length rather than rounded up.
#[test]
fn known_answer_key_derivation() {
    let p = modp_1536_p();
    let secret = dh::compute(&p, &alloc::vec![2u8], &unhex("feedface1234")).expect("valid parameters");
    let mut z = secret.clone();
    z.extend_from_slice(b"oxide-otherinfo");
    let out = dh::kdf_ctr(crypt::Digest::by_name("sha256").expect("registered"), &z, 40);
    assert_eq!(out.len(), 40);
    assert_eq!(hexed(&out), "b120f5c3434f2c09af557910cb6315bfc433af58c800b18e218276b2c03873b640704176a68ec68c");

    // With no otherinfo the input is the secret alone; a different hash gives a
    // different stream, so the name really selects the algorithm.
    let out = dh::kdf_ctr(crypt::Digest::by_name("sha1").expect("registered"), &secret, 20);
    assert_eq!(hexed(&out), "b043c99a4abb0a1715e3a6380db256bcabe6e32b");

    // A zero-length request derives nothing rather than one whole block.
    assert!(dh::kdf_ctr(crypt::Digest::by_name("sha256").expect("registered"), &z, 0).is_empty());
    // A request shorter than one digest is truncated from the first block.
    let short = dh::kdf_ctr(crypt::Digest::by_name("sha256").expect("registered"), &z, 8);
    assert_eq!(short.len(), 8);
    assert_eq!(hexed(&short), "b120f5c3434f2c09");
}

// The advertised capability bit and the command must agree — a caller that
// probes `KEYCTL_CAPABILITIES` before use is entitled to act on the answer.
#[test]
fn capability_bit_tracks_the_implementation() {
    let caps = super::super::keyctl::keyrings_capabilities();
    assert_eq!(caps.len(), KEYCTL_CAPS_BYTES);
    assert_eq!(caps[0] & KEYCTL_CAPS0_DIFFIE_HELLMAN != 0, dh::SUPPORTED,
        "the reported bit is the implementing module's own answer");
    assert_ne!(caps[0] & KEYCTL_CAPS0_CAPABILITIES, 0);
    // The families still absent keep their bits clear, so probing stays honest
    // in both directions.
    assert_eq!(caps[0] & KEYCTL_CAPS0_PUBLIC_KEY, 0);
    assert_eq!(caps[1] & KEYCTL_CAPS1_NOTIFICATIONS, 0);
}
