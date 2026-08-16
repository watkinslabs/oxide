//! The pairing crypto functions.
//!
//! Every value on this channel is carried least-significant-byte-first while
//! the functions are defined most-significant-first, so both the block cipher
//! and the message authentication code reverse their inputs and their output.
//! Getting that reversal wrong produces a key that is wrong but still looks
//! like a key, so the published vectors are the only real check.

use aes::{Aes128, cmac as aes_cmac_msb};

use crate::uapi::bt::{BDADDR_LEN, BdAddr};
use crate::uapi::smp::{
    SMP_ADDR_LEN, SMP_DHKEY_LEN, SMP_IO_CAP_LEN, SMP_KEY_LEN, SMP_PAIRING_PDU_LEN,
    SMP_PASSKEY_MODULUS,
    SMP_PUBKEY_COORD_LEN, SMP_RAND_LEN,
};

/// Longest message any of these functions authenticates, which is the numeric
/// comparison input: two public key coordinates and two nonces packed into one
/// sixteen-byte slot each side.
pub const SMP_CMAC_MSG_MAX: usize = 2 * SMP_PUBKEY_COORD_LEN + SMP_KEY_LEN;

/// Salt the key-derivation function mixes into the shared secret.
const F5_SALT: [u8; SMP_KEY_LEN] = [
    0xbe, 0x83, 0x60, 0x5a, 0xdb, 0x0b, 0x37, 0x60,
    0x38, 0xa5, 0xf5, 0xaa, 0x91, 0x83, 0x88, 0x6c,
];

/// Key identifier the derivation mixes in, stored least-significant-first.
const F5_KEY_ID: [u8; 4] = [0x65, 0x6c, 0x74, 0x62];

/// Length field of the derivation input: two hundred fifty six, little-endian
/// in the least-significant-first layout the message is built in.
const F5_LENGTH: [u8; 2] = [0x00, 0x01];

/// Counter value that selects the message authentication key.
const F5_COUNTER_MACKEY: u8 = 0;
/// Counter value that selects the long term key.
const F5_COUNTER_LTK: u8 = 1;

/// Width of the derivation input built from the addresses, nonces, key
/// identifier, length and counter.
const F5_MSG_LEN: usize = F5_LENGTH.len() + 2 * SMP_ADDR_LEN + 2 * SMP_KEY_LEN
    + F5_KEY_ID.len() + 1;

/// Width of the confirm-value input: a one-byte selector and two coordinates.
const F4_MSG_LEN: usize = 1 + 2 * SMP_PUBKEY_COORD_LEN;

/// Width of the check-value input: two addresses, the capabilities, the
/// passkey-or-random value and two nonces.
const F6_MSG_LEN: usize = 2 * SMP_ADDR_LEN + SMP_IO_CAP_LEN + 3 * SMP_KEY_LEN;

/// Bytes of the numeric-comparison output that form the displayed number.
const G2_VALUE_LEN: usize = 4;

/// Reverse a fixed-width value between the two byte orders. # C: O(n)
pub fn swap<const N: usize>(src: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    for i in 0..N { out[N - 1 - i] = src[i]; }
    out
}

/// The security function: a single block encryption whose key, input and
/// output are each reversed. # C: O(1)
pub fn e(k: &[u8; SMP_KEY_LEN], r: &[u8; SMP_KEY_LEN]) -> [u8; SMP_KEY_LEN] {
    let cipher = Aes128::new(&swap(k));
    swap(&cipher.encrypt(&swap(r)))
}

/// The message authentication code over a least-significant-first message.
/// # C: O(len)
pub fn aes_cmac(k: &[u8; SMP_KEY_LEN], m: &[u8]) -> [u8; SMP_KEY_LEN] {
    let mut msb = [0u8; SMP_CMAC_MSG_MAX];
    let len = m.len();
    for i in 0..len { msb[len - 1 - i] = m[i]; }
    swap(&aes_cmac_msb(&swap(k), &msb[..len]))
}

/// The legacy confirm value. The two pairing PDUs, the two addresses and the
/// two address types all enter it, which is what binds a confirm to the
/// specific exchange that produced it. # C: O(1)
pub fn c1(
    k: &[u8; SMP_KEY_LEN],
    r: &[u8; SMP_RAND_LEN],
    preq: &[u8; SMP_PAIRING_PDU_LEN],
    pres: &[u8; SMP_PAIRING_PDU_LEN],
    iat: u8,
    ia: &BdAddr,
    rat: u8,
    ra: &BdAddr,
) -> [u8; SMP_KEY_LEN] {
    let mut p1 = [0u8; SMP_KEY_LEN];
    p1[0] = iat;
    p1[1] = rat;
    p1[2..2 + SMP_PAIRING_PDU_LEN].copy_from_slice(preq);
    p1[2 + SMP_PAIRING_PDU_LEN..].copy_from_slice(pres);

    let mut res = [0u8; SMP_KEY_LEN];
    for i in 0..SMP_KEY_LEN { res[i] = r[i] ^ p1[i]; }
    res = e(k, &res);

    let mut p2 = [0u8; SMP_KEY_LEN];
    p2[..BDADDR_LEN].copy_from_slice(ra.as_bytes());
    p2[BDADDR_LEN..2 * BDADDR_LEN].copy_from_slice(ia.as_bytes());
    for i in 0..SMP_KEY_LEN { res[i] ^= p2[i]; }
    e(k, &res)
}

/// The legacy short-term key: the low halves of the two nonces, responder
/// first, encrypted under the temporary key. # C: O(1)
pub fn s1(
    k: &[u8; SMP_KEY_LEN],
    r1: &[u8; SMP_RAND_LEN],
    r2: &[u8; SMP_RAND_LEN],
) -> [u8; SMP_KEY_LEN] {
    let half = SMP_KEY_LEN / 2;
    let mut res = [0u8; SMP_KEY_LEN];
    res[..half].copy_from_slice(&r2[..half]);
    res[half..].copy_from_slice(&r1[..half]);
    e(k, &res)
}

/// The random address hash: three bytes of an encryption under the identity
/// resolving key. # C: O(1)
pub fn ah(irk: &[u8; SMP_KEY_LEN], r: &[u8; 3]) -> [u8; 3] {
    let mut block = [0u8; SMP_KEY_LEN];
    block[..3].copy_from_slice(r);
    let out = e(irk, &block);
    [out[0], out[1], out[2]]
}

/// The secure-connections confirm value over the two public key x
/// coordinates. # C: O(1)
pub fn f4(
    u: &[u8; SMP_PUBKEY_COORD_LEN],
    v: &[u8; SMP_PUBKEY_COORD_LEN],
    x: &[u8; SMP_KEY_LEN],
    z: u8,
) -> [u8; SMP_KEY_LEN] {
    let mut m = [0u8; F4_MSG_LEN];
    m[0] = z;
    m[1..1 + SMP_PUBKEY_COORD_LEN].copy_from_slice(v);
    m[1 + SMP_PUBKEY_COORD_LEN..].copy_from_slice(u);
    aes_cmac(x, &m)
}

/// The secure-connections key derivation: the shared secret and the two
/// nonces yield a message authentication key and a long term key.
/// The nonce order is initiator then responder, and swapping them yields two
/// keys that are wrong on both sides without either noticing. # C: O(1)
pub fn f5(
    w: &[u8; SMP_DHKEY_LEN],
    n1: &[u8; SMP_KEY_LEN],
    n2: &[u8; SMP_KEY_LEN],
    a1: &[u8; SMP_ADDR_LEN],
    a2: &[u8; SMP_ADDR_LEN],
) -> ([u8; SMP_KEY_LEN], [u8; SMP_KEY_LEN]) {
    let t = aes_cmac(&F5_SALT, w);

    let mut m = [0u8; F5_MSG_LEN];
    let mut o = 0;
    m[o..o + F5_LENGTH.len()].copy_from_slice(&F5_LENGTH); o += F5_LENGTH.len();
    m[o..o + SMP_ADDR_LEN].copy_from_slice(a2); o += SMP_ADDR_LEN;
    m[o..o + SMP_ADDR_LEN].copy_from_slice(a1); o += SMP_ADDR_LEN;
    m[o..o + SMP_KEY_LEN].copy_from_slice(n2); o += SMP_KEY_LEN;
    m[o..o + SMP_KEY_LEN].copy_from_slice(n1); o += SMP_KEY_LEN;
    m[o..o + F5_KEY_ID.len()].copy_from_slice(&F5_KEY_ID); o += F5_KEY_ID.len();

    m[o] = F5_COUNTER_MACKEY;
    let mackey = aes_cmac(&t, &m);
    m[o] = F5_COUNTER_LTK;
    let ltk = aes_cmac(&t, &m);
    (mackey, ltk)
}

/// The secure-connections check value. Each side computes it over its own
/// nonce first and verifies the peer's with the roles swapped. # C: O(1)
pub fn f6(
    w: &[u8; SMP_KEY_LEN],
    n1: &[u8; SMP_KEY_LEN],
    n2: &[u8; SMP_KEY_LEN],
    r: &[u8; SMP_KEY_LEN],
    io_cap: &[u8; SMP_IO_CAP_LEN],
    a1: &[u8; SMP_ADDR_LEN],
    a2: &[u8; SMP_ADDR_LEN],
) -> [u8; SMP_KEY_LEN] {
    let mut m = [0u8; F6_MSG_LEN];
    let mut o = 0;
    m[o..o + SMP_ADDR_LEN].copy_from_slice(a2); o += SMP_ADDR_LEN;
    m[o..o + SMP_ADDR_LEN].copy_from_slice(a1); o += SMP_ADDR_LEN;
    m[o..o + SMP_IO_CAP_LEN].copy_from_slice(io_cap); o += SMP_IO_CAP_LEN;
    m[o..o + SMP_KEY_LEN].copy_from_slice(r); o += SMP_KEY_LEN;
    m[o..o + SMP_KEY_LEN].copy_from_slice(n2); o += SMP_KEY_LEN;
    m[o..o + SMP_KEY_LEN].copy_from_slice(n1);
    aes_cmac(w, &m)
}

/// The numeric comparison value both users read off their displays. # C: O(1)
pub fn g2(
    u: &[u8; SMP_PUBKEY_COORD_LEN],
    v: &[u8; SMP_PUBKEY_COORD_LEN],
    x: &[u8; SMP_KEY_LEN],
    y: &[u8; SMP_KEY_LEN],
) -> u32 {
    let mut m = [0u8; SMP_CMAC_MSG_MAX];
    let mut o = 0;
    m[o..o + SMP_KEY_LEN].copy_from_slice(y); o += SMP_KEY_LEN;
    m[o..o + SMP_PUBKEY_COORD_LEN].copy_from_slice(v); o += SMP_PUBKEY_COORD_LEN;
    m[o..o + SMP_PUBKEY_COORD_LEN].copy_from_slice(u);
    let tmp = aes_cmac(x, &m);
    let mut low = [0u8; G2_VALUE_LEN];
    low.copy_from_slice(&tmp[..G2_VALUE_LEN]);
    u32::from_le_bytes(low) % SMP_PASSKEY_MODULUS
}

/// Cross-transport derivation keyed on the key being converted. # C: O(1)
pub fn h6(w: &[u8; SMP_KEY_LEN], key_id: &[u8; 4]) -> [u8; SMP_KEY_LEN] {
    aes_cmac(w, key_id)
}

/// Cross-transport derivation keyed on the salt instead, which is what the
/// second-generation conversion uses. Key and message swap roles against the
/// other one. # C: O(1)
pub fn h7(w: &[u8; SMP_KEY_LEN], salt: &[u8; SMP_KEY_LEN]) -> [u8; SMP_KEY_LEN] {
    aes_cmac(salt, w)
}
