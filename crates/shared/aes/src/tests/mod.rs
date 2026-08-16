//! Test manifest. Each child owns one published vector set.

#[path = "sbox.rs"] mod sbox;
#[path = "block.rs"] mod block;
#[path = "cmac.rs"] mod cmac;
#[path = "vec_util.rs"] mod vec_util;
#[path = "block256.rs"] mod block256;
#[path = "cmac256.rs"] mod cmac256;
#[path = "ccm.rs"] mod ccm;
#[path = "gcm.rs"] mod gcm;
#[path = "cbc.rs"] mod cbc;
#[path = "xts.rs"] mod xts;

const fn hexval(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Parse a hex string into a fixed-width byte array so a published vector can
/// be written the way the standard prints it.
pub(crate) const fn hex<const N: usize>(s: &str) -> [u8; N] {
    let b = s.as_bytes();
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (hexval(b[2 * i]) << 4) | hexval(b[2 * i + 1]);
        i += 1;
    }
    out
}
