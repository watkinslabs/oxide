//! Test manifest. Each child owns one published vector set.

#[path = "chacha20.rs"] mod chacha20;
#[path = "xchacha.rs"] mod xchacha;
#[path = "poly1305.rs"] mod poly1305;
#[path = "nh.rs"] mod nh;
#[path = "adiantum_short.rs"] mod adiantum_short;
#[path = "adiantum_long.rs"] mod adiantum_long;
#[path = "adiantum_sector.rs"] mod adiantum_sector;

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
