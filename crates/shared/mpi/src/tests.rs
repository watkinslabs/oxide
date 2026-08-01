// Hosted tests for the bignum core.
//
// Module manifest:
// - arith: import/export, ordering, add/sub/mul/shift, and the division
//          corner cases (single-limb divisor, the add-back branch).
// - powm:  modular exponentiation, including the known-answer vectors the
//          Diffie-Hellman path depends on.

mod arith;
mod powm;

use crate::Mpi;

/// Parse a hex literal (any length, no `0x` prefix) into an `Mpi`. Tests
/// express operands the way the reference vectors publish them.
pub(crate) fn hex(s: &str) -> Mpi {
    let clean: alloc::vec::Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut bytes = alloc::vec::Vec::new();
    let odd = clean.len() % 2;
    let mut i = 0;
    if odd == 1 {
        bytes.push(nybble(clean[0]));
        i = 1;
    }
    while i < clean.len() {
        bytes.push(nybble(clean[i]) << 4 | nybble(clean[i + 1]));
        i += 2;
    }
    Mpi::from_be_bytes(&bytes)
}

fn nybble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("hex digit"),
    }
}

/// Render an `Mpi` as lowercase hex with no leading zeros ("0" for zero).
pub(crate) fn to_hex(v: &Mpi) -> alloc::string::String {
    use core::fmt::Write;
    if v.is_zero() { return alloc::string::String::from("0"); }
    let bytes = v.to_be_bytes(v.byte_len()).expect("exact width fits");
    let mut s = alloc::string::String::new();
    for (i, b) in bytes.iter().enumerate() {
        if i == 0 { let _ = write!(s, "{b:x}"); } else { let _ = write!(s, "{b:02x}"); }
    }
    s
}
