// The escape a created object's name arrives in.
//
// A filename may hold any byte but NUL and the separator, so the name field
// carries `+` for a space and `%XX` for any other byte. An incomplete or
// non-hexadecimal escape is REFUSED, never decoded as far as it goes: a
// silently truncated name asks the policy about a different object than the
// caller named, and the answer would be attributed to the wrong one.

use alloc::string::String;
use alloc::vec::Vec;

use vfs::{KResult, VfsError};

/// Escape introducing a two-digit hexadecimal byte.
const ESCAPE: u8 = b'%';
/// Character standing in for a space.
const PLUS: u8 = b'+';
/// Digits an escape carries.
const ESCAPE_DIGITS: usize = 2;

/// Decode one percent-escaped name field. # C: O(len)
pub fn percent_decode(s: &str) -> KResult<String> {
    let src = s.as_bytes();
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < src.len() {
        match src[i] {
            PLUS => { out.push(b' '); i += 1; }
            ESCAPE => {
                if i + ESCAPE_DIGITS >= src.len() { return Err(VfsError::Einval); }
                let hi = hex_digit(src[i + 1])?;
                let lo = hex_digit(src[i + 2])?;
                out.push((hi << 4) | lo);
                i += 1 + ESCAPE_DIGITS;
            }
            b => { out.push(b); i += 1; }
        }
    }
    String::from_utf8(out).map_err(|_| VfsError::Einval)
}

/// Value of one hexadecimal digit. # C: O(1)
fn hex_digit(b: u8) -> KResult<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(VfsError::Einval),
    }
}

#[cfg(test)]
#[path = "../tests/format_percent.rs"]
mod tests;
