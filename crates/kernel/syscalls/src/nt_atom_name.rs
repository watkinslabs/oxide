//! Atom names: which names are integers rather than table entries, and how
//! two names compare.
//!
//! An atom name argument is either a string pointer or, when its value fits
//! in sixteen bits, the integer atom itself — so the argument is classified
//! before any of it is read. A string of a hash and decimal digits names the
//! same integer atom. Table names compare without regard to case.
//!
//! Ungated so both rules are testable without a target build.

/// First atom the string table hands out; every lower value is an integer
/// atom.
pub const FIRST_STRING_ATOM: u16 = 0xc000;
/// Longest atom name, in characters.
pub const MAX_ATOM_CHARS: usize = 255;

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_OBJECT_NAME_INVALID: u64 = 0xc000_0033;

/// What one name argument names.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Name { Integer(u16), Table }

/// Classify the name argument from its value alone, before reading it. A
/// value that fits in sixteen bits is the atom, not an address, and must not
/// be dereferenced.
/// # C: O(1)
pub fn classify_pointer(name: u64, length_bytes: usize) -> Result<Name, u64> {
    if name >> 16 != 0 {
        if length_bytes == 0 { return Err(STATUS_OBJECT_NAME_INVALID); }
        if length_bytes > MAX_ATOM_CHARS * 2 || length_bytes & 1 != 0 { return Err(STATUS_INVALID_PARAMETER); }
        return Ok(Name::Table);
    }
    let atom = name as u16;
    if atom == 0 || atom >= FIRST_STRING_ATOM { return Err(STATUS_INVALID_PARAMETER); }
    Ok(Name::Integer(atom))
}

/// Classify a table-bound name by its text: a hash followed only by decimal
/// digits names an integer atom, and a value outside the integer range names
/// none at all.
/// # C: O(n)
pub fn classify_text(units: &[u16]) -> Result<Name, u64> {
    if units.first() != Some(&(b'#' as u16)) || units.len() < 2 { return Ok(Name::Table); }
    let mut value: u32 = 0;
    for unit in &units[1..] {
        if *unit < b'0' as u16 || *unit > b'9' as u16 { return Ok(Name::Table); }
        value = value.saturating_mul(10).saturating_add((*unit - b'0' as u16) as u32);
    }
    let atom = if value >= FIRST_STRING_ATOM as u32 { 0 } else { value as u16 };
    if atom == 0 { return Err(STATUS_INVALID_PARAMETER); }
    Ok(Name::Integer(atom))
}

fn fold_ascii(value: u16) -> u16 { if value >= b'A' as u16 && value <= b'Z' as u16 { value + (b'a' - b'A') as u16 } else { value } }

/// Whether two atom names are the same name. Atom names are matched without
/// regard to case, so a class registered under one spelling is found under
/// another.
/// # C: O(n)
pub fn same_name(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.chunks_exact(2).zip(right.chunks_exact(2)).all(|(a, b)| {
        let left = u16::from_le_bytes([a[0], a[1]]);
        let right = u16::from_le_bytes([b[0], b[1]]);
        left == right || left <= 0x7f && right <= 0x7f && fold_ascii(left) == fold_ascii(right)
    })
}

#[cfg(test)]
#[path = "tests/nt_atom_name.rs"]
mod tests;
