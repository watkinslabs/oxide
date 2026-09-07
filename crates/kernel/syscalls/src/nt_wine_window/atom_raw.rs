//! Atom-name formatting for the window atom table and the clipboard format
//! names that share it.

pub(crate) const GET_ATOM_NAME: u64 = 0x13d1;


/// Atoms below this are integers rather than table entries.
pub(crate) const MAXINTATOM: u16 = 0xc000;
/// An integral atom's name is its value in decimal behind a hash.
const INTEGRAL_PREFIX: u16 = b'#' as u16;
/// `#65535` is the longest integral name.
pub(crate) const MAX_INTEGRAL_NAME: usize = 6;

/// Render an integral atom's name, answering how many units it used. An atom
/// of zero has no name at all. # C: O(1)
pub(crate) fn integral_atom_name(atom: u16, out: &mut [u16; MAX_INTEGRAL_NAME]) -> Option<usize> {
    if atom == 0 { return None; }
    let mut digits = [0u16; MAX_INTEGRAL_NAME];
    let mut value = atom;
    let mut count = 0;
    while value > 0 { digits[count] = (b'0' as u16) + value % 10; value /= 10; count += 1; }
    out[0] = INTEGRAL_PREFIX;
    for index in 0..count { out[index + 1] = digits[count - 1 - index]; }
    Some(count + 1)
}

/// How many name units fit in a caller's buffer, given its capacity in units
/// and the terminating null every answer carries. A buffer with no room for
/// the null cannot be written at all. # C: O(1)
pub(crate) const fn name_fit(available: usize, maximum_units: usize) -> Option<usize> {
    if maximum_units == 0 { return None; }
    Some(if available > maximum_units - 1 { maximum_units - 1 } else { available })
}

#[cfg(target_os = "oxide-kernel")]
#[path = "atom_raw/kernel.rs"]
pub(crate) mod kernel;

#[cfg(test)]
#[path = "tests/atom_raw.rs"]
mod tests;
