//! Turning a long name into the 8.3 name stored beside it.
//!
//! Every entry has an 8.3 name, including the ones whose real name is stored
//! in long-name slots — the short one is what an 8.3-only reader sees, and
//! what the checksum in every slot is taken over. It has to be unique in its
//! directory, which is why this takes a predicate over the names already
//! there rather than a name in isolation.
//!
//! Three outcomes, and which one a name gets is the whole point:
//! - the name is already 8.3-legal, so it IS the name and no slots are used;
//! - the name is legal but its case cannot be recovered from the eleven
//!   bytes, so a numeric tail is not added but the slots are;
//! - the name cannot be spelled in 8.3 at all, so it gets a `~N` tail that
//!   makes it unique, and the slots carry the real name.

use super::codepage::CodePage;
use super::flags::{CASE_LOWER_BASE, CASE_LOWER_EXT, DELETED_FLAG, ESCAPED_DELETED,
                   SFN_CREATE_WINNT, SHORT_BASE_LEN, SHORT_NAME_LEN};

use syscall::errno::Errno;

/// Characters that make a name unspellable in 8.3 but are stored as an
/// underscore rather than rejected.
const REPLACED: [u16; 6] = [b'[' as u16, b']' as u16, b';' as u16,
                            b',' as u16, b'+' as u16, b'=' as u16];
/// What a character with no byte on the code page becomes.
const REPLACEMENT: u8 = b'_';
/// Separator between the base and the numeric tail.
const TAIL_MARK: u8 = b'~';
/// Numeric tails tried in order before falling back to a hashed one. Windows
/// stops here too: a linear search of every tail is what made large
/// directories unusable.
const LINEAR_TAILS: u8 = 9;
/// Base characters kept when a numeric tail has to fit after them.
const NUMTAIL_BASELEN: usize = 6;
/// Base characters kept when the hashed tail has to fit after them.
const NUMTAIL2_BASELEN: usize = 2;
/// Length of that hashed tail, in hexadecimal digits.
const HASH_DIGITS: usize = 4;
/// Step between hashed-tail attempts. Odd, so the walk visits every value
/// before repeating one.
const HASH_STEP: u32 = 11;

const DOT: u16 = b'.' as u16;
const SPACE: u16 = b' ' as u16;

/// What the eleven bytes turned out to be.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShortName {
    /// The name spells itself in 8.3, so the entry needs no long-name slots.
    /// `lcase` records a base or extension that was all-lowercase.
    Alone { name: [u8; SHORT_NAME_LEN], lcase: u8 },
    /// The name is an alias; the real name goes in long-name slots.
    Aliased { name: [u8; SHORT_NAME_LEN] },
}

impl ShortName {
    /// The eleven bytes, whichever outcome this is. # C: O(1)
    pub fn bytes(&self) -> &[u8; SHORT_NAME_LEN] {
        match self { Self::Alone { name, .. } | Self::Aliased { name } => name }
    }
}

/// Case evidence gathered while folding one part of the name.
#[derive(Clone, Copy)]
struct CaseInfo { lower: bool, upper: bool, valid: bool }

impl CaseInfo {
    fn new() -> Self { Self { lower: true, upper: true, valid: true } }
}

/// Characters dropped outright rather than replaced. # C: O(1)
fn skip_char(c: u16) -> bool { c == DOT || c == SPACE }

/// One character as the byte that stores it, or `None` when it is dropped.
///
/// The case flags come out of here, not out of the finished name: by the time
/// the byte is uppercased there is no telling whether it started that way.
/// # C: O(256)
fn to_short_byte(cp: &CodePage, c: u16, info: &mut CaseInfo) -> Option<u8> {
    if skip_char(c) { info.valid = false; return None; }
    if REPLACED.contains(&c) { info.valid = false; return Some(REPLACEMENT); }
    let Some(byte) = cp.from_char(c) else {
        info.valid = false;
        return Some(REPLACEMENT);
    };
    if byte >= 0x7f { info.lower = false; info.upper = false; }
    let upper = cp.to_upper(byte);
    if upper.is_ascii_alphabetic() {
        if upper == byte { info.lower = false; } else { info.upper = false; }
    }
    Some(upper)
}

/// Where the extension starts, and how much of the name is base.
///
/// A name that is nothing but an extension — one beginning with dots, like a
/// dotfile — has no extension at all: the dots are the name's, and taking
/// them as a separator would leave an empty base.
/// # C: O(name length)
fn split(uname: &[u16]) -> (usize, Option<usize>) {
    let end = uname.len();
    let dot = uname.iter().rposition(|c| *c == DOT);
    match dot {
        None => (end, None),
        // A trailing dot separates nothing.
        Some(i) if i + 1 == end => (end, None),
        Some(i) => {
            let mut start = 0;
            while start < i && skip_char(uname[start]) { start += 1; }
            if start != i { (i, Some(i + 1)) } else { (end, None) }
        }
    }
}

/// The 8.3 name for a long name, unique within the directory `exists`
/// describes.
///
/// `exists` answers whether a directory already holds an entry with those
/// eleven bytes. `seed` supplies the hashed tail's starting value, which the
/// reference takes from the clock: any value works, and the search moves off
/// it until the name is free.
///
/// `EINVAL` when nothing of the name survives folding, `EEXIST` when the name
/// is 8.3-legal and already taken — the caller cannot rename around that,
/// because an 8.3-legal name has no alias to fall back on.
/// # C: O(tail attempts)
pub fn create(uname: &[u16], cp: &CodePage, opts: u16, numtail: bool, seed: u32,
              exists: &mut dyn FnMut(&[u8; SHORT_NAME_LEN]) -> bool)
              -> Result<ShortName, Errno> {
    let mut is_short = true;
    let mut base_info = CaseInfo::new();
    let mut ext_info = CaseInfo::new();
    let (sz, ext_start) = split(uname);

    let mut base = [0u8; SHORT_BASE_LEN];
    let mut baselen = 0usize;
    for i in 0..sz {
        let Some(byte) = to_short_byte(cp, uname[i], &mut base_info) else { continue };
        base[baselen] = byte;
        baselen += 1;
        if baselen >= SHORT_BASE_LEN {
            if i + 1 < sz { is_short = false; }
            break;
        }
    }
    if baselen == 0 { return Err(Errno::Einval); }

    let ext_len_max = SHORT_NAME_LEN - SHORT_BASE_LEN;
    let mut ext = [0u8; SHORT_NAME_LEN - SHORT_BASE_LEN];
    let mut extlen = 0usize;
    if let Some(start) = ext_start {
        let mut at = start;
        while extlen < ext_len_max && at < uname.len() {
            if let Some(byte) = to_short_byte(cp, uname[at], &mut ext_info) {
                ext[extlen] = byte;
                extlen += 1;
                if extlen >= ext_len_max {
                    if at + 1 != uname.len() { is_short = false; }
                    break;
                }
            }
            at += 1;
        }
    }

    let mut name = [b' '; SHORT_NAME_LEN];
    name[..baselen].copy_from_slice(&base[..baselen]);
    name[SHORT_BASE_LEN..SHORT_BASE_LEN + extlen].copy_from_slice(&ext[..extlen]);
    // A name may begin with the deleted marker's own value; stored as-is it
    // would read as a free slot.
    if name[0] == DELETED_FLAG { name[0] = ESCAPED_DELETED; }

    if is_short && base_info.valid && ext_info.valid {
        if exists(&name) { return Err(Errno::Eexist); }
        return Ok(settled(name, opts, base_info, ext_info));
    }

    // Without a numeric tail the plain name stands, if it is free.
    if !numtail && !exists(&name) { return Ok(ShortName::Aliased { name }); }

    Ok(ShortName::Aliased { name: unique(name, baselen, seed, exists) })
}

/// The outcome for a name that spells itself, under the mount's creation
/// rule.
///
/// The win95 rule stores no case bits, so a name that was not already
/// uppercase needs its long-name slots after all. The winnt rule stores them,
/// so an all-lowercase name round-trips with no slots at all — but a MIXED
/// name still needs them, since one bit cannot record which characters were
/// which.
/// # C: O(1)
fn settled(name: [u8; SHORT_NAME_LEN], opts: u16, base: CaseInfo, ext: CaseInfo) -> ShortName {
    if opts & SFN_CREATE_WINNT != 0 {
        if (base.upper || base.lower) && (ext.upper || ext.lower) {
            let mut lcase = 0u8;
            if !base.upper && base.lower { lcase |= CASE_LOWER_BASE; }
            if !ext.upper && ext.lower { lcase |= CASE_LOWER_EXT; }
            return ShortName::Alone { name, lcase };
        }
        return ShortName::Aliased { name };
    }
    // SFN_CREATE_WIN95, and the fallback for a mount that names neither.
    if base.upper && ext.upper { ShortName::Alone { name, lcase: 0 } } else { ShortName::Aliased { name } }
}

/// A name no entry in the directory already has.
///
/// `~1` through `~9` first, then a hashed tail. The linear search stops at
/// nine deliberately: walking every tail is what made directories holding
/// thousands of aliases take quadratic time to add one more.
/// # C: O(attempts)
fn unique(mut name: [u8; SHORT_NAME_LEN], baselen: usize, seed: u32,
          exists: &mut dyn FnMut(&[u8; SHORT_NAME_LEN]) -> bool) -> [u8; SHORT_NAME_LEN] {
    let mut at = baselen;
    if at > NUMTAIL_BASELEN {
        at = NUMTAIL_BASELEN;
        name[SHORT_BASE_LEN - 1] = b' ';
    }
    name[at] = TAIL_MARK;
    for n in 1..=LINEAR_TAILS {
        name[at + 1] = b'0' + n;
        if !exists(&name) { return name; }
    }

    let mut value = seed;
    let spread = ((seed >> 16) & 0x7) as u8;
    if at > NUMTAIL2_BASELEN {
        at = NUMTAIL2_BASELEN;
        name[SHORT_BASE_LEN - 1] = b' ';
    }
    name[at + HASH_DIGITS] = TAIL_MARK;
    name[at + HASH_DIGITS + 1] = b'1' + spread;
    loop {
        let digits = hex4((value & 0xffff) as u16);
        name[at..at + HASH_DIGITS].copy_from_slice(&digits);
        if !exists(&name) { return name; }
        value = value.wrapping_sub(HASH_STEP);
    }
}

/// A 16-bit value as four uppercase hexadecimal digits. # C: O(1)
fn hex4(value: u16) -> [u8; HASH_DIGITS] {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = [0u8; HASH_DIGITS];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = DIGITS[usize::from((value >> (12 - 4 * i)) & 0xf)];
    }
    out
}
