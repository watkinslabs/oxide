//! The 8.3-only name rules: a name is either spellable in eleven bytes or it
//! does not exist.
//!
//! Nothing here generates an alias and nothing here reads a long-name slot.
//! A name too long, or holding a character the format cannot store, is
//! rejected outright — which is the whole difference between this and the
//! long-name side, and the reason both a lookup and a create of such a name
//! fail rather than silently becoming a different name.

use super::flags::{DELETED_FLAG, ESCAPED_DELETED, SHORT_BASE_LEN, SHORT_NAME_LEN};

use syscall::errno::Errno;

/// Characters no name may contain.
const BAD: [u8; 6] = [b'*', b'?', b'<', b'>', b'|', b'"'];
/// Characters only the strict rule refuses.
const BAD_IF_STRICT: [u8; 5] = [b'+', b'=', b',', b';', b' '];

/// How hard a mount checks the names it is given (`check=`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NameCheck {
    /// Accept anything that fits.
    Relaxed,
    /// Refuse the characters the format cannot store.
    Normal,
    /// Refuse anything a machine of the era would have refused, uppercase
    /// letters included.
    Strict,
}

/// What an 8.3-only mount was asked for.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub check: NameCheck,
    /// Whether a name may begin with a dot, stored as the hidden attribute
    /// rather than as a character.
    pub dots_ok: bool,
    /// Whether a lowercase name is stored as it stands rather than folded up.
    pub nocase: bool,
}

impl Default for Options {
    /// # C: O(1)
    fn default() -> Self { Self { check: NameCheck::Normal, dots_ok: false, nocase: false } }
}

/// The eleven bytes a name is stored as, or the errno that refuses it.
///
/// The dot is a separator, not a character: everything before the first one
/// is the base, everything after it the extension, and both are padded with
/// spaces to their fixed width. A name with nothing after the dot still has
/// the dot consumed.
///
/// Bytes, not text: a name is an arbitrary byte string, and a name holding a
/// byte no charset would produce still has to be storable and findable.
/// # C: O(name length)
pub fn format_name(name: &[u8], opts: &Options) -> Result<[u8; SHORT_NAME_LEN], Errno> {
    let mut src = name;
    if src.first() == Some(&b'.') {
        if !opts.dots_ok { return Err(Errno::Einval); }
        src = &src[1..];
    }

    let mut res = [b' '; SHORT_NAME_LEN];
    let mut walk = 0usize;
    let mut space = true;
    let mut c = 0u8;
    let mut at = 0usize;
    while at < src.len() && walk < SHORT_BASE_LEN {
        c = src[at];
        at += 1;
        reject(c, opts)?;
        // The deleted marker's own value is legal as a first character and is
        // stored escaped, since an unescaped one would read as a free slot.
        if walk == 0 && c == DELETED_FLAG { c = ESCAPED_DELETED; }
        if c == b'.' { break; }
        space = c == b' ';
        res[walk] = fold(c, opts);
        walk += 1;
    }
    if space { return Err(Errno::Einval); }

    // Under the strict rule the base must end AT the separator: a base cut
    // short by the eight-byte limit is a different name, not this one.
    if opts.check == NameCheck::Strict && at < src.len() && c != b'.' {
        c = src[at];
        at += 1;
        if c != b'.' { return Err(Errno::Einval); }
    }
    while c != b'.' && at < src.len() { c = src[at]; at += 1; }

    if c == b'.' {
        // The extension has a fixed place, so a base shorter than eight
        // leaves padding rather than moving it.
        walk = walk.max(SHORT_BASE_LEN);
        while at < src.len() && walk < SHORT_NAME_LEN {
            c = src[at];
            at += 1;
            reject(c, opts)?;
            if c == b'.' {
                if opts.check == NameCheck::Strict { return Err(Errno::Einval); }
                break;
            }
            space = c == b' ';
            res[walk] = fold(c, opts);
            walk += 1;
        }
        if space { return Err(Errno::Einval); }
        if opts.check == NameCheck::Strict && at < src.len() { return Err(Errno::Einval); }
    }
    Ok(res)
}

/// The characters this rule refuses outright. # C: O(1)
fn reject(c: u8, opts: &Options) -> Result<(), Errno> {
    if opts.check != NameCheck::Relaxed && BAD.contains(&c) { return Err(Errno::Einval); }
    if opts.check == NameCheck::Strict && BAD_IF_STRICT.contains(&c) { return Err(Errno::Einval); }
    if c.is_ascii_uppercase() && opts.check == NameCheck::Strict { return Err(Errno::Einval); }
    if c < b' ' || c == b':' || c == b'\\' { return Err(Errno::Einval); }
    Ok(())
}

/// One character as it is stored. # C: O(1)
fn fold(c: u8, opts: &Options) -> u8 {
    const CASE_DELTA: u8 = 0x20;
    if !opts.nocase && c.is_ascii_lowercase() { c - CASE_DELTA } else { c }
}

/// Whether two names name the same 8.3 entry.
///
/// Both are put through the same formatting, so `readme.txt` and `README.TXT`
/// are one name — and a name neither can be formatted falls back to comparing
/// the text, which is what lets a lookup of an impossible name fail with the
/// error it deserves rather than matching something else.
/// # C: O(length)
pub fn eq(a: &[u8], b: &[u8], opts: &Options) -> bool {
    match (format_name(a, opts), format_name(b, opts)) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}
