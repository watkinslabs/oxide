// Boot-parameter tokenisation. The command line is a whitespace-separated
// list of `name`, `name=value` tokens. Every parameter decision in this
// crate goes through these primitives so there is exactly one definition of
// "what counts as a token" — a second scanner would disagree the first time
// a value contained a `=` or a parameter name was a prefix of another.
//
// Ungated on purpose (`no_std`, no globals): every function here takes the
// line as an argument so the whole surface is hosted-testable.

/// First index of `needle` in `hay`, or `None`. # C: O(len)
pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() { return None; }
    (0..=hay.len() - needle.len()).find(|&w| &hay[w..w + needle.len()] == needle)
}

/// Iterate the whitespace-separated tokens of `line`, skipping empties.
/// # C: O(line length)
pub fn tokens(line: &[u8]) -> impl Iterator<Item = &[u8]> {
    line.split(|b| b.is_ascii_whitespace()).filter(|t| !t.is_empty())
}

/// Split a token into `(key, Some(value))` or `(key, None)` for a bare flag.
/// The FIRST `=` separates; a value may itself contain `=`.
/// # C: O(token length)
pub fn split_token(token: &[u8]) -> (&[u8], Option<&[u8]>) {
    match token.iter().position(|b| *b == b'=') {
        Some(at) => (&token[..at], Some(&token[at + 1..])),
        None => (token, None),
    }
}

/// Value of the last exact `name=value` token. Repeated scalar parameters take
/// the last supplied value; prefixes and embedded `=` text never match.
/// # C: O(line length)
pub fn value<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    if name.is_empty() { return None; }
    let mut found = None;
    for token in tokens(line) {
        let (key, val) = split_token(token);
        if key == name { if let Some(v) = val { found = Some(v); } }
    }
    found
}

/// Is `name` present as a whole token, with or without a value? A bare flag
/// (`quiet`) and a valued form (`oops=panic`) both count as present.
/// # C: O(line length)
pub fn present(line: &[u8], name: &[u8]) -> bool {
    tokens(line).any(|t| split_token(t).0 == name)
}

/// Is `name` present as a bare flag (no `=`)? `earlycon` is a flag;
/// `earlycon=uart8250,io,0x3f8` is not, and the two mean different things.
/// # C: O(line length)
pub fn bare_flag(line: &[u8], name: &[u8]) -> bool {
    tokens(line).any(|t| { let (k, v) = split_token(t); k == name && v.is_none() })
}

/// Parse an unsigned integer, honouring a `0x`/`0X` hex prefix and stopping
/// at the first byte that is not a digit of the detected base. Returns
/// `(value, bytes_consumed)`; a consumed count of 0 means "no digits".
/// # C: O(len)
pub fn parse_uint(s: &[u8]) -> (u64, usize) {
    let (radix, start) = if s.len() > 2 && s[0] == b'0' && (s[1] | 0x20) == b'x' { (16u64, 2usize) } else { (10, 0) };
    let mut v: u64 = 0;
    let mut i = start;
    while i < s.len() {
        let d = match s[i] {
            c @ b'0'..=b'9' => (c - b'0') as u64,
            c @ b'a'..=b'f' if radix == 16 => (c - b'a' + 10) as u64,
            c @ b'A'..=b'F' if radix == 16 => (c - b'A' + 10) as u64,
            _ => break,
        };
        v = v.saturating_mul(radix).saturating_add(d);
        i += 1;
    }
    if i == start { (0, 0) } else { (v, i) }
}

/// Whole-value unsigned parse: `None` unless every byte is a digit of the
/// detected base. Rejects `loglevel=7x` the way a strict scalar parse must.
/// # C: O(len)
pub fn full_uint(s: &[u8]) -> Option<u64> {
    let (v, n) = parse_uint(s);
    if n == 0 || n != s.len() { None } else { Some(v) }
}

/// Signed whole-value parse for parameters that accept a negative
/// (`panic=-1` means "reboot immediately"). # C: O(len)
pub fn full_int(s: &[u8]) -> Option<i64> {
    match s.first() {
        Some(b'-') => full_uint(&s[1..]).map(|v| -(v as i64)),
        Some(b'+') => full_uint(&s[1..]).map(|v| v as i64),
        _ => full_uint(s).map(|v| v as i64),
    }
}

/// Value of the last exact `name=value` token, parsed as a whole unsigned
/// integer. A malformed value yields `None`, which callers treat as "keep
/// the default" rather than installing a nonsense setting.
/// # C: O(line length)
pub fn uint_value(line: &[u8], name: &[u8]) -> Option<u64> { value(line, name).and_then(full_uint) }

/// Signed form of [`uint_value`]. # C: O(line length)
pub fn int_value(line: &[u8], name: &[u8]) -> Option<i64> { value(line, name).and_then(full_int) }

/// Split `s` at the first `,`, returning `(head, Some(tail))` or `(s, None)`.
/// # C: O(len)
pub fn split_comma(s: &[u8]) -> (&[u8], Option<&[u8]>) {
    match s.iter().position(|b| *b == b',') {
        Some(at) => (&s[..at], Some(&s[at + 1..])),
        None => (s, None),
    }
}
