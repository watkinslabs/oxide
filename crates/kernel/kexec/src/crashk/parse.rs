// The `crashkernel=` command-line grammar.
//
// Ungated, and every decision it makes is one a boot cannot report on: a
// machine that reserves the wrong amount, or reserves nothing because a suffix
// was misread, boots exactly like one that got it right and only differs the
// day it panics.

use cmdline::token;

/// Granularity the total-RAM figure is rounded up to before it is matched
/// against a `range:size` table.
///
/// A machine reports slightly less usable RAM than it has — firmware carves
/// pieces out below the kernel — so an unrounded figure falls out of the
/// bottom of the range the operator wrote for that size class.
pub const SYSTEM_RAM_GRANULE: u64 = 128 * 1024 * 1024;

/// Where the reservation is preferred, when the value did not fix a base.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Pref {
    /// Plain form: below the 32-bit boundary first, above it as a fallback.
    #[default]
    Auto,
    /// `,high`: above the 32-bit boundary first, below it as a fallback.
    High,
}

/// Bytes and optional fixed base a `crashkernel=` value asks for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CrashKernelReq {
    /// Bytes to reserve.
    pub size: u64,
    /// Fixed physical base, when the value named one.
    pub base: Option<u64>,
    /// Where an unfixed reservation is preferred.
    pub pref: Pref,
}

/// Everything one command line asks of the crash reservation.
///
/// Three independent requests, because the suffixed forms are not alternative
/// spellings of the main one: `crashkernel=1G,high crashkernel=64M,low` asks
/// for both regions, and a parse that let the second value replace the first
/// would silently drop the region the low one exists to guarantee.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CrashKernelSpec {
    /// The plain or `,high` request — the region a crash image lands in.
    pub main: Option<CrashKernelReq>,
    /// `,low`: extra bytes below the 32-bit boundary, for devices that cannot
    /// address above it.
    pub low: Option<u64>,
    /// `,cma`: bytes lent to the page allocator until a crash claims them.
    pub cma: Option<u64>,
}

/// Why a `crashkernel=` value was refused. Distinguishable rather than a bare
/// `None` so a test can pin WHICH refusal a malformed value earns; a parser
/// that collapses them cannot show that `crashkernel=0M` and `crashkernel=x`
/// fail for different reasons.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParseError {
    /// No digits where a size or an offset was required.
    NoNumber,
    /// The value resolved to zero bytes.
    ZeroSize,
    /// The size is at least as large as the machine's whole memory.
    TooBig,
    /// A `start-end` range whose end is not above its start.
    BadRange,
    /// Text after the part the grammar accounts for.
    Trailing,
    /// A range table in which no entry covers this machine's memory size.
    NoMatchingRange,
}

/// Round a raw total-RAM figure to the granule a range table is written in.
/// # C: O(1)
pub fn round_system_ram(total: u64) -> u64 {
    let g = SYSTEM_RAM_GRANULE;
    match total.checked_add(g - 1) { Some(v) => (v / g) * g, None => total }
}

/// Parse an unsigned size with an optional binary suffix, returning the value
/// and the unconsumed tail. # C: O(len)
fn memparse(s: &[u8]) -> Result<(u64, &[u8]), ParseError> {
    let (v, n) = token::parse_uint(s);
    if n == 0 { return Err(ParseError::NoNumber); }
    let rest = &s[n..];
    let shift = match rest.first() {
        Some(b'K') | Some(b'k') => 10,
        Some(b'M') | Some(b'm') => 20,
        Some(b'G') | Some(b'g') => 30,
        Some(b'T') | Some(b't') => 40,
        _ => return Ok((v, rest)),
    };
    Ok((v.saturating_mul(1u64 << shift), &rest[1..]))
}

/// Strip a recognised placement suffix, returning it and the head.
fn split_suffix(v: &[u8]) -> (&[u8], Option<&[u8]>) {
    for suf in [&b",high"[..], &b",low"[..], &b",cma"[..]] {
        if v.len() > suf.len() && &v[v.len() - suf.len()..] == suf {
            return (&v[..v.len() - suf.len()], Some(&suf[1..]));
        }
    }
    (v, None)
}

/// `<size>[@<offset>]`, with nothing after it.
fn parse_simple(v: &[u8]) -> Result<CrashKernelReq, ParseError> {
    let (size, rest) = memparse(v)?;
    if size == 0 { return Err(ParseError::ZeroSize); }
    match rest.first() {
        None => Ok(CrashKernelReq { size, base: None, pref: Pref::Auto }),
        Some(b'@') => {
            let (base, tail) = memparse(&rest[1..])?;
            if !tail.is_empty() { return Err(ParseError::Trailing); }
            Ok(CrashKernelReq { size, base: Some(base), pref: Pref::Auto })
        }
        Some(_) => Err(ParseError::Trailing),
    }
}

/// `<start>-<end>:<size>[,<start>-<end>:<size>]…[@<offset>]`.
///
/// The entry chosen is the one whose range contains this machine's memory
/// size: one command line then serves a whole fleet, reserving proportionally
/// on each member rather than the same absolute figure on a 2 GiB machine and
/// a 2 TiB one.
fn parse_ranges(v: &[u8], system_ram: u64) -> Result<CrashKernelReq, ParseError> {
    let mut cur = v;
    let mut chosen: Option<u64> = None;
    loop {
        let (start, rest) = memparse(cur)?;
        if rest.first() != Some(&b'-') { return Err(ParseError::Trailing); }
        let rest = &rest[1..];
        // `start-:size` leaves the top open, which is how the last entry of a
        // table says "and everything above this".
        let (end, rest) = if rest.first() == Some(&b':') { (u64::MAX, rest) } else { memparse(rest)? };
        if end <= start { return Err(ParseError::BadRange); }
        if rest.first() != Some(&b':') { return Err(ParseError::Trailing); }
        let (size, rest) = memparse(&rest[1..])?;
        // Refused before the range test, so a table whose entry for THIS
        // machine is sane still fails when a later entry is not — the operator
        // learns on the machine that boots, not on the one that crashes.
        if size >= system_ram { return Err(ParseError::TooBig); }
        if chosen.is_none() && system_ram >= start && system_ram < end { chosen = Some(size); }
        match rest.first() {
            Some(b',') => { cur = &rest[1..]; }
            _ => {
                let size = chosen.ok_or(ParseError::NoMatchingRange)?;
                if size == 0 { return Err(ParseError::ZeroSize); }
                return match rest.first() {
                    None => Ok(CrashKernelReq { size, base: None, pref: Pref::Auto }),
                    Some(b'@') => {
                        let (base, tail) = memparse(&rest[1..])?;
                        if !tail.is_empty() { return Err(ParseError::Trailing); }
                        Ok(CrashKernelReq { size, base: Some(base), pref: Pref::Auto })
                    }
                    Some(_) => Err(ParseError::Trailing),
                };
            }
        }
    }
}

/// Parse one `crashkernel=` VALUE. `system_ram` is the rounded total.
/// # C: O(value length)
pub fn parse_value(v: &[u8], system_ram: u64) -> Result<(CrashKernelReq, Option<&[u8]>), ParseError> {
    let (head, suffix) = split_suffix(v);
    if suffix.is_some() {
        // A suffixed value names a size and nothing else: there is no address
        // to fix when the whole point of the suffix is where to search.
        let (size, rest) = memparse(head)?;
        if !rest.is_empty() { return Err(ParseError::Trailing); }
        if size == 0 { return Err(ParseError::ZeroSize); }
        if system_ram != 0 && size >= system_ram { return Err(ParseError::TooBig); }
        let pref = if suffix == Some(&b"high"[..]) { Pref::High } else { Pref::Auto };
        return Ok((CrashKernelReq { size, base: None, pref }, suffix));
    }
    let req = if head.contains(&b':') { parse_ranges(head, system_ram)? } else { parse_simple(head)? };
    if system_ram != 0 && req.size >= system_ram { return Err(ParseError::TooBig); }
    Ok((req, None))
}

/// Read every `crashkernel=` token on `line` into one spec.
///
/// Per FORM, the last value wins: a line may carry a main request and a `,low`
/// request at once, and each is independently replaced by a later token of the
/// same form. A malformed value is dropped rather than poisoning the forms
/// that parsed — the alternative is a typo in the `,cma` figure costing the
/// machine its crash region entirely.
/// # C: O(line length)
pub fn parse_line(line: &[u8], system_ram: u64) -> CrashKernelSpec {
    let mut spec = CrashKernelSpec::default();
    for t in token::tokens(line) {
        let (key, val) = token::split_token(t);
        if key != b"crashkernel" { continue; }
        let Some(val) = val else { continue };
        let Ok((req, suffix)) = parse_value(val, system_ram) else { continue };
        match suffix {
            Some(b"low") => spec.low = Some(req.size),
            Some(b"cma") => spec.cma = Some(req.size),
            _ => spec.main = Some(req),
        }
    }
    spec
}
