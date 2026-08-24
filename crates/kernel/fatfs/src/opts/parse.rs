//! One `-o` string into an option set.
//!
//! Numbers are not all written in one base: the three permission masks and
//! `allow_utime` are OCTAL, everything else decimal. Reading a mask as decimal
//! turns `umask=0077` into a mask of seventy-seven, which masks off bits
//! nobody asked about and leaves the ones they did.

use syscall::errno::Errno;

use crate::name::codepage::by_number;
use crate::name::compare::IoCharset;
use crate::name::flags::shortname_mode;
use crate::name::msdos::NameCheck;
use crate::time::TimeConfig;

use super::values::{Errors, Nfs, Options, UTIME_BITS};

/// Separator between options, and between a key and its value.
const SEP: char = ',';
const ASSIGN: char = '=';

/// Widest offset `time_offset=` accepts, in minutes. Twelve hours either way
/// plus daylight corrections is the real span; the limit is a whole day, so no
/// plausible zone is refused and no absurd one is accepted.
const MAX_OFFSET_MINUTES: i32 = 24 * 60;

/// Parse `data` on top of `base`, which carries the type's defaults.
///
/// Generic per-mount words are consumed by the VFS before this parser runs.
/// Every remaining key belongs to this filesystem, so an unknown one is a
/// caller error rather than an option that may be silently discarded.
/// # C: O(len(data))
pub fn parse(base: Options, data: &str) -> Result<Options, Errno> {
    let mut o = base;
    for token in data.split(SEP).map(str::trim).filter(|t| !t.is_empty()) {
        let (key, val) = match token.split_once(ASSIGN) {
            Some((k, v)) => (k, Some(v)),
            None => (token, None),
        };
        one(&mut o, key, val)?;
    }
    o.settle();
    Ok(o)
}

/// Apply one key. # C: O(1)
fn one(o: &mut Options, key: &str, val: Option<&str>) -> Result<(), Errno> {
    match key {
        "uid" => o.uid = dec(val)?,
        "gid" => o.gid = dec(val)?,
        "umask" => { let m = mask(val)?; o.fmask = m; o.dmask = m; }
        "fmask" => o.fmask = mask(val)?,
        "dmask" => o.dmask = mask(val)?,
        "allow_utime" => o.allow_utime = Some(mask(val)? & UTIME_BITS),
        "codepage" => o.codepage = by_number(dec(val)?).ok_or(Errno::Einval)?,
        "check" => o.check = check(need(val)?)?,
        "shortname" => o.shortname = shortname_mode(need(val)?).ok_or(Errno::Einval)?,
        "iocharset" => o.iocharset = charset(need(val)?)?,
        "tz" => o.time = tz(need(val)?)?,
        "time_offset" => o.time = offset(need(val)?)?,
        "errors" => o.errors = errors(need(val)?)?,
        "nfs" => o.nfs = nfs(val)?,
        "usefree" => { flag(val)?; o.usefree = true; }
        "nocase" => { flag(val)?; o.nocase = true; }
        "quiet" => { flag(val)?; o.quiet = true; }
        "showexec" => { flag(val)?; o.showexec = true; }
        "sys_immutable" => { flag(val)?; o.sys_immutable = true; }
        "flush" => { flag(val)?; o.flush = true; }
        "discard" => { flag(val)?; o.discard = true; }
        "dos1xfloppy" => { flag(val)?; o.dos1xfloppy = true; }
        "rodir" => { flag(val)?; o.rodir = true; }
        "utf8" => o.utf8 = boolean(val)?,
        "uni_xlate" => o.uni_xlate = boolean(val)?,
        // Spelled as its own negation, so a value INVERTS it.
        "nonumtail" => o.numtail = !boolean(val)?,
        "dots" => { flag(val)?; o.dots_ok = true; }
        "nodots" => { flag(val)?; o.dots_ok = false; }
        "dotsOK" => o.dots_ok = boolean(val)?,
        _ => return Err(Errno::Einval),
    }
    Ok(())
}

/// A key that must carry a value. # C: O(1)
fn need(val: Option<&str>) -> Result<&str, Errno> { val.ok_or(Errno::Einval) }

/// A key that must NOT carry one. # C: O(1)
fn flag(val: Option<&str>) -> Result<(), Errno> {
    if val.is_some() { return Err(Errno::Einval); }
    Ok(())
}

/// A flag that may also be written with an explicit truth value. # C: O(1)
fn boolean(val: Option<&str>) -> Result<bool, Errno> {
    match val {
        None => Ok(true),
        Some("1") | Some("y") | Some("yes") | Some("true") | Some("on") => Ok(true),
        Some("0") | Some("n") | Some("no") | Some("false") | Some("off") => Ok(false),
        Some(_) => Err(Errno::Einval),
    }
}

/// A decimal value. # C: O(len)
fn dec(val: Option<&str>) -> Result<u32, Errno> {
    need(val)?.parse::<u32>().map_err(|_| Errno::Einval)
}

/// An OCTAL permission mask, whether or not it was written with a leading
/// zero. # C: O(len)
fn mask(val: Option<&str>) -> Result<u16, Errno> {
    let text = need(val)?;
    if text.is_empty() { return Err(Errno::Einval); }
    u16::from_str_radix(text, 8).map_err(|_| Errno::Einval)
}

/// # C: O(1)
fn check(val: &str) -> Result<NameCheck, Errno> {
    match val {
        "r" | "relaxed" => Ok(NameCheck::Relaxed),
        "n" | "normal" => Ok(NameCheck::Normal),
        "s" | "strict" => Ok(NameCheck::Strict),
        _ => Err(Errno::Einval),
    }
}

/// The one charset spelling this build can honour.
///
/// Accepted, not stored: long names are exchanged as UTF-8 here whatever the
/// mount says, which is what `iocharset=utf8` asks for. Any other charset
/// would silently produce different names than it promised, so it is refused
/// rather than accepted and ignored. It does NOT imply the `utf8` option,
/// which is a separate switch and is rendered separately.
/// # C: O(len)
fn charset(val: &str) -> Result<IoCharset, Errno> {
    match val {
        v if v.eq_ignore_ascii_case("utf8") => Ok(IoCharset::Utf8),
        v if v.eq_ignore_ascii_case("iso8859-1") || v.eq_ignore_ascii_case("iso88591") =>
            Ok(IoCharset::Iso88591),
        _ => Err(Errno::Einval),
    }
}

/// # C: O(1)
fn tz(val: &str) -> Result<TimeConfig, Errno> {
    if !val.eq_ignore_ascii_case("UTC") { return Err(Errno::Einval); }
    Ok(TimeConfig::with_offset(0))
}

/// # C: O(len)
fn offset(val: &str) -> Result<TimeConfig, Errno> {
    let minutes: i32 = val.parse().map_err(|_| Errno::Einval)?;
    if !(-MAX_OFFSET_MINUTES..=MAX_OFFSET_MINUTES).contains(&minutes) { return Err(Errno::Einval); }
    Ok(TimeConfig::with_offset(minutes))
}

/// # C: O(1)
fn errors(val: &str) -> Result<Errors, Errno> {
    match val {
        "continue" => Ok(Errors::Continue),
        "panic" => Ok(Errors::Panic),
        "remount-ro" => Ok(Errors::RemountRo),
        _ => Err(Errno::Einval),
    }
}

/// `nfs` alone is the read-write export; the two spellings name the trade
/// each makes. # C: O(1)
fn nfs(val: Option<&str>) -> Result<Nfs, Errno> {
    match val {
        None => Ok(Nfs::StaleRw),
        Some("stale_rw") => Ok(Nfs::StaleRw),
        Some("nostale_ro") => Ok(Nfs::NostaleRo),
        Some(_) => Err(Errno::Einval),
    }
}
