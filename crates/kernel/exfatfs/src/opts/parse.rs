//! One `-o` string into an option set.
//!
//! The three permission masks and `allow_utime=` are OCTAL, everything else
//! decimal. Reading a mask as decimal turns `umask=0077` into a mask of
//! seventy-seven, which masks off bits nobody asked about and leaves the ones
//! they did.

use syscall::errno::Errno;

use crate::time::TimeConfig;

use super::{Errors, Options, UTIME_BITS};

/// Separator between options, and between a key and its value.
const SEP: char = ',';
const ASSIGN: char = '=';

/// Widest offset `time_offset=` accepts, in minutes. Twelve hours either way
/// plus daylight corrections is the real span; the limit is a whole day, so no
/// plausible zone is refused and no absurd one is accepted.
const MAX_OFFSET_MINUTES: i32 = 24 * 60;

/// Parse `data` on top of `base`.
///
/// A key this filesystem does not know is skipped rather than refused: the
/// generic per-mount words travel in the same string, and failing on one would
/// make every ordinary `mount -o ro` fail. A key it DOES know with a value it
/// cannot read is `EINVAL` — that one the caller meant.
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
        "iocharset" => o.utf8 = charset(need(val)?)?,
        "errors" => o.errors = errors(need(val)?)?,
        "time_offset" => o.time = offset(need(val)?)?,
        "discard" => { flag(val)?; o.discard = true; }
        "nodiscard" => { flag(val)?; o.discard = false; }
        "keep_last_dots" => { flag(val)?; o.keep_last_dots = true; }
        "sys_tz" => { flag(val)?; o.sys_tz = true; }
        "zero_size_dir" => { flag(val)?; o.zero_size_dir = true; }
        "nozero_size_dir" => { flag(val)?; o.zero_size_dir = false; }
        _ => {}
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

/// The one charset spelling this build can honour.
///
/// Names on this filesystem are UTF-16 on the medium and UTF-8 at the
/// interface; there is no code-page path to select. Any other charset would
/// silently produce different names than it promised, so it is refused rather
/// than accepted and ignored.
/// # C: O(len)
fn charset(val: &str) -> Result<bool, Errno> {
    if !val.eq_ignore_ascii_case("utf8") { return Err(Errno::Einval); }
    Ok(true)
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
