//! One `-o` string into an option set.
//!
//! A name this filesystem KNOWS but this build cannot honour is refused
//! rather than accepted and dropped: a mount that asked for compression and
//! got none, or asked for injected faults and got none, is worse off than one
//! that failed, because it believes it got what it asked for. A name it does
//! not know at all is skipped — the generic per-mount words travel in the same
//! string, and refusing them would break every ordinary `mount -o ro`.

use syscall::errno::Errno;

use crate::fault::{ALL_TYPES};

use super::bounds::{active_logs_ok, inline_xattr_ok, MAX_UNUSABLE_PERC};
use super::compress;
use super::crypt;
use super::jquota::{self, JqFmt, QKind};
use super::spec::Spec;
use super::{AllocMode, BackgroundGc, CompressMode, DiscardUnit, Errors, Fragment, FsyncMode,
            MemoryMode, Mode, Options};

const SEP: char = ',';
const ASSIGN: char = '=';

/// Parse `data` on top of `base`.
///
/// The two quota arrangements are settled against each other once, at the end,
/// rather than as each name arrives: `usrquota` and `usrjquota=` may appear in
/// either order in one string, and whether they conflict is a property of the
/// whole string.
/// # C: O(len(data))
pub fn parse(base: Options, data: &str) -> Result<Options, Errno> {
    let (mut o, _) = parse_spec(base, data)?;
    settle_quotas(&mut o)?;
    Ok(o)
}

/// Settle the two quota arrangements against each other, over one option set.
///
/// A remount does NOT go through here: what it may do depends on what the
/// mount already has, and settling the new line alone would refuse a line that
/// names a file while the running mount already carries the format.
/// # C: O(1)
pub fn settle_quotas(o: &mut Options) -> Result<(), Errno> {
    let (mut usr, mut grp, mut prj) = (o.usrquota, o.grpquota, o.prjquota);
    jquota::settle(&o.jquota, &mut usr, &mut grp, &mut prj)?;
    o.usrquota = usr;
    o.grpquota = grp;
    o.prjquota = prj;
    Ok(())
}

/// Parse, and report which keys the string named.
///
/// The second half is not derivable from the first: an option left at its
/// default and an option explicitly set to that default are the same value and
/// different requests, and the consistency pass answers them differently.
/// # C: O(len(data))
pub fn parse_spec(base: Options, data: &str) -> Result<(Options, Spec), Errno> {
    let mut o = base;
    let mut spec = Spec::none();
    for token in data.split(SEP).map(str::trim).filter(|t| !t.is_empty()) {
        let (key, val) = match token.split_once(ASSIGN) {
            Some((k, v)) => (k, Some(v)),
            None => (token, None),
        };
        one(&mut o, key, val)?;
        note(&mut spec, key);
    }
    Ok((o, spec))
}

/// Record that `key` appeared. # C: O(1)
fn note(s: &mut Spec, key: &str) {
    match key {
        "discard" | "nodiscard" => s.discard = true,
        "discard_unit" => s.discard_unit = true,
        "extent_cache" | "noextent_cache" => s.extent_cache = true,
        "age_extent_cache" => s.age_extent_cache = true,
        "reserve_root" => s.reserve_root = true,
        "reserve_node" => s.reserve_node = true,
        "mode" => s.mode = true,
        "inline_xattr" | "noinline_xattr" => s.inline_xattr = true,
        "inline_xattr_size" => s.inline_xattr_size = true,
        "background_gc" => s.background_gc = true,
        "atgc" => s.atgc = true,
        "flush_merge" | "noflush_merge" => s.flush_merge = true,
        "norecovery" | "disable_roll_forward" => s.recovery = true,
        "nat_bits" => s.nat_bits = true,
        "checkpoint" => s.checkpoint = true,
        "test_dummy_encryption" => s.dummy_policy = true,
        "usrjquota" => s.qname[QKind::User as usize] = true,
        "grpjquota" => s.qname[QKind::Group as usize] = true,
        "prjjquota" => s.qname[QKind::Project as usize] = true,
        "jqfmt" => s.jqfmt = true,
        _ => {}
    }
}

/// Apply one key. # C: O(1)
fn one(o: &mut Options, key: &str, val: Option<&str>) -> Result<(), Errno> {
    match key {
        "background_gc" => o.background_gc = background_gc(need(val)?)?,
        "disable_roll_forward" => { flag(val)?; o.recovery = false; }
        "norecovery" => { flag(val)?; o.recovery = false; o.norecovery = true; }
        "discard" => { flag(val)?; o.discard = true; }
        "discard_unit" => o.discard_unit = discard_unit(need(val)?)?,
        "memory" => o.memory = memory(need(val)?)?,
        "nodiscard" => { flag(val)?; o.discard = false; }
        "user_xattr" => { flag(val)?; o.user_xattr = true; }
        "nouser_xattr" => { flag(val)?; o.user_xattr = false; }
        "acl" => { flag(val)?; o.acl = true; }
        "noacl" => { flag(val)?; o.acl = false; }
        "active_logs" => {
            // Checked at full width BEFORE narrowing: a count that only fits
            // after truncation is a different count, and `active_logs=258`
            // would otherwise mount as two logs.
            let n = dec(val)?;
            if !active_logs_ok(n) { return Err(Errno::Einval); }
            o.active_logs = n as u8;
        }
        "fastboot" => { flag(val)?; o.fastboot = true; }
        // Two names the format still accepts and no longer acts on. Refusing
        // them would break a mount line that has carried them for years;
        // treating them as unknown would accept `heap=3`, which they never
        // took.
        "heap" | "no_heap" => flag(val)?,
        "disable_ext_identify" => { flag(val)?; o.ext_identify = false; }
        "inline_xattr" => { flag(val)?; o.inline_xattr = true; }
        "noinline_xattr" => { flag(val)?; o.inline_xattr = false; }
        "inline_xattr_size" => {
            let n = dec(val)?;
            if !inline_xattr_ok(n) { return Err(Errno::Einval); }
            o.inline_xattr_size = Some(n as u16);
        }
        "inline_data" => { flag(val)?; o.inline_data = true; }
        "noinline_data" => { flag(val)?; o.inline_data = false; }
        "inline_dentry" => { flag(val)?; o.inline_dentry = true; }
        "noinline_dentry" => { flag(val)?; o.inline_dentry = false; }
        "flush_merge" => { flag(val)?; o.flush_merge = true; }
        "noflush_merge" => { flag(val)?; o.flush_merge = false; }
        "barrier" => { flag(val)?; o.barrier = true; }
        "nobarrier" => { flag(val)?; o.barrier = false; }
        "data_flush" => { flag(val)?; o.data_flush = true; }
        "extent_cache" => { flag(val)?; o.extent_cache = true; }
        "noextent_cache" => { flag(val)?; o.extent_cache = false; }
        "age_extent_cache" => { flag(val)?; o.age_extent_cache = true; }
        "reserve_root" => o.reserve_root = dec(val)?,
        "reserve_node" => o.reserve_node = dec(val)?,
        "resuid" => o.resuid = dec(val)?,
        "resgid" => o.resgid = dec(val)?,
        "mode" => o.mode = mode(need(val)?)?,
        "alloc_mode" => o.alloc_mode = alloc_mode(need(val)?)?,
        "fsync_mode" => o.fsync_mode = fsync_mode(need(val)?)?,
        "errors" => o.errors = errors(need(val)?)?,
        "checkpoint" => checkpoint(o, need(val)?)?,
        "checkpoint_merge" => { flag(val)?; o.checkpoint_merge = true; }
        "nocheckpoint_merge" => { flag(val)?; o.checkpoint_merge = false; }
        "lazytime" => { flag(val)?; o.lazytime = true; }
        "nolazytime" => { flag(val)?; o.lazytime = false; }
        "nat_bits" => { flag(val)?; o.nat_bits = true; }
        "gc_merge" => { flag(val)?; o.gc_merge = true; }
        "nogc_merge" => { flag(val)?; o.gc_merge = false; }
        "atgc" => { flag(val)?; o.atgc = true; }
        "lookup_mode" => {
            o.lookup_mode =
                crate::casefold::LookupMode::parse(need(val)?.as_bytes()).ok_or(Errno::Einval)?;
        }
        "quota" | "usrquota" => { flag(val)?; o.usrquota = true; }
        "grpquota" => { flag(val)?; o.grpquota = true; }
        "prjquota" => { flag(val)?; o.prjquota = true; }
        "noquota" => { flag(val)?; o.usrquota = false; o.grpquota = false; o.prjquota = false; }
        // A bare spelling CLEARS the name rather than being refused: that is
        // how a remount takes a quota file back out of the arrangement.
        "usrjquota" => o.jquota.note(QKind::User, val)?,
        "grpjquota" => o.jquota.note(QKind::Group, val)?,
        "prjjquota" => o.jquota.note(QKind::Project, val)?,
        "jqfmt" => o.jquota.fmt = Some(JqFmt::parse(need(val)?).ok_or(Errno::Einval)?),
        "fault_injection" => o.fault.rate = Some(dec_signed(val)?),
        "fault_type" => {
            let n = dec(val)?;
            // The bound the mount interface states is one wider than the set
            // of sites: the single value past the last site is accepted here
            // and dropped where the mask is stored.
            if n > ALL_TYPES.wrapping_add(1) { return Err(Errno::Einval); }
            o.fault.types = Some(n);
        }
        "test_dummy_encryption" => {
            o.dummy_policy = Some(crypt::parse_dummy(o.dummy_policy, val)?);
        }
        // Accepted whether or not the path to the device can encrypt: it moves
        // WHERE the same encryption happens, so a build without it encrypts in
        // the filesystem instead and the caller gets what it asked for.
        "inlinecrypt" => { flag(val)?; o.inlinecrypt = crypt::INLINE_CRYPT; }
        // The compression group. Every one of these is checked for shape here
        // and honoured or dropped later, against the volume: a value out of
        // range is refused even on a volume that could not record it, because
        // it is a mistake in the line rather than a mismatch with the medium.
        "compress_algorithm" => {
            let (a, level) = compress::algorithm(need(val)?)?;
            o.compress.algorithm = a;
            o.compress.level = level;
        }
        "compress_log_size" => o.compress.log_size = compress::log_size(need(val)?)?,
        "compress_extension" => o.compress.extensions.push(need(val)?.as_bytes())?,
        "nocompress_extension" => o.compress.noextensions.push(need(val)?.as_bytes())?,
        "compress_chksum" => { flag(val)?; o.compress.chksum = true; }
        "compress_mode" => o.compress.mode = compress_mode(need(val)?)?,
        // Not part of the group above: it says what this mount does with the
        // clusters it READS, rather than what it writes into a new file.
        "compress_cache" => { flag(val)?; o.compress_cache = true; }
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

/// A decimal value the interface carries as signed.
///
/// The sign is not decoration: a negative one is a value the mount interface
/// accepts and the field it lands in refuses, which produces a mount with that
/// field unset rather than a mount that fails.
/// # C: O(len)
fn dec_signed(val: Option<&str>) -> Result<i32, Errno> {
    need(val)?.parse::<i32>().map_err(|_| Errno::Einval)
}

/// # C: O(1)
fn background_gc(v: &str) -> Result<BackgroundGc, Errno> {
    match v {
        "on" => Ok(BackgroundGc::On),
        "off" => Ok(BackgroundGc::Off),
        "sync" => Ok(BackgroundGc::Sync),
        _ => Err(Errno::Einval),
    }
}

/// # C: O(1)
fn mode(v: &str) -> Result<Mode, Errno> {
    match v {
        "adaptive" => Ok(Mode::Adaptive),
        "lfs" => Ok(Mode::Lfs),
        "fragment:segment" => Ok(Mode::Fragment(Fragment::Segment)),
        "fragment:block" => Ok(Mode::Fragment(Fragment::Block)),
        _ => Err(Errno::Einval),
    }
}

/// # C: O(1)
fn alloc_mode(v: &str) -> Result<AllocMode, Errno> {
    match v {
        "reuse" => Ok(AllocMode::Reuse),
        "default" => Ok(AllocMode::Default),
        _ => Err(Errno::Einval),
    }
}

/// # C: O(1)
fn fsync_mode(v: &str) -> Result<FsyncMode, Errno> {
    match v {
        "posix" => Ok(FsyncMode::Posix),
        "strict" => Ok(FsyncMode::Strict),
        "nobarrier" => Ok(FsyncMode::Nobarrier),
        _ => Err(Errno::Einval),
    }
}

/// # C: O(1)
fn discard_unit(v: &str) -> Result<DiscardUnit, Errno> {
    match v {
        "block" => Ok(DiscardUnit::Block),
        "segment" => Ok(DiscardUnit::Segment),
        "section" => Ok(DiscardUnit::Section),
        _ => Err(Errno::Einval),
    }
}

/// # C: O(1)
fn memory(v: &str) -> Result<MemoryMode, Errno> {
    match v {
        "normal" => Ok(MemoryMode::Normal),
        "low" => Ok(MemoryMode::Low),
        _ => Err(Errno::Einval),
    }
}

/// # C: O(1)
fn compress_mode(v: &str) -> Result<CompressMode, Errno> {
    match v {
        "fs" => Ok(CompressMode::Fs),
        "user" => Ok(CompressMode::User),
        _ => Err(Errno::Einval),
    }
}

/// # C: O(1)
fn errors(v: &str) -> Result<Errors, Errno> {
    match v {
        "continue" => Ok(Errors::Continue),
        "panic" => Ok(Errors::Panic),
        "remount-ro" => Ok(Errors::RemountRo),
        _ => Err(Errno::Einval),
    }
}

/// `checkpoint=` carries four spellings, and two of them differ only by a
/// trailing sign.
///
/// `disable:5` is five BLOCKS the mount may leave unusable; `disable:5%` is
/// five percent of the volume. Reading the first as the second caps a large
/// volume at five blocks, and reading the second as the first caps a small one
/// at five percent of nothing — both leave the mount unable to write long
/// before the caller expected, and neither reports anything.
/// # C: O(len)
fn checkpoint(o: &mut Options, v: &str) -> Result<(), Errno> {
    match v {
        "enable" => {
            o.checkpoint_disabled = false;
            o.unusable_cap = 0;
            o.unusable_cap_perc = 0;
            Ok(())
        }
        "disable" => { o.checkpoint_disabled = true; Ok(()) }
        other => {
            let arg = other.strip_prefix("disable:").ok_or(Errno::Einval)?;
            match arg.strip_suffix('%') {
                Some(pct) => {
                    let n: u32 = pct.parse().map_err(|_| Errno::Einval)?;
                    if n > MAX_UNUSABLE_PERC { return Err(Errno::Einval); }
                    o.unusable_cap_perc = n;
                }
                None => o.unusable_cap = arg.parse().map_err(|_| Errno::Einval)?,
            }
            o.checkpoint_disabled = true;
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "../tests/opts_parse.rs"]
mod tests;
