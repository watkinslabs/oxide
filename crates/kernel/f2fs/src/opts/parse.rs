//! One `-o` string into an option set.
//!
//! A name this filesystem KNOWS but this build cannot honour is refused
//! rather than accepted and dropped: a mount that asked for compression and
//! got none, or asked for injected faults and got none, is worse off than one
//! that failed, because it believes it got what it asked for. A name it does
//! not know at all is skipped — the generic per-mount words travel in the same
//! string, and refusing them would break every ordinary `mount -o ro`.

use syscall::errno::Errno;

use super::{AllocMode, BackgroundGc, Errors, Fragment, FsyncMode, Mode, Options};

const SEP: char = ',';
const ASSIGN: char = '=';

/// Log counts the format admits. Anything else would leave the checkpoint's
/// current-segment array describing logs the volume does not have.
const VALID_ACTIVE_LOGS: [u8; 3] = [2, 4, 6];

/// Parse `data` on top of `base`. # C: O(len(data))
pub fn parse(base: Options, data: &str) -> Result<Options, Errno> {
    let mut o = base;
    for token in data.split(SEP).map(str::trim).filter(|t| !t.is_empty()) {
        let (key, val) = match token.split_once(ASSIGN) {
            Some((k, v)) => (k, Some(v)),
            None => (token, None),
        };
        one(&mut o, key, val)?;
    }
    Ok(o)
}

/// Apply one key. # C: O(1)
fn one(o: &mut Options, key: &str, val: Option<&str>) -> Result<(), Errno> {
    match key {
        "background_gc" => o.background_gc = background_gc(need(val)?)?,
        "disable_roll_forward" => { flag(val)?; o.recovery = false; }
        "norecovery" => { flag(val)?; o.recovery = false; }
        "discard" => { flag(val)?; o.discard = true; }
        "nodiscard" => { flag(val)?; o.discard = false; }
        "user_xattr" => { flag(val)?; o.user_xattr = true; }
        "nouser_xattr" => { flag(val)?; o.user_xattr = false; }
        "acl" => { flag(val)?; o.acl = true; }
        "noacl" => { flag(val)?; o.acl = false; }
        "active_logs" => {
            let n = dec(val)? as u8;
            if !VALID_ACTIVE_LOGS.contains(&n) { return Err(Errno::Einval); }
            o.active_logs = n;
        }
        "disable_ext_identify" => { flag(val)?; o.ext_identify = false; }
        "inline_xattr" => { flag(val)?; o.inline_xattr = true; }
        "noinline_xattr" => { flag(val)?; o.inline_xattr = false; }
        "inline_xattr_size" => o.inline_xattr_size = Some(dec(val)? as u16),
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
        "quota" | "usrquota" => { flag(val)?; o.usrquota = true; }
        "grpquota" => { flag(val)?; o.grpquota = true; }
        "prjquota" => { flag(val)?; o.prjquota = true; }
        "noquota" => { flag(val)?; o.usrquota = false; o.grpquota = false; o.prjquota = false; }
        // Names the format defines that this build cannot deliver. Each one
        // changes what the caller gets, so accepting it silently would be a
        // promise nothing keeps.
        "compress_algorithm"
        | "compress_log_size"
        | "compress_extension"
        | "nocompress_extension"
        | "compress_chksum"
        | "compress_mode"
        | "compress_cache"
        | "test_dummy_encryption"
        | "inlinecrypt"
        | "fault_injection"
        | "fault_type"
        | "memory"
        | "discard_unit"
        | "lookup_mode"
        | "usrjquota"
        | "grpjquota"
        | "prjjquota"
        | "jqfmt" => return Err(Errno::Eopnotsupp),
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
fn errors(v: &str) -> Result<Errors, Errno> {
    match v {
        "continue" => Ok(Errors::Continue),
        "panic" => Ok(Errors::Panic),
        "remount-ro" => Ok(Errors::RemountRo),
        _ => Err(Errno::Einval),
    }
}

/// `checkpoint=` carries three spellings, one of which takes a percentage.
/// # C: O(len)
fn checkpoint(o: &mut Options, v: &str) -> Result<(), Errno> {
    match v {
        "enable" => { o.checkpoint_disabled = false; Ok(()) }
        "disable" => { o.checkpoint_disabled = true; Ok(()) }
        other => match other.strip_prefix("disable:") {
            Some(pct) => {
                let n: u32 = pct.parse().map_err(|_| Errno::Einval)?;
                if n > 100 { return Err(Errno::Einval); }
                o.checkpoint_disabled = true;
                Ok(())
            }
            None => Err(Errno::Einval),
        },
    }
}

#[cfg(test)]
#[path = "../tests/opts_parse.rs"]
mod tests;
