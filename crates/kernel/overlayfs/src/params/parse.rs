//! One option string into a configuration, and a record of what it named.
//!
//! Order matters in three places and nowhere else: `lowerdir=` discards every
//! layer named before it, `lowerdir+=`/`datadir+=` may not follow it, and a
//! merged layer may not follow a data-only one. Everything else is
//! last-writer-wins, which is what a runtime appending an option to a string
//! it did not build expects.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::config::{Config, FsyncMode, LayerOpt, LowerName, OptSet, RedirectMode, UuidMode,
                    VerityMode, XinoMode, DEF_FSYNC, DEF_REDIRECT};
use crate::limits::MAX_STACK;

use super::split::{options, split_lowerdirs, unescape};

/// A parsed option string: the configuration, and which options were named
/// rather than defaulted.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Parsed {
    pub config: Config,
    pub set: OptSet,
}

/// Parse a whole `-o` string on top of the build defaults.
///
/// An option this filesystem does not know is REFUSED, not skipped: unlike a
/// block filesystem, an overlay has no meaning at all without its layers, and
/// a misspelled `lowerdir` that mounted an empty tree anyway would be worse
/// than a failed mount.
/// # C: O(len(data))
pub fn parse(data: &str) -> Result<Parsed, Errno> {
    let mut p = Parsed { config: Config::default(), set: OptSet::default() };
    for token in options(data) {
        let (key, val) = match token.find('=') {
            Some(i) => (&token[..i], Some(&token[i + 1..])),
            None => (token, None),
        };
        one(&mut p, key, val)?;
    }
    Ok(p)
}

/// Apply one key. # C: O(len(val))
fn one(p: &mut Parsed, key: &str, val: Option<&str>) -> Result<(), Errno> {
    match key {
        "lowerdir" => lowerdir(p, val.ok_or(Errno::Einval)?),
        "lowerdir+" => layer_add(p, need(val)?, LayerOpt::LowerdirAdd),
        "datadir+" => layer_add(p, need(val)?, LayerOpt::DatadirAdd),
        "upperdir" => { p.config.upperdir = Some(unescape(need(val)?)); Ok(()) }
        "workdir" => { p.config.workdir = Some(unescape(need(val)?)); Ok(()) }
        "default_permissions" => { flag(val)?; p.config.default_permissions = true; Ok(()) }
        "redirect_dir" => { p.config.redirect_mode = redirect(need(val)?)?; p.set.redirect = true; Ok(()) }
        "index" => { p.config.index = boolean(need(val)?)?; p.set.index = true; Ok(()) }
        "uuid" => { p.config.uuid = uuid(need(val)?)?; Ok(()) }
        "nfs_export" => { p.config.nfs_export = boolean(need(val)?)?; p.set.nfs_export = true; Ok(()) }
        "userxattr" => { flag(val)?; p.config.userxattr = true; Ok(()) }
        "xino" => { p.config.xino = xino(need(val)?)?; Ok(()) }
        "metacopy" => { p.config.metacopy = boolean(need(val)?)?; p.set.metacopy = true; Ok(()) }
        "verity" => { p.config.verity_mode = verity(need(val)?)?; Ok(()) }
        "fsync" => { p.config.fsync_mode = fsync(need(val)?)?; Ok(()) }
        "volatile" => { flag(val)?; p.config.fsync_mode = FsyncMode::Volatile; Ok(()) }
        "override_creds" => { flag(val)?; p.config.override_creds = true; Ok(()) }
        "nooverride_creds" => { flag(val)?; p.config.override_creds = false; Ok(()) }
        _ => Err(Errno::Einval),
    }
}

/// `lowerdir=` — replace every layer named so far. An empty value leaves no
/// lower layers at all, which is how a runtime clears an inherited list.
/// # C: O(len(spec))
fn lowerdir(p: &mut Parsed, spec: &str) -> Result<(), Errno> {
    p.config.lowerdirs.clear();
    p.config.lowerdir_all = None;
    if spec.is_empty() { return Ok(()); }
    let parts = split_lowerdirs(spec)?;
    if parts.len() > MAX_STACK { return Err(Errno::Einval); }
    p.config.lowerdir_all = Some(spec.to_string());
    p.config.lowerdirs = parts.iter()
        .map(|l| LowerName { name: unescape(&l.raw), data_only: l.data_only })
        .collect::<Vec<_>>();
    Ok(())
}

/// `lowerdir+=` / `datadir+=` — append one layer, with no escape processing:
/// the value is a whole path on its own, so a backslash in it is a backslash.
/// # C: O(len(name))
fn layer_add(p: &mut Parsed, name: &str, opt: LayerOpt) -> Result<(), Errno> {
    if name.is_empty() { return Err(Errno::Einval); }
    // The two forms are not mixable: `lowerdir=` states the whole stack, and
    // an append after it would not be visible in what the mount shows back.
    if p.config.lowerdir_all.is_some() { return Err(Errno::Einval); }
    let data_only = opt == LayerOpt::DatadirAdd;
    if !data_only && p.config.nr_data() > 0 { return Err(Errno::Einval); }
    if p.config.lowerdirs.len() == MAX_STACK { return Err(Errno::Einval); }
    p.config.lowerdirs.push(LowerName { name: name.to_string(), data_only });
    Ok(())
}

/// A key that must carry a value. # C: O(1)
fn need(val: Option<&str>) -> Result<&str, Errno> { val.ok_or(Errno::Einval) }

/// A key that must NOT carry one. # C: O(1)
fn flag(val: Option<&str>) -> Result<(), Errno> { if val.is_some() { Err(Errno::Einval) } else { Ok(()) } }

/// `redirect_dir=`. `off` is never stored as such: with redirects still
/// followed by default it means "do not write one", which is `follow`.
/// # C: O(1)
fn redirect(v: &str) -> Result<RedirectMode, Errno> {
    match v {
        "off" => Ok(DEF_REDIRECT_OFF),
        "follow" => Ok(RedirectMode::Follow),
        "nofollow" => Ok(RedirectMode::NoFollow),
        "on" => Ok(RedirectMode::On),
        _ => Err(Errno::Einval),
    }
}

/// What `redirect_dir=off` resolves to in this build. Following a redirect
/// already on a layer stays on, so an upper layer written by an older mount
/// keeps working; only writing new ones is off.
const DEF_REDIRECT_OFF: RedirectMode = DEF_REDIRECT;

/// `on`/`off`. # C: O(1)
fn boolean(v: &str) -> Result<bool, Errno> {
    match v { "on" => Ok(true), "off" => Ok(false), _ => Err(Errno::Einval) }
}

/// `uuid=`. # C: O(1)
fn uuid(v: &str) -> Result<UuidMode, Errno> {
    match v {
        "off" => Ok(UuidMode::Off), "null" => Ok(UuidMode::Null),
        "auto" => Ok(UuidMode::Auto), "on" => Ok(UuidMode::On),
        _ => Err(Errno::Einval),
    }
}

/// `xino=`. # C: O(1)
fn xino(v: &str) -> Result<XinoMode, Errno> {
    match v {
        "off" => Ok(XinoMode::Off), "auto" => Ok(XinoMode::Auto), "on" => Ok(XinoMode::On),
        _ => Err(Errno::Einval),
    }
}

/// `verity=`. # C: O(1)
fn verity(v: &str) -> Result<VerityMode, Errno> {
    match v {
        "off" => Ok(VerityMode::Off), "on" => Ok(VerityMode::On),
        "require" => Ok(VerityMode::Require),
        _ => Err(Errno::Einval),
    }
}

/// `fsync=`. # C: O(1)
fn fsync(v: &str) -> Result<FsyncMode, Errno> {
    match v {
        "volatile" => Ok(FsyncMode::Volatile), "auto" => Ok(FsyncMode::Auto),
        "strict" => Ok(FsyncMode::Strict),
        _ => Err(Errno::Einval),
    }
}

/// Build default for `fsync=`, exposed so the option display can tell a
/// defaulted value from a named one. # C: O(1)
pub fn fsync_default() -> FsyncMode { DEF_FSYNC }
