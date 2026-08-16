//! The configuration back into the tail `/proc/mounts` carries.
//!
//! A container runtime reads this line back to reconstruct the mount, so a
//! layer path containing a comma must come back escaped and every option must
//! come back in a spelling the parser accepts. Options left at their build
//! default are omitted, which is what keeps an ordinary line short enough to
//! read.
//!
//! Each option carries its OWN leading comma, which is what the generic
//! per-mount flags in front of it expect.

extern crate alloc;

use alloc::format;
use alloc::string::String;

use crate::config::{Config, FsyncMode, RedirectMode, UuidMode, VerityMode, XinoMode,
                    DEF_FSYNC, DEF_INDEX, DEF_METACOPY, DEF_NFS_EXPORT, DEF_REDIRECT,
                    DEF_UUID, DEF_VERITY, DEF_XINO};

/// Characters that would be read back as structure rather than as part of a
/// path.
const NEEDS_ESCAPE: &[char] = &[',', ' ', '\t', '\n', '\\'];

/// Render `config`. `same_fs` says whether every layer turned out to be on one
/// filesystem, in which case inode-number remapping did nothing and saying so
/// would only mislead. # C: O(total option length)
pub fn show(config: &Config, same_fs: bool) -> String {
    let mut s = String::new();
    match &config.lowerdir_all {
        Some(all) => option(&mut s, "lowerdir", all),
        None => for l in &config.lowerdirs {
            option(&mut s, if l.data_only { "datadir+" } else { "lowerdir+" }, &l.name);
        },
    }
    if let Some(u) = &config.upperdir {
        option(&mut s, "upperdir", u);
        option(&mut s, "workdir", config.workdir.as_deref().unwrap_or(""));
    }
    if config.default_permissions { s.push_str(",default_permissions"); }
    if config.redirect_mode != DEF_REDIRECT {
        s.push_str(&format!(",redirect_dir={}", redirect(config.redirect_mode)));
    }
    if config.index != DEF_INDEX { s.push_str(&format!(",index={}", on_off(config.index))); }
    if config.uuid != DEF_UUID { s.push_str(&format!(",uuid={}", uuid(config.uuid))); }
    if config.nfs_export != DEF_NFS_EXPORT {
        s.push_str(&format!(",nfs_export={}", on_off(config.nfs_export)));
    }
    if config.xino != DEF_XINO && !same_fs { s.push_str(&format!(",xino={}", xino(config.xino))); }
    if config.metacopy != DEF_METACOPY {
        s.push_str(&format!(",metacopy={}", on_off(config.metacopy)));
    }
    if config.fsync_mode != DEF_FSYNC { s.push_str(&format!(",fsync={}", fsync(config.fsync_mode))); }
    if config.userxattr { s.push_str(",userxattr"); }
    if config.verity_mode != DEF_VERITY {
        s.push_str(&format!(",verity={}", verity(config.verity_mode)));
    }
    s
}

/// One `key=value`, with the value escaped. # C: O(len(value))
fn option(s: &mut String, key: &str, value: &str) {
    s.push(',');
    s.push_str(key);
    s.push('=');
    for c in value.chars() {
        if NEEDS_ESCAPE.contains(&c) { s.push('\\'); }
        s.push(c);
    }
}

/// # C: O(1)
fn on_off(v: bool) -> &'static str { if v { "on" } else { "off" } }

/// # C: O(1)
fn redirect(m: RedirectMode) -> &'static str {
    match m {
        RedirectMode::Follow => "follow",
        RedirectMode::NoFollow => "nofollow",
        RedirectMode::On => "on",
    }
}

/// # C: O(1)
fn uuid(m: UuidMode) -> &'static str {
    match m {
        UuidMode::Off => "off", UuidMode::Null => "null",
        UuidMode::Auto => "auto", UuidMode::On => "on",
    }
}

/// # C: O(1)
fn xino(m: XinoMode) -> &'static str {
    match m { XinoMode::Off => "off", XinoMode::Auto => "auto", XinoMode::On => "on" }
}

/// # C: O(1)
fn verity(m: VerityMode) -> &'static str {
    match m { VerityMode::Off => "off", VerityMode::On => "on", VerityMode::Require => "require" }
}

/// # C: O(1)
fn fsync(m: FsyncMode) -> &'static str {
    match m {
        FsyncMode::Volatile => "volatile", FsyncMode::Auto => "auto", FsyncMode::Strict => "strict",
    }
}
