//! What one mount was asked for, and what it reports back.
//!
//! exFAT stores no owner and no permission bits, so almost every option here
//! is the mount's answer to a question the medium cannot answer. The two that
//! are not — `time_offset=` and `keep_last_dots` — change how the medium's own
//! bytes are read.
//!
//! Module manifest:
//! - `parse`: one `-o` string into an option set.
//! - `show`:  an option set back into the string `/proc/mounts` carries.

use crate::time::TimeConfig;

pub mod parse;
pub mod show;

pub use parse::parse;
pub use show::show;

/// Longest name this filesystem admits, which `statfs` reports.
pub const EXFAT_NAME_MAX: u64 = crate::uapi::MAX_NAME_LENGTH as u64;

/// Permission bits `allow_utime=` may carry: the group and other WRITE bits,
/// and nothing else.
pub const UTIME_BITS: u16 = 0o022;

/// What a mount does when it finds the volume inconsistent.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Errors {
    /// Carry on and log.
    Continue,
    /// Drop the mount to read-only. The default.
    RemountRo,
    /// Stop the machine.
    Panic,
}

/// Everything one mount was asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Options {
    /// Owner every entry presents with — the medium stores none.
    pub uid: u32,
    pub gid: u32,
    /// Permission bits masked OFF files and directories.
    pub fmask: u16,
    pub dmask: u16,
    /// Which write bits a non-owner may still use `utimes` through. `None`
    /// until the mount derives it from `dmask`.
    pub allow_utime: Option<u16>,
    /// Whether names are exchanged as UTF-8. Every mount of this filesystem
    /// does; the option exists because the reference accepts a charset name.
    pub utf8: bool,
    pub errors: Errors,
    /// Whether freed clusters are discarded on the device.
    pub discard: bool,
    /// Whether a name's trailing dots are part of the name.
    pub keep_last_dots: bool,
    /// Whether the machine's own timezone is used for readings that carry no
    /// offset of their own.
    pub sys_tz: bool,
    /// Which local time such readings are in.
    pub time: TimeConfig,
    /// Whether a directory may be created with no cluster allocated at all.
    pub zero_size_dir: bool,
}

impl Options {
    /// What a mount that named nothing gets. # C: O(1)
    pub fn defaults() -> Self {
        Self {
            uid: 0,
            gid: 0,
            fmask: 0,
            dmask: 0,
            allow_utime: None,
            utf8: true,
            errors: Errors::RemountRo,
            discard: false,
            keep_last_dots: false,
            sys_tz: false,
            time: TimeConfig::default(),
            zero_size_dir: false,
        }
    }

    /// Fill in what the mount did not say but must still have.
    ///
    /// `allow_utime` defaults to the directory mask's own write bits, which is
    /// how the reference derives it: a mount that masked write off directories
    /// does not want a non-owner setting times through it either.
    /// # C: O(1)
    pub fn settle(&mut self) {
        if self.allow_utime.is_none() { self.allow_utime = Some(!self.dmask & UTIME_BITS); }
    }

    /// The write bits a non-owner may set times through. # C: O(1)
    pub fn utime_bits(&self) -> u16 { self.allow_utime.unwrap_or(!self.dmask & UTIME_BITS) }
}
