//! The option set itself, and the two defaults each filesystem type starts
//! from.
//!
//! `vfat` and `msdos` are two filesystem types sharing one implementation, and
//! the defaults are where they part: one reads and writes long names and
//! displays a short name through its case bits, the other has 8.3 names and
//! nothing else. Everything downstream reads `long_names` rather than asking
//! which type it is.

use crate::name::codepage::{CodePage, CP437};
use crate::name::flags::{SFN_DEFAULT, SFN_MSDOS};
use crate::name::msdos::{NameCheck, Options as ShortOptions};
use crate::name::compare::IoCharset;
use crate::time::TimeConfig;

/// Longest component each type reports to `statfs`. A long name reaches 255
/// characters; an 8.3 name reaches eight, a dot and three.
pub const VFAT_NAME_MAX: u64 = 255;
pub const MSDOS_NAME_MAX: u64 = 12;

/// Permission bits `allow_utime` may carry: the group and other WRITE bits,
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

/// Whether file handles this mount hands out survive a cache eviction.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Nfs {
    /// Not exportable.
    Off,
    /// Handles go stale after eviction; the mount may still be written.
    StaleRw,
    /// Handles stay valid, at the price of a read-only mount.
    NostaleRo,
}

/// Everything one mount was asked for.
#[derive(Clone, Copy)]
pub struct Options {
    /// Whether long-name slots are read and written. The whole difference
    /// between the two filesystem types.
    pub long_names: bool,
    /// Code page the eleven name bytes are written in.
    pub codepage: &'static CodePage,
    /// Charset Linux's `nls_io` uses for long-name comparison.
    pub iocharset: IoCharset,
    /// `shortname=` display and creation rules, as the bits of one word.
    pub shortname: u16,
    /// Whether a name that needs an alias gets a `~N` tail.
    pub numtail: bool,
    /// How hard the 8.3 rules check a name (`check=`).
    pub check: NameCheck,
    /// Whether an 8.3-only mount stores a leading dot as the hidden attribute.
    pub dots_ok: bool,
    /// Whether an 8.3-only mount stores a lowercase name unfolded.
    pub nocase: bool,
    /// Whether long names are exchanged as UTF-8.
    pub utf8: bool,
    /// Whether long names are escaped rather than refused when the charset
    /// cannot spell them.
    pub uni_xlate: bool,
    /// Owner every entry presents with — FAT stores none.
    pub uid: u32,
    pub gid: u32,
    /// Permission bits masked OFF files and directories.
    pub fmask: u16,
    pub dmask: u16,
    /// Which write bits a non-owner may still use `utimes` through. `None`
    /// until the mount derives it from `dmask`.
    pub allow_utime: Option<u16>,
    /// Whether the information sector's free count may be believed at mount.
    pub usefree: bool,
    /// Whether a failed operation is reported quietly.
    pub quiet: bool,
    /// Whether the execute bits follow the extension.
    pub showexec: bool,
    /// Whether the system attribute presents as immutable.
    pub sys_immutable: bool,
    /// Whether every metadata write reaches the medium immediately.
    pub flush: bool,
    /// Whether a read-only directory presents its read-only bit.
    pub rodir: bool,
    /// Whether freed clusters are discarded on the device.
    pub discard: bool,
    /// Whether a volume with no boot signature is accepted.
    pub dos1xfloppy: bool,
    pub errors: Errors,
    pub nfs: Nfs,
    /// Which local time the medium's readings are in.
    pub time: TimeConfig,
}

impl Options {
    /// What a `vfat` mount that named nothing gets. # C: O(1)
    pub fn vfat() -> Self {
        Self {
            long_names: true,
            codepage: &CP437,
            iocharset: IoCharset::DEFAULT,
            shortname: SFN_DEFAULT,
            numtail: true,
            check: NameCheck::Normal,
            dots_ok: false,
            nocase: false,
            utf8: false,
            uni_xlate: false,
            uid: 0,
            gid: 0,
            fmask: 0,
            dmask: 0,
            allow_utime: None,
            usefree: false,
            quiet: false,
            showexec: false,
            sys_immutable: false,
            flush: false,
            rodir: false,
            discard: false,
            dos1xfloppy: false,
            errors: Errors::RemountRo,
            nfs: Nfs::Off,
            time: TimeConfig::default(),
        }
    }

    /// What an `msdos` mount that named nothing gets.
    ///
    /// Three fields differ from the long-name default and each is the reason
    /// the two are separate types: no long-name slots at all, no short-name
    /// display rule to apply, and a read-only directory reported as one —
    /// which the long-name type suppresses because its own tools would then
    /// refuse to descend.
    /// # C: O(1)
    pub fn msdos() -> Self {
        Self { long_names: false, shortname: SFN_MSDOS, rodir: true, ..Self::vfat() }
    }

    /// The 8.3 name rules this mount applies. # C: O(1)
    pub fn short_rules(&self) -> ShortOptions {
        ShortOptions { check: self.check, dots_ok: self.dots_ok, nocase: self.nocase }
    }

    /// Whether two names compare case-sensitively.
    ///
    /// Only the strict rule does. Every other rule folds case, which is what
    /// makes a directory unable to hold both spellings of one name.
    /// # C: O(1)
    pub fn case_sensitive(&self) -> bool { self.check == NameCheck::Strict }

    /// Longest component this mount accepts. # C: O(1)
    pub fn name_max(&self) -> u64 {
        if self.long_names { VFAT_NAME_MAX } else { MSDOS_NAME_MAX }
    }

    /// Fill in what the mount derives rather than reads.
    ///
    /// `allow_utime` is not defaulted to a constant: a mount that masked the
    /// group and other write bits off its directories must not then let a
    /// non-owner set their timestamps through the bits it just removed.
    /// # C: O(1)
    pub fn settle(&mut self) {
        if self.allow_utime.is_none() { self.allow_utime = Some(!self.dmask & UTIME_BITS); }
        // Linux's unicode_xlate path is the legacy NLS conversion path even
        // when both flags were supplied; the escape syntax owns conversion.
        if self.uni_xlate { self.utf8 = false; }
    }
}
