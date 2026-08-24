//! The option set back into the tail `/proc/mounts` carries.
//!
//! Order and spelling are contract, not presentation: `mount -o remount` and
//! every tool that round-trips a mount table reads this back, so an option
//! rendered in a form the parser does not accept makes a remount fail on a
//! mount that was working.
//!
//! Each option carries its OWN leading comma, which is what the generic
//! per-mount flags in front of it expect.

use alloc::format;
use alloc::string::String;

use crate::name::flags::{SFN_CREATE_WIN95, SFN_CREATE_WINNT, SFN_DISPLAY_LOWER,
                         SFN_DISPLAY_WIN95, SFN_DISPLAY_WINNT};
use crate::name::msdos::NameCheck;

use super::values::{Errors, Nfs, Options};

/// Render `o`. # C: O(number of options)
pub fn show(o: &Options) -> String {
    let mut s = String::new();
    // The two identity options are shown only when they are not root's, which
    // is what makes an untouched mount's line short.
    if o.uid != 0 { s.push_str(&format!(",uid={}", o.uid)); }
    if o.gid != 0 { s.push_str(&format!(",gid={}", o.gid)); }
    s.push_str(&format!(",fmask={:04o}", o.fmask));
    s.push_str(&format!(",dmask={:04o}", o.dmask));
    if let Some(bits) = o.allow_utime {
        if bits != 0 { s.push_str(&format!(",allow_utime={:04o}", bits)); }
    }
    s.push_str(&format!(",codepage={}", o.codepage.number));
    if o.long_names {
        s.push_str(&format!(",iocharset={}", o.iocharset.name()));
        s.push_str(shortname(o.shortname));
    }
    if o.check != NameCheck::Normal { s.push_str(check(o.check)); }
    if o.usefree { s.push_str(",usefree"); }
    if o.quiet { s.push_str(",quiet"); }
    if o.showexec { s.push_str(",showexec"); }
    if o.sys_immutable { s.push_str(",sys_immutable"); }
    if o.long_names {
        if o.utf8 { s.push_str(",utf8"); }
        if o.uni_xlate { s.push_str(",uni_xlate"); }
        if !o.numtail { s.push_str(",nonumtail"); }
        if o.rodir { s.push_str(",rodir"); }
    } else {
        if o.dots_ok { s.push_str(",dotsOK=yes"); }
        if o.nocase { s.push_str(",nocase"); }
    }
    if o.flush { s.push_str(",flush"); }
    if o.time.set {
        // A zero offset is UTC, and is spelled the way it was asked for.
        if o.time.offset_minutes != 0 {
            s.push_str(&format!(",time_offset={}", o.time.offset_minutes));
        } else {
            s.push_str(",tz=UTC");
        }
    }
    s.push_str(errors(o.errors));
    s.push_str(nfs(o.nfs));
    if o.discard { s.push_str(",discard"); }
    if o.dos1xfloppy { s.push_str(",dos1xfloppy"); }
    s
}

/// The `shortname=` word for a display/creation pair.
///
/// A pair no word names is reported as unknown rather than as one of the four:
/// naming the wrong one would tell a remount to set a rule this mount is not
/// using. # C: O(1)
fn shortname(bits: u16) -> &'static str {
    match bits {
        b if b == SFN_DISPLAY_WIN95 | SFN_CREATE_WIN95 => ",shortname=win95",
        b if b == SFN_DISPLAY_WINNT | SFN_CREATE_WINNT => ",shortname=winnt",
        b if b == SFN_DISPLAY_WINNT | SFN_CREATE_WIN95 => ",shortname=mixed",
        b if b == SFN_DISPLAY_LOWER | SFN_CREATE_WIN95 => ",shortname=lower",
        _ => ",shortname=unknown",
    }
}

/// # C: O(1)
fn check(rule: NameCheck) -> &'static str {
    match rule {
        NameCheck::Relaxed => ",check=r",
        NameCheck::Normal => ",check=n",
        NameCheck::Strict => ",check=s",
    }
}

/// # C: O(1)
fn errors(e: Errors) -> &'static str {
    match e {
        Errors::Continue => ",errors=continue",
        Errors::Panic => ",errors=panic",
        Errors::RemountRo => ",errors=remount-ro",
    }
}

/// # C: O(1)
fn nfs(n: Nfs) -> &'static str {
    match n {
        Nfs::Off => "",
        Nfs::StaleRw => ",nfs=stale_rw",
        Nfs::NostaleRo => ",nfs=nostale_ro",
    }
}
