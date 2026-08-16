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

use super::{Errors, Options};

/// The charset names are exchanged in on this build.
const IOCHARSET: &str = "utf8";

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
    if o.utf8 { s.push_str(&format!(",iocharset={IOCHARSET}")); }
    s.push_str(errors(o.errors));
    if o.discard { s.push_str(",discard"); }
    if o.keep_last_dots { s.push_str(",keep_last_dots"); }
    if o.sys_tz { s.push_str(",sys_tz"); }
    else if o.time.offset_minutes != 0 {
        s.push_str(&format!(",time_offset={}", o.time.offset_minutes));
    }
    if o.zero_size_dir { s.push_str(",zero_size_dir"); }
    s
}

/// # C: O(1)
fn errors(e: Errors) -> &'static str {
    match e {
        Errors::Continue => ",errors=continue",
        Errors::Panic => ",errors=panic",
        Errors::RemountRo => ",errors=remount-ro",
    }
}

#[cfg(test)]
#[path = "../tests/opts.rs"]
mod tests;
