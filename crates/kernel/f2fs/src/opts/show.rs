//! The option set back into the tail the mount table carries.
//!
//! Every option rendered here must be one `parse` accepts, in the spelling it
//! accepts: a remount reads this string back, so an option shown in a form the
//! parser refuses makes a remount fail on a mount that was working.
//!
//! Each option carries its own leading comma, which is what the generic
//! per-mount flags in front of it expect.

use alloc::format;
use alloc::string::String;

use super::compress::{algorithm_name, Compress};
use super::{AllocMode, BackgroundGc, CompressMode, DiscardUnit, Errors, Fragment, FsyncMode,
            MemoryMode, Mode, Options};

/// Render `o`, for a volume whose features are `feature`.
///
/// The feature set is a parameter because the compression group is shown only
/// where the volume can record it. Rendering it everywhere would put a codec
/// and a cluster width in the mount table of every volume that has no way to
/// store either, and a remount reading the string back would then be told to
/// configure compression on a volume that cannot have it.
/// # C: O(number of options)
pub fn show(o: &Options, feature: u32) -> String {
    let d = Options::defaults();
    let mut s = String::new();
    if o.background_gc != d.background_gc {
        s.push_str(match o.background_gc {
            BackgroundGc::On => ",background_gc=on",
            BackgroundGc::Off => ",background_gc=off",
            BackgroundGc::Sync => ",background_gc=sync",
        });
    }
    // The two spellings are rendered apart, because only one of them is
    // refused on a writable mount and a remount reads this string back.
    if !o.recovery && !o.norecovery { s.push_str(",disable_roll_forward"); }
    if o.norecovery { s.push_str(",norecovery"); }
    s.push_str(if o.discard { ",discard" } else { ",nodiscard" });
    if o.discard_unit != d.discard_unit {
        s.push_str(match o.discard_unit {
            DiscardUnit::Block => ",discard_unit=block",
            DiscardUnit::Segment => ",discard_unit=segment",
            DiscardUnit::Section => ",discard_unit=section",
        });
    }
    if o.memory != d.memory {
        s.push_str(match o.memory {
            MemoryMode::Normal => ",memory=normal",
            MemoryMode::Low => ",memory=low",
        });
    }
    s.push_str(if o.user_xattr { ",user_xattr" } else { ",nouser_xattr" });
    s.push_str(if o.acl { ",acl" } else { ",noacl" });
    if o.active_logs != d.active_logs { s.push_str(&format!(",active_logs={}", o.active_logs)); }
    if !o.ext_identify { s.push_str(",disable_ext_identify"); }
    s.push_str(if o.inline_xattr { ",inline_xattr" } else { ",noinline_xattr" });
    if let Some(n) = o.inline_xattr_size { s.push_str(&format!(",inline_xattr_size={n}")); }
    s.push_str(if o.inline_data { ",inline_data" } else { ",noinline_data" });
    s.push_str(if o.inline_dentry { ",inline_dentry" } else { ",noinline_dentry" });
    if o.flush_merge { s.push_str(",flush_merge"); }
    if !o.barrier { s.push_str(",nobarrier"); }
    if o.fastboot { s.push_str(",fastboot"); }
    if o.data_flush { s.push_str(",data_flush"); }
    s.push_str(if o.extent_cache { ",extent_cache" } else { ",noextent_cache" });
    if o.age_extent_cache { s.push_str(",age_extent_cache"); }
    if o.reserve_root != 0 { s.push_str(&format!(",reserve_root={}", o.reserve_root)); }
    if o.reserve_node != 0 { s.push_str(&format!(",reserve_node={}", o.reserve_node)); }
    if o.resuid != 0 { s.push_str(&format!(",resuid={}", o.resuid)); }
    if o.resgid != 0 { s.push_str(&format!(",resgid={}", o.resgid)); }
    s.push_str(mode(o.mode));
    if o.alloc_mode != d.alloc_mode {
        s.push_str(match o.alloc_mode {
            AllocMode::Reuse => ",alloc_mode=reuse",
            AllocMode::Default => ",alloc_mode=default",
        });
    }
    s.push_str(match o.fsync_mode {
        FsyncMode::Posix => ",fsync_mode=posix",
        FsyncMode::Strict => ",fsync_mode=strict",
        FsyncMode::Nobarrier => ",fsync_mode=nobarrier",
    });
    // The cap is rendered in the spelling it was given in: rendering a
    // percentage as blocks, or the other way round, would remount the volume
    // under a different cap than it is running with.
    if o.checkpoint_disabled {
        if o.unusable_cap_perc != 0 {
            s.push_str(&format!(",checkpoint=disable:{}%", o.unusable_cap_perc));
        } else if o.unusable_cap != 0 {
            s.push_str(&format!(",checkpoint=disable:{}", o.unusable_cap));
        } else {
            s.push_str(",checkpoint=disable");
        }
    }
    if o.checkpoint_merge { s.push_str(",checkpoint_merge"); }
    if o.lazytime { s.push_str(",lazytime"); }
    if o.gc_merge { s.push_str(",gc_merge"); }
    if o.atgc { s.push_str(",atgc"); }
    if o.lookup_mode != d.lookup_mode {
        s.push_str(&format!(",lookup_mode={}", o.lookup_mode.name()));
    }
    if o.usrquota { s.push_str(",usrquota"); }
    if o.grpquota { s.push_str(",grpquota"); }
    if o.prjquota { s.push_str(",prjquota"); }
    jquota(&mut s, o);
    if let Some(p) = &o.dummy_policy { s.push_str(crate::opts::crypt::show_dummy(p)); }
    if o.inlinecrypt { s.push_str(",inlinecrypt"); }
    if crate::features::has_compression(feature) { compress(&mut s, &o.compress); }
    // Shown only when the mount asked, so an ordinary line stays short — and
    // shown in FULL when it did, because a volume running with injected
    // failures must never look like one that is not.
    // Each field is rendered only if the mount named it: naming a rate alone
    // and naming a rate with an empty site list are different requests, and
    // rendering the second for the first would change what a remount arms.
    if let Some(rate) = o.fault.rate { s.push_str(&format!(",fault_injection={rate}")); }
    if let Some(ty) = o.fault.types { s.push_str(&format!(",fault_type={ty}")); }
    if o.errors != d.errors {
        s.push_str(match o.errors {
            Errors::Continue => ",errors=continue",
            Errors::Panic => ",errors=panic",
            Errors::RemountRo => ",errors=remount-ro",
        });
    }
    s
}

/// The compression group, in full.
///
/// Rendered in full rather than only where it differs from a default, because
/// what a file is created with is not recoverable from the file afterwards: a
/// caller reading the mount table has to be able to say what the next file it
/// creates will be compressed with, and "whatever the build's default is" is
/// not an answer a remount can restate.
///
/// The level rides on the codec's own name, in the one spelling the parser
/// takes it in — a level rendered as a name of its own would be read back as
/// an unknown option and silently dropped.
/// # C: O(entries)
fn compress(s: &mut String, c: &Compress) {
    s.push_str(&format!(",compress_algorithm={}", algorithm_name(c.algorithm)));
    if c.level != 0 { s.push_str(&format!(":{}", c.level)); }
    s.push_str(&format!(",compress_log_size={}", c.log_size));
    for e in c.extensions.iter() {
        s.push_str(",compress_extension=");
        s.push_str(&String::from_utf8_lossy(e));
    }
    for e in c.noextensions.iter() {
        s.push_str(",nocompress_extension=");
        s.push_str(&String::from_utf8_lossy(e));
    }
    if c.chksum { s.push_str(",compress_chksum"); }
    s.push_str(match c.mode {
        CompressMode::Fs => ",compress_mode=fs",
        CompressMode::User => ",compress_mode=user",
    });
}

/// The legacy arrangement: the format first, then one name per kind.
///
/// The format leads because it is what makes the names readable at all; a line
/// carrying names with no format describes files nothing can parse.
/// # C: O(names)
fn jquota(s: &mut String, o: &Options) {
    if let Some(f) = o.jquota.fmt { s.push_str(&format!(",jqfmt={}", f.name())); }
    const NAMES: [(crate::opts::QKind, &str); 3] = [
        (crate::opts::QKind::User, "usrjquota"),
        (crate::opts::QKind::Group, "grpjquota"),
        (crate::opts::QKind::Project, "prjjquota"),
    ];
    for (kind, spelling) in NAMES {
        if let Some(n) = &o.jquota.names[kind as usize] {
            s.push_str(&format!(",{spelling}={}", n.as_str()));
        }
    }
}

/// # C: O(1)
fn mode(m: Mode) -> &'static str {
    match m {
        Mode::Adaptive => ",mode=adaptive",
        Mode::Lfs => ",mode=lfs",
        Mode::Fragment(Fragment::Segment) => ",mode=fragment:segment",
        Mode::Fragment(Fragment::Block) => ",mode=fragment:block",
    }
}

#[cfg(test)]
#[path = "../tests/opts_show.rs"]
mod tests;
