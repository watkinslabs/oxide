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

use super::{AllocMode, BackgroundGc, Errors, Fragment, FsyncMode, Mode, Options};

/// Render `o`. # C: O(number of options)
pub fn show(o: &Options) -> String {
    let d = Options::defaults();
    let mut s = String::new();
    if o.background_gc != d.background_gc {
        s.push_str(match o.background_gc {
            BackgroundGc::On => ",background_gc=on",
            BackgroundGc::Off => ",background_gc=off",
            BackgroundGc::Sync => ",background_gc=sync",
        });
    }
    if !o.recovery { s.push_str(",disable_roll_forward"); }
    s.push_str(if o.discard { ",discard" } else { ",nodiscard" });
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
    if o.data_flush { s.push_str(",data_flush"); }
    s.push_str(if o.extent_cache { ",extent_cache" } else { ",noextent_cache" });
    if o.age_extent_cache { s.push_str(",age_extent_cache"); }
    if o.reserve_root != 0 { s.push_str(&format!(",reserve_root={}", o.reserve_root)); }
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
    if o.checkpoint_disabled { s.push_str(",checkpoint=disable"); }
    if o.checkpoint_merge { s.push_str(",checkpoint_merge"); }
    if o.lazytime { s.push_str(",lazytime"); }
    if o.gc_merge { s.push_str(",gc_merge"); }
    if o.atgc { s.push_str(",atgc"); }
    if o.usrquota { s.push_str(",usrquota"); }
    if o.grpquota { s.push_str(",grpquota"); }
    if o.prjquota { s.push_str(",prjquota"); }
    if o.errors != d.errors {
        s.push_str(match o.errors {
            Errors::Continue => ",errors=continue",
            Errors::Panic => ",errors=panic",
            Errors::RemountRo => ",errors=remount-ro",
        });
    }
    s
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
