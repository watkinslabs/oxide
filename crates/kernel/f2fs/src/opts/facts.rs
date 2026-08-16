//! The defaults a volume's own shape dictates, rather than the ones a build
//! picks.
//!
//! Several options have no single right value: the right number of logs on a
//! volume whose features permit only reads is two, and six anywhere else;
//! discard is on where the device needs telling and off where it costs
//! throughput for nothing; a zoned volume can only ever be written one way.
//! A build-wide default gets each of those wrong on some volume, and gets it
//! wrong SILENTLY — the mount succeeds and behaves as though the volume were
//! shaped some other way.
//!
//! What is derived here and what is not is the reference's own split. The four
//! settings under `at_mount` are decided once when the volume is opened and
//! survive a remount, because two of them cannot be changed while mounted at
//! all and the other two describe the device rather than the request.

use crate::features;
use crate::uapi::{NR_CURSEG_PERSIST_TYPE, NR_CURSEG_RO_TYPE};

use super::{AllocMode, BackgroundGc, DiscardUnit, Errors, FsyncMode, MemoryMode, Mode, Options};

/// Volumes at or under this many main segments reuse space inside a partly
/// used segment rather than always opening a fresh one.
///
/// A small volume runs out of whole free segments long before it runs out of
/// space, so appending only to fresh ones makes it report `ENOSPC` with a
/// large part of the medium still free.
pub const SMALL_VOLUME_SEGMENTS: u32 = 16 * 512;

/// Everything about the volume and the device that a default reads.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Facts {
    pub feature: u32,
    pub segment_count_main: u32,
    /// Whether the device can be told that blocks are no longer needed.
    pub hw_support_discard: bool,
    /// Whether this mount is read-only, by request or because the medium is.
    pub mount_ro: bool,
}

impl Facts {
    /// A single-device volume on a medium that cannot be discarded, mounted
    /// for writing — what a caller with nothing to say assumes. # C: O(1)
    pub fn plain(feature: u32, segment_count_main: u32) -> Self {
        Self { feature, segment_count_main, hw_support_discard: false, mount_ro: false }
    }

    /// Whether the volume's zones make telling the device mandatory rather
    /// than optional. # C: O(1)
    pub fn hw_should_discard(&self) -> bool { self.zoned() }

    /// # C: O(1)
    pub fn zoned(&self) -> bool { self.feature & crate::flags::FEATURE_BLKZONED != 0 }

    /// Whether the volume itself, not the mount, permits only reads. # C: O(1)
    pub fn sb_readonly(&self) -> bool { self.feature & crate::flags::FEATURE_RO != 0 }

    /// Whether nothing may be written, from either side. # C: O(1)
    pub fn readonly(&self) -> bool { self.sb_readonly() || self.mount_ro }

    /// # C: O(1)
    pub fn device_alias(&self) -> bool { self.feature & crate::flags::FEATURE_DEVICE_ALIAS != 0 }

    /// # C: O(1)
    pub fn extra_attr(&self) -> bool { features::has_extra_attr(self.feature) }

    /// # C: O(1)
    pub fn flexible_inline_xattr(&self) -> bool {
        features::has_flexible_inline_xattr(self.feature)
    }
}

impl Options {
    /// What a mount of a volume with these facts gets before its line is read.
    /// # C: O(1)
    pub fn defaults_for(facts: &Facts) -> Self {
        Self::redefault(Self::defaults(), facts, false)
    }

    /// Reset `base` to the defaults these facts dictate.
    ///
    /// `remount` keeps four settings the mount already resolved: the read
    /// extent cache and the checkpoint switch, because neither may be turned
    /// on or off while mounted, and the discard pair, because those describe
    /// the DEVICE and re-deriving them would undo a `discard_unit` the mount
    /// is already issuing against.
    ///
    /// Everything this does not name keeps its value, which is the point: a
    /// remount that says nothing about the cleaner's threshold or the injected
    /// faults keeps them, and the ones it does say something about are then
    /// applied over this by the parser.
    /// # C: O(1)
    pub fn redefault(base: Options, facts: &Facts, remount: bool) -> Self {
        let mut o = base;
        if !remount {
            o.extent_cache = true;
            o.checkpoint_disabled = false;
            o.discard = facts.hw_support_discard || facts.hw_should_discard();
            o.discard_unit =
                if facts.zoned() { DiscardUnit::Section } else { DiscardUnit::Block };
        }
        // A volume marked read-only at format time was written with two logs
        // and has current-segment slots for no more; opening six would have
        // four of them describing segments the checkpoint never recorded.
        o.active_logs =
            if facts.sb_readonly() { NR_CURSEG_RO_TYPE as u8 } else { NR_CURSEG_PERSIST_TYPE as u8 };
        o.alloc_mode = if facts.segment_count_main <= SMALL_VOLUME_SEGMENTS {
            AllocMode::Reuse
        } else {
            AllocMode::Default
        };
        o.fsync_mode = FsyncMode::Posix;
        o.resuid = 0;
        o.resgid = 0;
        o.background_gc = BackgroundGc::On;
        o.memory = MemoryMode::Normal;
        o.errors = Errors::Continue;
        o.inline_xattr = true;
        o.inline_data = true;
        o.inline_dentry = true;
        o.checkpoint_merge = true;
        o.lazytime = true;
        o.unusable_cap = 0;
        // Merging is a WRITE-side optimisation, and a read-only mount has no
        // flushes to merge; leaving it on would start a thread with nothing to
        // do and make the consistency pass refuse its own default.
        o.flush_merge = !facts.readonly();
        o.mode = if facts.zoned() { Mode::Lfs } else { Mode::Adaptive };
        o.user_xattr = true;
        o.acl = true;
        o.fault = crate::fault::Cfg { rate: None, types: None };
        o.lookup_mode = crate::casefold::DEFAULT_LOOKUP_MODE;
        o
    }

    /// Addresses an inline attribute region reserves in a new inode.
    ///
    /// The mount line's value when it named one, and the format's own
    /// otherwise. Not folded into the field, because the field doubles as the
    /// record of whether the line named it at all — which is what decides
    /// whether the option is reported back and whether the consistency pass
    /// has anything to check.
    /// # C: O(1)
    pub fn inline_xattr_addrs(&self) -> u16 {
        self.inline_xattr_size.unwrap_or(crate::uapi::DEFAULT_INLINE_XATTR_ADDRS as u16)
    }
}

#[cfg(test)]
#[path = "../tests/opts/facts.rs"]
mod tests;
