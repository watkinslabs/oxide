//! The stored status bits, what seeds them, and what they persist into.
//!
//! Two directions matter and they are not symmetric. A checkpoint on the
//! medium carries a few of these conditions forward, so a mount SEEDS the word
//! from it; and a checkpoint being written takes some of them back, so the
//! flag word is what composes the checkpoint's. Getting the second direction
//! backwards — reading the condition out of the checkpoint that the checkpoint
//! is supposed to be told — is how a volume that needs `fsck` stops saying so
//! at the first clean checkpoint.

use crate::flags::{CP_DISABLED_FLAG, CP_DISABLED_QUICK_FLAG, CP_FSCK_FLAG,
                   CP_QUOTA_NEED_FSCK_FLAG, CP_RESIZEFS_FLAG};

use super::bits::{self, DERIVED};

/// The conditions the volume already tracks elsewhere, gathered for the one
/// point that composes the word.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Derived {
    /// Whether anything this mount changed is still only in memory.
    pub dirty: bool,
    /// Whether a replay is running.
    pub recovering: bool,
    /// Whether any quota record is waiting for the next checkpoint to write
    /// it back.
    pub quota_dirty: bool,
}

/// Every volume-wide condition this mount stores.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct SbFlags(u64);

impl SbFlags {
    /// A mount that has raised nothing yet. # C: O(1)
    pub const fn new() -> Self { Self(0) }

    /// The conditions the checkpoint on the medium carries forward.
    ///
    /// A volume marked for `fsck`, one whose quota files are suspect, and one
    /// whose checkpointing was turned off on the short timer all say so in the
    /// checkpoint, and a mount that did not pick them up would report a clean
    /// volume and then write a checkpoint that lost the mark.
    /// # C: O(1)
    pub fn at_mount(cp_flags: u32) -> Self {
        let mut f = Self::new();
        if cp_flags & CP_FSCK_FLAG != 0 { f.set(bits::NEED_FSCK); }
        if cp_flags & CP_QUOTA_NEED_FSCK_FLAG != 0 { f.set(bits::QUOTA_NEED_REPAIR); }
        if cp_flags & CP_DISABLED_QUICK_FLAG != 0 { f.set(bits::CP_DISABLED_QUICK); }
        f
    }

    /// Raise a condition. A position the word does not store is not stored:
    /// the volume's own state is the one copy of those. # C: O(1)
    pub fn set(&mut self, pos: u32) { self.0 |= bits::bit(pos) & !DERIVED; }

    /// Lower a condition. # C: O(1)
    pub fn clear(&mut self, pos: u32) { self.0 &= !(bits::bit(pos) & !DERIVED); }

    /// Whether a stored condition is raised. # C: O(1)
    pub fn is_set(&self, pos: u32) -> bool { self.0 & bits::bit(pos) != 0 }

    /// The stored bits alone, without the two the volume tracks itself.
    /// # C: O(1)
    pub fn stored(&self) -> u64 { self.0 }

    /// The whole status word, stored bits and derived ones together. This is
    /// the only place the two are joined. # C: O(1)
    pub fn word(&self, d: Derived) -> u64 {
        let mut w = self.0;
        if d.dirty { w |= bits::bit(bits::IS_DIRTY); }
        if d.recovering { w |= bits::bit(bits::POR_DOING); }
        if d.quota_dirty { w |= bits::bit(bits::QUOTA_NEED_FLUSH); }
        w
    }

    /// The checkpoint flag word this mount's conditions produce, given the one
    /// the current checkpoint carries.
    ///
    /// The `fsck` mark is the asymmetric one: it is set from the live
    /// condition and NEVER cleared here, because the volume stays suspect
    /// until a checker says otherwise, and a checkpoint that dropped the mark
    /// would silently retire it.
    /// # C: O(1)
    pub fn cp_flags(&self, base: u32) -> u32 {
        let mut f = base;
        if self.is_set(bits::NEED_FSCK) { f |= CP_FSCK_FLAG; }
        f = set_or_clear(f, CP_RESIZEFS_FLAG, self.is_set(bits::IS_RESIZEFS));
        f = set_or_clear(f, CP_DISABLED_FLAG, self.is_set(bits::CP_DISABLED));
        f = set_or_clear(f, CP_DISABLED_QUICK_FLAG, self.is_set(bits::CP_DISABLED_QUICK));
        f = set_or_clear(f, CP_QUOTA_NEED_FSCK_FLAG, self.is_set(bits::QUOTA_SKIP_FLUSH));
        if self.is_set(bits::QUOTA_NEED_REPAIR) { f |= CP_QUOTA_NEED_FSCK_FLAG; }
        f
    }

    /// What a written checkpoint retires: the dirty mark is the volume's own,
    /// and these are the two this word holds. # C: O(1)
    pub fn checkpointed(&mut self) {
        self.clear(bits::NEED_CP);
        self.clear(bits::QUOTA_SKIP_FLUSH);
    }

    /// Turn checkpointing off for this mount. # C: O(1)
    pub fn disable_checkpoint(&mut self, quick: bool) {
        self.set(bits::CP_DISABLED);
        if quick { self.set(bits::CP_DISABLED_QUICK); }
    }

    /// Begin turning checkpointing back on. Writes taken while this is raised
    /// are the ones the enable is waiting for, so it is lowered only once they
    /// have been taken. # C: O(1)
    pub fn begin_enable_checkpoint(&mut self) { self.set(bits::ENABLE_CHECKPOINT); }

    /// Finish turning checkpointing back on. # C: O(1)
    pub fn end_enable_checkpoint(&mut self) {
        self.clear(bits::ENABLE_CHECKPOINT);
        self.clear(bits::CP_DISABLED);
        self.clear(bits::CP_DISABLED_QUICK);
    }

    /// Whether a checkpoint is owed before an `fsync` may take the node-chain
    /// path. # C: O(1)
    pub fn need_cp(&self) -> bool { self.is_set(bits::NEED_CP) }

    /// Whether this mount may still write at all. A volume shut down by ioctl
    /// may not, whatever the mount was opened as. # C: O(1)
    pub fn shutdown(&self) -> bool { self.is_set(bits::IS_SHUTDOWN) }

    /// Record that this mount put something back that a crash had left —
    /// orphans, a node chain, or both.
    ///
    /// A latch: it says what THIS mount did, so nothing lowers it. A tool
    /// reading the word after the mount settled would otherwise see a volume
    /// indistinguishable from one that came up clean. # C: O(1)
    pub fn recovered(&mut self) { self.set(bits::IS_RECOVERED); }

    /// Raise and lower the closing mark around a flush taken as if the volume
    /// were going away — an unmount, or a mount going read-only. # C: O(1)
    pub fn set_closing(&mut self, on: bool) {
        if on { self.set(bits::IS_CLOSE); } else { self.clear(bits::IS_CLOSE); }
    }
}

/// One flag, raised or lowered. # C: O(1)
fn set_or_clear(word: u32, flag: u32, on: bool) -> u32 {
    if on { word | flag } else { word & !flag }
}

#[cfg(test)]
#[path = "../tests/sbflags.rs"]
mod tests;
