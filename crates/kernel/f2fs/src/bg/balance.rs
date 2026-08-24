//! Keeping the volume able to allocate, at the end of every operation that
//! used space.
//!
//! Two different jobs share the name, and confusing them is how a volume ends
//! up either wedged or checkpointing on every write:
//!
//! - **The blocking one** runs after a write and asks whether the volume can
//!   still serve the NEXT one. If sections are short it cleans, and the caller
//!   waits — there is nothing else it can do, because the space it needs does
//!   not exist yet.
//! - **The background one** runs from the cleaner's own thread and from the
//!   blocking one when the metadata caches have grown, and asks whether a
//!   checkpoint is due. It never cleans. A checkpoint is what turns emptied
//!   segments into free ones and what bounds the work a crash has to replay,
//!   so it is due for reasons that have nothing to do with free space.
//!
//! The decisions are separated from the volume they read so they can be
//! tested on their own: every branch below is a case somebody has to be able
//! to provoke without a medium.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::volume::gc::Policy;
use crate::volume::Volume;

/// Cached node-table entries past which the caches are worth a checkpoint on
/// their own — a checkpoint is the only thing that retires them.
pub const NAT_CACHE_THRESHOLD: usize = 100_000;
/// Segments' worth of dirty metadata entries that make a checkpoint due.
pub const DIRTY_THRESHOLD_SEGS: u64 = 4;
/// Default seconds between checkpoints on an otherwise quiet volume.
pub const CP_INTERVAL_SECS: u64 = 60;

/// Whether `cached` dirty node-table entries out of a table of `max` is enough
/// to be worth a checkpoint on its own, at `ratio` percent.
///
/// Pure and separate from the volume that reads it, because the fixture's node
/// table is large enough that no admissible share can cross the threshold on a
/// handful of entries — so the comparison itself is only checkable here.
/// # C: O(1)
pub fn excess_dirty_nats_at(cached: usize, max: usize, ratio: usize) -> bool {
    cached >= max.saturating_mul(ratio) / 100 && cached > 0
}

/// What the background balance sees when it decides.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct BgState {
    /// A replay is walking the chain a checkpoint would retire.
    pub recovering: bool,
    pub excess_dirty_nats: bool,
    pub excess_dirty_meta: bool,
    pub excess_prefree: bool,
    /// Whether a crash's tail would still fit in what the volume has left.
    pub space_for_roll_forward: bool,
    /// An operation is in flight, or one finished moments ago.
    pub recent_io: bool,
    /// The periodic checkpoint is due.
    pub cp_time_over: bool,
    /// The caches a checkpoint would retire have grown past their threshold.
    pub excess_cached_nats: bool,
}

/// Whether a checkpoint is due.
///
/// The four hard conditions come first and are not negotiable: each names
/// state that only a checkpoint can bound, and a volume that defers one past
/// them either replays forever after a crash or runs out of segments holding
/// space it has already reclaimed.
///
/// The recent-operation test sits BELOW them and above the soft ones. A
/// checkpoint stalls every writer, so one taken because the clock said so
/// while a program is mid-write is a stall nobody asked for; one taken
/// because the volume cannot go on is not optional.
/// # C: O(1)
pub fn needs_checkpoint(s: &BgState) -> bool {
    if s.recovering { return false; }
    if s.excess_dirty_nats || s.excess_dirty_meta || s.excess_prefree
        || !s.space_for_roll_forward { return true; }
    if s.recent_io { return false; }
    if s.cp_time_over { return true; }
    s.excess_cached_nats
}

/// What the blocking balance does after an operation.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct BalanceFs {
    /// Ask the background decision whether a checkpoint is due.
    pub background: bool,
    /// Clean, with the caller waiting.
    pub clean: bool,
}

/// Decide the blocking balance.
///
/// The cache condition is checked even when there is room to allocate: the
/// caches grow with writes, not with fullness, and a volume with plenty of
/// space can still be holding a replay's worth of unretired entries.
/// # C: O(1)
pub fn balance_fs_choice(need: bool, excess_cached_nats: bool, enough_free_secs: bool)
    -> BalanceFs {
    BalanceFs {
        background: need && excess_cached_nats,
        clean: !enough_free_secs,
    }
}

impl<S: SectorSource> Volume<S> {
    /// Node-table entries this mount is holding that a checkpoint would
    /// retire. # C: O(1)
    pub fn cached_nats(&self) -> usize {
        self.nat_dirty.len().saturating_add(self.nat_journal.len())
            .saturating_add(self.nat_cache_count())
    }

    /// Whether enough of the node table is dirty to be worth a checkpoint.
    /// # C: O(1)
    pub fn excess_dirty_nats(&self) -> bool {
        excess_dirty_nats_at(self.cached_nats(), self.max_nid() as usize,
                             self.dirty_nats_ratio() as usize)
    }

    /// Whether the entries themselves have grown past what a mount should
    /// hold between checkpoints. # C: O(1)
    pub fn excess_cached_nats(&self) -> bool { self.cached_nats() >= NAT_CACHE_THRESHOLD }

    /// Whether the changed metadata a checkpoint would write has grown past
    /// what one should carry. # C: O(1)
    pub fn excess_dirty_meta(&self) -> bool {
        let threshold = u64::from(self.sb.blks_per_seg()) * DIRTY_THRESHOLD_SEGS;
        (self.sit_dirty.len() + self.nat_dirty.len()) as u64 >= threshold
    }

    /// Whether the periodic checkpoint is due.
    ///
    /// Measured from the last checkpoint, or from the mount when none has
    /// landed since. Measuring from zero instead would make every mount
    /// overdue at its first tick and take a checkpoint nothing had dirtied.
    /// # C: O(1)
    pub fn cp_time_over(&self) -> bool {
        let base = match self.segstate.last_cp_clock {
            0 => self.segstate.mounted_clock.unwrap_or(self.clock),
            at => at,
        };
        self.clock.saturating_sub(base) > self.cp_interval_secs
    }

    /// Periodic checkpoint interval in seconds. # C: O(1)
    pub fn cp_interval(&self) -> u64 { self.cp_interval_secs }

    /// Set the periodic checkpoint interval in seconds. # C: O(1)
    pub fn set_cp_interval(&mut self, value: u64) { self.cp_interval_secs = value; }

    /// Seconds allowed for the final unmount discard drain. # C: O(1)
    pub fn umount_discard_timeout(&self) -> u64 { self.umount_discard_timeout_secs }

    /// Set the final unmount discard drain timeout in seconds. # C: O(1)
    pub fn set_umount_discard_timeout(&mut self, value: u64) {
        self.umount_discard_timeout_secs = value;
    }

    /// Sections the allocator could still open. # C: O(main segments)
    pub fn free_section_count(&self) -> u32 {
        let per_sec = self.sb.segs_per_sec.max(1);
        let n = self.sb.segment_count_main;
        (0..n).step_by(per_sec as usize)
            .filter(|&first| (first..(first + per_sec).min(n)).all(|s| self.seg_is_free(s)))
            .count() as u32
    }

    /// Sections held back so the cleaner always has a destination.
    /// # C: O(1)
    pub fn reserved_sections(&self) -> u32 {
        let per_sec = self.sb.segs_per_sec.max(1);
        self.gc_reserve().div_ceil(per_sec).max(1)
    }

    /// Sections the metadata this mount has changed will need when it is
    /// written.
    ///
    /// Changed entries are not free space: every one of them becomes a block
    /// in the next checkpoint, and a volume with exactly enough sections for
    /// its data has none for the metadata describing it.
    /// # C: O(1)
    pub fn secs_required(&self) -> u32 {
        let per_sec = u32::from(self.sb.blks_per_seg() as u16).saturating_mul(
            self.sb.segs_per_sec.max(1)).max(1);
        let blocks = (self.sit_dirty.len() + self.nat_dirty.len()) as u32;
        blocks.div_ceil(per_sec)
    }

    /// Whether the volume can serve `needed` more sections after `freed` come
    /// back.
    ///
    /// A replay is exempt: it is rewriting blocks that already existed, and
    /// refusing it for want of space would leave a volume that cannot be
    /// mounted at all.
    /// # C: O(main segments)
    pub fn has_enough_free_secs(&self, freed: u32, needed: u32) -> bool {
        if self.recovering { return true; }
        self.free_section_count() + freed
            >= needed + self.reserved_sections() + self.secs_required()
    }

    /// Share of the volume in use, as a percentage. # C: O(1)
    pub fn utilization(&self) -> u32 {
        let user = u64::from(self.cp.user_block_count).max(1);
        (self.valid_block_count.min(user) * 100 / user) as u32
    }

    /// What the background balance sees right now. # C: O(main segments)
    pub fn bg_state(&self, recent_io: bool) -> BgState {
        BgState {
            recovering: self.recovering,
            excess_dirty_nats: self.excess_dirty_nats(),
            excess_dirty_meta: self.excess_dirty_meta(),
            excess_prefree: self.excess_prefree(),
            space_for_roll_forward: self.space_for_roll_forward(),
            recent_io,
            cp_time_over: self.cp_time_over(),
            excess_cached_nats: self.excess_cached_nats(),
        }
    }

    /// Take the checkpoint the background balance calls for, if one is due.
    ///
    /// Never cleans. A checkpoint that has to move live blocks first is the
    /// blocking path's job, and doing it here would stall the thread that is
    /// supposed to be keeping out of the way.
    /// # C: O(main segments), plus a checkpoint when one is due
    pub fn balance_fs_bg(&mut self, _from_bg: bool, recent_io: bool) -> Result<(), Errno> {
        if !self.writable || self.recovering { return Ok(()); }
        self.load_segments()?;
        if !needs_checkpoint(&self.bg_state(recent_io)) { return Ok(()); }
        self.commit_background()
    }

    /// Keep the volume able to allocate, after an operation that used space.
    ///
    /// `need` is whether the operation actually changed the node tree; an
    /// operation that only touched bytes already allocated has not grown the
    /// caches and does not need them looked at.
    /// # C: O(main segments), plus a clean or a checkpoint when one is due
    pub fn balance_fs(&mut self, need: bool, recent_io: bool) -> Result<(), Errno> {
        // A checkpoint failure is not an error the caller can act on: the
        // volume stops instead, which is what keeps a filesystem that can no
        // longer describe itself from writing any more of itself down.
        // Injection is turned off with it, or a stopped volume would keep
        // counting failures for work it is no longer doing.
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::Checkpoint) {
            let _ = crate::fault::build(&self.fault, 0, 0, crate::fault::Which::ALL);
            self.stop_checkpoint(crate::errrec::StopReason::FaultInject, false);
        }
        if !self.writable || self.recovering { return Ok(()); }
        // A clean re-entering itself would find its own half-emptied victim.
        if self.segstate.gc_running { return Ok(()); }
        self.load_segments()?;
        let choice = balance_fs_choice(need, self.excess_cached_nats(),
                                       self.has_enough_free_secs(0, 0));
        if choice.background { self.balance_fs_bg(false, recent_io)?; }
        if !choice.clean { return Ok(()); }
        // One section is what the caller needs to go on. Cleaning to the
        // reserve would make every short write pay for the whole shortfall.
        let target = self.free_segment_count() + self.sb.segs_per_sec.max(1);
        self.collect_with(Policy::Greedy, target).map(|_| ())
    }
}

#[cfg(test)]
#[path = "../tests/bg/balance.rs"]
mod tests;
