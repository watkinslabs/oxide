//! Handing one freed run to the member that holds it.
//!
//! The decision is `zoned::discard` and the routing is `announce_free`; this
//! is the half that talks to the drive, and the reason it is a step of its own
//! is that a zoned member takes a DIFFERENT command for the same request. A
//! sequential zone's blocks come back only when its write pointer goes back,
//! so the run becomes a zone RESET; a conventional zone, or a member with no
//! zones, takes the ordinary discard.
//!
//! A run is cut at the ZONE boundaries before anything is sent. A reset
//! addresses one zone and one zone only, so a run spanning two of them is two
//! commands — and cutting it here is what keeps the whole-zone rule below a
//! rule about the drive rather than a limit on how much a checkpoint may free
//! at once.
//!
//! Best effort throughout, in both directions. A refused command costs nothing
//! but space the drive still believes is in use, so it never fails the
//! checkpoint that already landed — and a piece a sequential zone cannot take
//! whole is dropped rather than sent as a discard the drive would ignore.

use block::{BlockRequest, ZoneMgmtOp};

use crate::uapi::BLKSIZE;
use crate::zoned::discard::{action, zone_of, Action};

use super::F2fs;

impl F2fs {
    /// Tell member `dev` it may forget `len` blocks from its own block
    /// `first_blk`, and report the bytes that actually left.
    ///
    /// `None` is "nothing was sent", which covers a member that announces
    /// nothing, a run the two block units cannot express, a refused command,
    /// and a part of a sequential zone. None of those is an error here: the
    /// caller counts traffic, not intent.
    /// # C: O(zones the run spans)
    pub(crate) fn submit_freed(&self, dev: usize, first_blk: u64, len: u32) -> Option<u64> {
        let per = self.zone_blocks();
        if per == 0 { return self.send(dev, first_blk, u64::from(len), Action::Discard); }
        let span = u64::from(per);
        let mut at = first_blk;
        let mut left = u64::from(len);
        let mut total = 0u64;
        while left > 0 {
            // Up to the end of the zone `at` falls in, so every piece belongs
            // to exactly one zone and can be judged whole against it.
            let chunk = core::cmp::min(span - at % span, left);
            let act = match zone_of(at, per) {
                Some(zoneno) => action(self.zone_is_seq(dev, zoneno), at, chunk, per),
                None => Action::Discard,
            };
            if let Some(bytes) = self.send(dev, at, chunk, act) { total += bytes; }
            at += chunk;
            left -= chunk;
        }
        (total > 0).then_some(total)
    }

    /// Put one piece of a run on the wire, and report the bytes that left.
    /// # C: one request
    fn send(&self, dev: usize, first_blk: u64, len: u64, act: Action) -> Option<u64> {
        let d = self.devs.get(dev)?;
        let bytes = len * BLKSIZE as u64;
        let dev_block = u64::from(d.block_size().max(1));
        let byte = first_blk * BLKSIZE as u64;
        // Both figures have to land on the DRIVE's block, whichever command is
        // sent: a reset names a zone by a drive block and a discard names a
        // run by one.
        if byte % dev_block != 0 || bytes % dev_block != 0 { return None; }
        match act {
            // Part of a sequential zone. Announced as an ordinary discard the
            // drive would leave the pointer where it is, so the space would
            // come back here and not there.
            Action::Unaligned => None,
            Action::Reset => {
                d.zone_mgmt(ZoneMgmtOp::Reset, byte / dev_block).ok()?;
                Some(bytes)
            }
            Action::Discard => {
                if !d.supports_discard() { return None; }
                let blocks = u32::try_from(bytes / dev_block).ok()?;
                let mut req = BlockRequest::new_discard(byte / dev_block, blocks);
                d.submit_sync(&mut req).ok()?;
                Some(bytes)
            }
        }
    }

    /// Blocks per zone this volume's members agreed on, or zero when it has no
    /// zones at all. # C: O(1)
    fn zone_blocks(&self) -> u32 {
        self.volume.lock().zones().map_or(0, |g| g.blocks_per_zone)
    }

    /// Whether member `dev`'s zone `zoneno` must be written sequentially.
    ///
    /// Read off the mount's zone map, settled from the drives' own reports at
    /// mount time, rather than a fresh report per run: a report costs a
    /// request and this answer cannot change while the volume is mounted.
    /// # C: O(1)
    fn zone_is_seq(&self, dev: usize, zoneno: usize) -> bool {
        self.volume.lock().zones().is_some_and(|g| g.is_seq(dev, zoneno))
    }
}
