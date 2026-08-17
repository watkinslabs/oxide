//! Reconciling the drives' write pointers with the volume, at mount.
//!
//! The decisions are `zoned::wp` and the segment-table half is
//! `volume::zonewp`; this is the half that talks to the drives. It runs ONCE,
//! after the mount has replayed whatever a crash left — replay writes, and
//! reconciling before it would settle the logs against a state the replay is
//! about to change.
//!
//! Every zone is asked about AGAIN after a log is moved, rather than reusing
//! the report the pass started from: moving a log changes which zone it
//! stands in, and a stale report would reset the zone the log has just left
//! or leave the one it has just been given un-discarded.

use alloc::vec;

use vfs::{KResult, VfsError};

use block::{BlockError, BlockRequest, ZoneMgmtOp};

use crate::flags::CP_UMOUNT_FLAG;
use crate::uapi::{BLKSIZE, NR_CURSEG_PERSIST_TYPE};
use crate::zoned::report::Zone;
use crate::zoned::{wp, ZoneType};

use super::{devs, errno_to_vfs, F2fs};

/// One member's report for one zone, in the terms each side needs it.
struct Located {
    /// Which member holds it.
    dev: usize,
    /// The zone as the volume addresses it: every block figure shifted by the
    /// member's own offset, so a segment number can be taken from it.
    zone: Zone,
    /// The zone's first block as the DRIVE addresses it, which is how a
    /// management command names a zone.
    dev_start: u64,
}

impl F2fs {
    /// Settle every drive's write pointers against the volume.
    ///
    /// Refused work is reported rather than swallowed: a zone that could not
    /// be reset is one the next allocation will be refused from, and a mount
    /// that hid that would fail later, somewhere with no explanation.
    /// # C: O(zones), plus one report per member
    pub fn check_and_fix_write_pointers(&self) -> KResult<()> {
        {
            let v = self.volume.lock();
            // The reference's own guard, in the same order: a volume with no
            // zones has no pointers, and a mount that may not write can
            // neither repair one nor be harmed by one.
            if v.zones().is_none() || !v.writable() { return Ok(()); }
        }
        self.fix_curseg_write_pointers()?;
        self.check_zone_write_pointers()
    }

    /// Settle each log against the zone it stands in.
    ///
    /// Done before the sweep below, and the sweep then skips the logs' own
    /// zones: repairing one from both sides would reset a zone out from under
    /// a log about to write into it.
    /// # C: O(logs), plus one report per member per log
    fn fix_curseg_write_pointers(&self) -> KResult<()> {
        for log in 0..NR_CURSEG_PERSIST_TYPE {
            let (block, clean) = {
                let v = self.volume.lock();
                (v.curseg_zone_block(log), v.checkpoint().has(CP_UMOUNT_FLAG))
            };
            let Some(block) = block else { continue };
            let Some(at) = self.locate(block) else { continue };
            let facts = self.volume.lock().curseg_facts(log, &at.zone, clean);
            if wp::curseg_agrees(facts) { continue; }
            if wp::needs_new_section(facts) {
                self.volume.lock().open_new_section(log).map_err(errno_to_vfs)?;
            }
            // The zone the log has LEFT is now an ordinary zone and is
            // reconciled as one.
            self.apply(&at)?;
            // And the one it has been given may still be part way written as
            // far as the drive is concerned: free to the filesystem says
            // nothing about what the drive will accept.
            let Some(block) = self.volume.lock().curseg_zone_block(log) else { continue };
            let Some(fresh) = self.locate(block) else { continue };
            let seq = fresh.zone.kind == ZoneType::SeqWriteRequired;
            if wp::new_zone_needs_reset(seq, fresh.zone.at_start()) {
                self.devs[fresh.dev]
                    .zone_mgmt(ZoneMgmtOp::Reset, fresh.dev_start)
                    .map_err(from_block)?;
            }
        }
        Ok(())
    }

    /// Reconcile every zone of every zoned member. # C: O(zones)
    fn check_zone_write_pointers(&self) -> KResult<()> {
        for dev in 0..self.devs.len() {
            for at in self.zones_of(dev) { self.apply(&at)?; }
        }
        Ok(())
    }

    /// Ask the segment tables about one zone and do what they say.
    /// # C: O(segments per section)
    fn apply(&self, at: &Located) -> KResult<()> {
        let facts = {
            let mut v = self.volume.lock();
            let seq = at.zone.kind == ZoneType::SeqWriteRequired;
            v.zone_facts(u32::try_from(at.zone.start_blk).unwrap_or(u32::MAX), seq, at.zone.cond)
                .map_err(errno_to_vfs)?
        };
        match wp::check_zone(facts) {
            wp::Fix::Nothing => Ok(()),
            wp::Fix::Reset => self.devs[at.dev]
                .zone_mgmt(ZoneMgmtOp::Reset, at.dev_start)
                .map_err(from_block),
            wp::Fix::Finish => self.finish(at),
        }
    }

    /// Close a zone whose live blocks and write pointer disagree.
    ///
    /// A drive that has no finish command is closed the long way instead —
    /// the tail is written with zeroes, which leaves the pointer at the end
    /// and the zone full. The blocks being overwritten are past the pointer
    /// and so hold nothing the drive has ever been given.
    /// # C: O(blocks past the pointer) when the drive cannot finish
    fn finish(&self, at: &Located) -> KResult<()> {
        match self.devs[at.dev].zone_mgmt(ZoneMgmtOp::Finish, at.dev_start) {
            Ok(()) => Ok(()),
            Err(BlockError::Eopnotsupp) => self.fill(at),
            Err(e) => Err(from_block(e)),
        }
    }

    /// Write the zone's tail out, from its write pointer to its end.
    /// # C: O(blocks past the pointer)
    fn fill(&self, at: &Located) -> KResult<()> {
        let dev = &self.devs[at.dev];
        let bs = u64::from(dev.block_size().max(1));
        // Nothing to fill when the drive states no pointer: the zone takes a
        // write anywhere, so there is no tail it will refuse.
        let Some(wp_blk) = at.zone.wp_blk else { return Ok(()) };
        let end = at.zone.start_blk + u64::from(at.zone.len_blks);
        let Some(count) = end.checked_sub(wp_blk).filter(|n| *n > 0) else { return Ok(()) };
        // Bytes, not blocks: the two sides count in different units and only
        // the byte figure is common to both. Both quantities are whole
        // multiples of the drive's block, because the report was refused at
        // conversion unless every zone boundary was.
        let into_zone = (wp_blk - at.zone.start_blk) * BLKSIZE as u64;
        let start = at.dev_start + into_zone / bs;
        let blocks = u32::try_from(count * BLKSIZE as u64 / bs).unwrap_or(u32::MAX);
        let bytes = vec![0u8; blocks as usize * bs as usize];
        let mut req = BlockRequest::new_write(start, blocks, bytes);
        dev.submit_sync(&mut req).map_err(from_block)
    }

    /// Every zone one member reports, addressed the way each side needs.
    /// # C: O(zones)
    fn zones_of(&self, dev: usize) -> alloc::vec::Vec<Located> {
        let Some(d) = self.devs.get(dev) else { return alloc::vec::Vec::new() };
        let Some(raw) = d.zone_report() else { return alloc::vec::Vec::new() };
        let starts: alloc::vec::Vec<u64> = raw.zones.iter().map(|z| z.start_block).collect();
        let Some(conv) = devs::convert(raw, d.block_size()) else { return alloc::vec::Vec::new() };
        let shift = self.member_start(dev);
        conv.zones
            .into_iter()
            .zip(starts)
            .map(|(z, dev_start)| Located { dev, zone: shifted(z, shift), dev_start })
            .collect()
    }

    /// The zone holding volume block `block`, if the member holding it has
    /// one. # C: O(zones)
    fn locate(&self, block: u32) -> Option<Located> {
        let (dev, _) = self.volume.lock().devices().target(block);
        self.zones_of(dev).into_iter().find(|at| {
            let end = at.zone.start_blk + u64::from(at.zone.len_blks);
            u64::from(block) >= at.zone.start_blk && u64::from(block) < end
        })
    }

    /// Where member `dev`'s blocks begin on the volume. # C: O(devices)
    fn member_start(&self, dev: usize) -> u64 {
        let v = self.volume.lock();
        u64::from(v.devices().get(dev).map_or(0, |d| d.start_blk))
    }
}

/// The same zone, addressed from the start of the VOLUME rather than of its
/// member. # C: O(1)
fn shifted(mut z: Zone, by: u64) -> Zone {
    z.start_blk += by;
    z.wp_blk = z.wp_blk.map(|w| w + by);
    z
}

/// A block-layer refusal in the filesystem's own error vocabulary.
///
/// The two enums carry the same numbers, so the mapping is the number rather
/// than a per-variant table that could drift from it.
/// # C: O(1)
fn from_block(e: BlockError) -> VfsError { VfsError::from_posix_errno(e as i32) }

#[cfg(test)]
#[path = "../tests/wp.rs"]
mod tests;
