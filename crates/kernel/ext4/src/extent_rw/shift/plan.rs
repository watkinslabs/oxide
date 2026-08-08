// Pure logical-block shift planning for the two fallocate range-shift modes.
// No I/O and no journal: takes the inode's physical extent runs and produces
// the post-shift run list — plus, for a left shift, the data blocks the removed
// range gives back. The tree write and the block frees are the caller's job.

use crate::inode::{self, Extent};
use crate::mount::MountError;
use alloc::vec::Vec;

use crate::extent_rw::EXTENT_LEN_MAX;
use crate::extent_rw::collect::PhysRun;
use crate::extent_rw::records::extent_run;

/// Widest logical block a shift may produce: `ee_block` is 32 bits, so a run
/// whose shifted end passes this cannot be represented.
const LOGICAL_BLOCK_MAX: u64 = u32::MAX as u64;

/// # C: O(1)
fn piece(logical: u64, phys: u64, len: u64, unwritten: bool) -> PhysRun {
    PhysRun { logical: logical as u32, phys, len: len as u32, unwritten }
}

/// Fuse runs that ended up logically AND physically adjacent after a shift,
/// same writtenness, whose combined length still fits one extent record. A
/// left shift routinely makes two runs that straddled the removed range meet.
/// # C: O(N)
fn coalesce(runs: Vec<PhysRun>) -> Vec<PhysRun> {
    let mut out: Vec<PhysRun> = Vec::with_capacity(runs.len());
    for r in runs {
        if let Some(last) = out.last_mut() {
            let joins = last.unwritten == r.unwritten
                && last.logical as u64 + last.len as u64 == r.logical as u64
                && last.phys + last.len as u64 == r.phys
                && last.len as u64 + r.len as u64 <= EXTENT_LEN_MAX as u64;
            if joins { last.len += r.len; continue; }
        }
        out.push(r);
    }
    out
}

/// # C: O(N)
fn to_extents(runs: Vec<PhysRun>) -> Vec<Extent> {
    runs.into_iter().map(|r| extent_run(r.logical, r.phys, r.len, r.unwritten)).collect()
}

/// Left shift: drop logical blocks `[start, start+shift)` and pull everything
/// at or past `start+shift` down by `shift`. Returns the surviving extents in
/// ascending logical order plus the physical blocks the removed range frees.
/// A run straddling either edge is split; a run wholly inside is freed whole.
/// # C: O(N_runs + N_freed_blocks)
pub(in crate::extent_rw) fn plan_collapse(runs: &[PhysRun], start: u32, shift: u32)
    -> (Vec<Extent>, Vec<u64>)
{
    let (start, shift) = (start as u64, shift as u64);
    let end = start + shift;
    let mut out: Vec<PhysRun> = Vec::with_capacity(runs.len() + 1);
    let mut freed: Vec<u64> = Vec::new();
    for r in runs {
        let s = r.logical as u64;
        let e = s + r.len as u64;
        let head_end = e.min(start);
        if s < head_end { out.push(piece(s, r.phys, head_end - s, r.unwritten)); }
        let (mid_start, mid_end) = (s.max(start), e.min(end));
        for b in mid_start..mid_end { freed.push(r.phys + (b - s)); }
        let tail_start = s.max(end);
        if tail_start < e {
            out.push(piece(tail_start - shift, r.phys + (tail_start - s), e - tail_start, r.unwritten));
        }
    }
    out.sort_unstable_by_key(|r| r.logical);
    (to_extents(coalesce(out)), freed)
}

/// Right shift: open a `shift`-block logical hole at `start` by pushing every
/// block at or past `start` up by `shift`. Physical blocks are untouched — no
/// allocation, no free. A run straddling `start` is split there. A shifted run
/// whose end would pass the 32-bit logical block ceiling is rejected.
/// # C: O(N_runs)
pub(in crate::extent_rw) fn plan_insert(runs: &[PhysRun], start: u32, shift: u32)
    -> Result<Vec<Extent>, MountError>
{
    let (start, shift) = (start as u64, shift as u64);
    let mut out: Vec<PhysRun> = Vec::with_capacity(runs.len() + 1);
    for r in runs {
        let s = r.logical as u64;
        let e = s + r.len as u64;
        if e <= start { out.push(piece(s, r.phys, e - s, r.unwritten)); continue; }
        if s < start { out.push(piece(s, r.phys, start - s, r.unwritten)); }
        let moved = s.max(start);
        let shifted = moved + shift;
        if shifted + (e - moved) > LOGICAL_BLOCK_MAX {
            return Err(MountError::Inode(inode::InodeError::BadLen));
        }
        out.push(piece(shifted, r.phys + (moved - s), e - moved, r.unwritten));
    }
    out.sort_unstable_by_key(|r| r.logical);
    Ok(to_extents(coalesce(out)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCKS_PER_RUN: u32 = 4;

    fn run(logical: u32, phys: u64, len: u32) -> PhysRun {
        PhysRun { logical, phys, len, unwritten: false }
    }

    fn shape(extents: &[Extent]) -> Vec<(u32, u64, u32, bool)> {
        extents.iter().map(|e| (e.block, e.start_lba(), e.real_len(), e.is_unwritten())).collect()
    }

    #[test]
    fn collapse_pulls_the_tail_down_and_frees_the_middle() {
        let runs = [run(0, 100, BLOCKS_PER_RUN), run(8, 200, BLOCKS_PER_RUN)];
        let (out, freed) = plan_collapse(&runs, BLOCKS_PER_RUN, BLOCKS_PER_RUN);
        assert_eq!(shape(&out), std::vec![(0, 100, 4, false), (4, 200, 4, false)]);
        assert!(freed.is_empty(), "the removed range was a hole, so nothing is freed");
    }

    #[test]
    fn collapse_frees_exactly_the_blocks_inside_the_range() {
        let runs = [run(0, 100, 12)];
        let (out, freed) = plan_collapse(&runs, 4, 4);
        assert_eq!(freed, std::vec![104, 105, 106, 107]);
        // The two surviving halves are physically discontiguous (104..107 went
        // away) so they stay two extents even though they are logically joined.
        assert_eq!(shape(&out), std::vec![(0, 100, 4, false), (4, 108, 4, false)]);
    }

    #[test]
    fn collapse_rejoins_runs_that_meet_physically_after_the_shift() {
        // A hole at logical 4..8 with the two data runs already physically
        // contiguous: removing the hole makes them one extent.
        let runs = [run(0, 100, 4), run(8, 104, 4)];
        let (out, freed) = plan_collapse(&runs, 4, 4);
        assert!(freed.is_empty());
        assert_eq!(shape(&out), std::vec![(0, 100, 8, false)]);
    }

    #[test]
    fn collapse_splits_a_run_straddling_both_edges() {
        let runs = [run(0, 100, 16)];
        let (out, freed) = plan_collapse(&runs, 4, 8);
        assert_eq!(freed, std::vec![104, 105, 106, 107, 108, 109, 110, 111]);
        assert_eq!(shape(&out), std::vec![(0, 100, 4, false), (4, 112, 4, false)]);
    }

    #[test]
    fn collapse_keeps_writtenness_distinct_across_the_seam() {
        let mut tail = run(8, 104, 4);
        tail.unwritten = true;
        let runs = [run(0, 100, 4), tail];
        let (out, _) = plan_collapse(&runs, 4, 4);
        assert_eq!(shape(&out), std::vec![(0, 100, 4, false), (4, 104, 4, true)],
            "an unwritten run never fuses into a written one");
    }

    #[test]
    fn insert_pushes_the_tail_up_without_touching_physical_blocks() {
        let runs = [run(0, 100, 4), run(4, 104, 4)];
        let out = plan_insert(&runs, 4, 2).unwrap();
        assert_eq!(shape(&out), std::vec![(0, 100, 4, false), (6, 104, 4, false)]);
    }

    #[test]
    fn insert_splits_the_run_containing_the_offset() {
        let runs = [run(0, 100, 8)];
        let out = plan_insert(&runs, 4, 4).unwrap();
        assert_eq!(shape(&out), std::vec![(0, 100, 4, false), (8, 104, 4, false)]);
    }

    #[test]
    fn insert_at_a_run_boundary_moves_the_whole_run() {
        let runs = [run(0, 100, 4), run(4, 200, 4)];
        let out = plan_insert(&runs, 4, 4).unwrap();
        assert_eq!(shape(&out), std::vec![(0, 100, 4, false), (8, 200, 4, false)]);
    }

    #[test]
    fn insert_before_every_run_moves_them_all() {
        let runs = [run(2, 100, 4)];
        let out = plan_insert(&runs, 0, 8).unwrap();
        assert_eq!(shape(&out), std::vec![(10, 100, 4, false)]);
    }

    #[test]
    fn insert_past_the_logical_block_ceiling_is_rejected() {
        let runs = [run(u32::MAX - 8, 100, 4)];
        assert!(plan_insert(&runs, 0, 16).is_err(),
            "a shifted run must stay inside the 32-bit ee_block space");
    }

    #[test]
    fn a_shift_of_zero_blocks_is_the_identity() {
        let runs = [run(0, 100, 4), run(9, 200, 3)];
        let (collapsed, freed) = plan_collapse(&runs, 4, 0);
        assert_eq!(shape(&collapsed), std::vec![(0, 100, 4, false), (9, 200, 3, false)]);
        assert!(freed.is_empty());
        let inserted = plan_insert(&runs, 4, 0).unwrap();
        assert_eq!(shape(&inserted), std::vec![(0, 100, 4, false), (9, 200, 3, false)]);
    }
}
