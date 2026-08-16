//! Releasing a chain, and cutting one short.
//!
//! Freeing walks and releases in one pass, entry by entry, exactly as the
//! reference does. That is what makes a CIRCULAR chain terminate rather than
//! spin: the first cluster is already free by the time the loop comes back
//! round to it, and a free entry reached mid-chain is a corrupt table, which
//! stops with an error. A walk-then-free would have to carry its own cycle
//! detector and would refuse to reclaim anything from a damaged chain.

use syscall::errno::Errno;

use crate::chain::{self, Link};
use crate::fsinfo::FreeState;
use crate::geometry::{Geometry, FAT_START_ENT};

use super::entry::{end_mark, write_entry, FREE_MARK};

/// Whether `cluster` is a number this volume's table can hold data for.
/// # C: O(1)
pub fn valid_entry(geo: &Geometry, cluster: u32) -> bool {
    cluster >= FAT_START_ENT && cluster < geo.max_cluster
}

/// Release every cluster of the chain starting at `first`, counting each one
/// back into the free total as it goes.
///
/// A link naming a cluster this volume does not have, and a free entry found
/// part-way along, are both corrupt tables and both stop with `EIO` — with
/// everything released so far left released, which is the reference's outcome
/// and the one that reclaims as much as is safely reclaimable.
/// # C: O(chain length)
pub fn free_chain_state(geo: &Geometry, table: &mut [u8], st: &mut FreeState, first: u32)
    -> Result<usize, Errno> {
    let mut freed = 0usize;
    let mut cluster = first;
    loop {
        if !valid_entry(geo, cluster) { return Err(Errno::Eio); }
        let link = chain::read_entry(geo.width, table, cluster).ok_or(Errno::Eio)?;
        // A free entry inside a chain means the file claims a cluster the
        // volume believes nobody owns. Releasing it again would hand one
        // cluster to two files the next time either is extended.
        if link == Link::Free { return Err(Errno::Eio); }
        write_entry(geo.width, table, cluster, FREE_MARK)?;
        st.gave_back();
        freed += 1;
        match link {
            Link::End => break,
            Link::Next(next) => cluster = next,
            Link::Free => break,
        }
    }
    Ok(freed)
}

/// Release a chain without persistent free-cluster state.
/// # C: O(chain length)
pub fn free_chain(geo: &Geometry, table: &mut [u8], first: u32) -> Result<usize, Errno> {
    let mut st = FreeState::new();
    free_chain_state(geo, table, &mut st, first)
}

/// Cut a chain to its first `keep` clusters, releasing the rest.
///
/// The survivor is given an end BEFORE anything after it is freed, so a reader
/// that stops between the two never follows a link into a cluster the table
/// already calls free. A `keep` past the chain's length releases nothing, and
/// a `keep` of zero releases all of it.
/// # C: O(chain length)
pub fn truncate_chain_state(geo: &Geometry, table: &mut [u8], st: &mut FreeState, first: u32,
                            keep: usize) -> Result<usize, Errno> {
    if keep == 0 { return free_chain_state(geo, table, st, first); }
    let Some((last_kept, after)) = seek_kept(geo, table, first, keep)? else { return Ok(0) };
    write_entry(geo.width, table, last_kept, end_mark(geo.width))?;
    free_chain_state(geo, table, st, after)
}

/// Walk `keep` clusters in and report the last one kept together with the
/// first one to drop. `None` when the chain ends at or before that point,
/// which is a truncation with nothing to release.
/// # C: O(keep)
fn seek_kept(geo: &Geometry, table: &[u8], first: u32, keep: usize)
    -> Result<Option<(u32, u32)>, Errno> {
    let mut cluster = first;
    for _ in 0..keep.saturating_sub(1) {
        if !valid_entry(geo, cluster) { return Err(Errno::Eio); }
        match chain::read_entry(geo.width, table, cluster).ok_or(Errno::Eio)? {
            Link::Next(next) => cluster = next,
            // The chain is already shorter than the length asked for.
            Link::End => return Ok(None),
            Link::Free => return Err(Errno::Eio),
        }
    }
    if !valid_entry(geo, cluster) { return Err(Errno::Eio); }
    match chain::read_entry(geo.width, table, cluster).ok_or(Errno::Eio)? {
        Link::Next(next) => Ok(Some((cluster, next))),
        Link::End => Ok(None),
        Link::Free => Err(Errno::Eio),
    }
}

/// Cut a chain short without persistent free-cluster state.
/// # C: O(chain length)
pub fn truncate_chain(geo: &Geometry, table: &mut [u8], first: u32, keep: usize)
    -> Result<usize, Errno> {
    let mut st = FreeState::new();
    truncate_chain_state(geo, table, &mut st, first, keep)
}
