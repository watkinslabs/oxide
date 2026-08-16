//! Claiming free clusters and linking them into a chain.
//!
//! The scan is the reference's, and its shape is load-bearing in three ways.
//!
//! It starts AFTER the previous allocation's last cluster and WRAPS, so
//! repeated allocations walk forward instead of rescanning the same head, and a
//! volume whose tail is full still allocates from its head.
//!
//! It marks each entry as it finds it rather than deciding the whole run first.
//! An entry is terminated BEFORE the previous one points at it, so a reader
//! that stops between the two sees a chain that ends early rather than one
//! running into an entry that says nothing.
//!
//! And when the volume cannot satisfy the request it gives back everything it
//! had already claimed, records that the volume is now known to be full, and
//! reports the shortfall — so a failed allocation leaks nothing and the count
//! it leaves behind is exact rather than stale.

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::chain::{self, Link};
use crate::fsinfo::FreeState;
use crate::geometry::{Geometry, FAT_START_ENT};

use super::entry::{end_mark, write_entry, FREE_MARK};

/// Claim `count` clusters, linking them into one chain as they are found.
///
/// The state's hint decides where the scan begins and is advanced past every
/// cluster taken; its free count drops by one per cluster and is marked for
/// write-back. A trusted count that is already smaller than the request
/// refuses immediately, touching neither the table nor the hint — the volume
/// is known to be too full to bother scanning.
/// # C: O(total clusters)
pub fn alloc_clusters(geo: &Geometry, table: &mut [u8], st: &mut FreeState, count: usize)
    -> Result<Vec<u32>, Errno> {
    let mut got: Vec<u32> = Vec::with_capacity(count);
    if count == 0 { return Ok(got); }
    if let Some(free) = st.trusted_count() {
        if (free as usize) < count { return Err(Errno::Enospc); }
    }
    let span = geo.max_cluster.saturating_sub(FAT_START_ENT);
    if span == 0 { return Err(Errno::Enospc); }

    let mut cluster = st.hint().wrapping_add(1);
    if cluster >= geo.max_cluster || cluster < FAT_START_ENT { cluster = FAT_START_ENT; }
    let mut err = None;
    for _ in 0..span {
        if chain::read_entry(geo.width, table, cluster) == Some(Link::Free) {
            // Terminate the new tail first, then attach it to the previous
            // cluster: the reverse order publishes a link into an entry that
            // has not been given an end yet.
            match write_entry(geo.width, table, cluster, end_mark(geo.width))
                .and_then(|()| match got.last() {
                    Some(prev) => write_entry(geo.width, table, *prev, cluster),
                    None => Ok(()),
                }) {
                Ok(()) => {}
                Err(e) => { err = Some(e); break; }
            }
            st.took(cluster);
            got.push(cluster);
            if got.len() == count { break; }
        }
        cluster += 1;
        if cluster >= geo.max_cluster { cluster = FAT_START_ENT; }
    }
    if err.is_none() && got.len() < count {
        // The whole table was walked and came up short, so the free count is
        // now known exactly — zero — rather than merely stale.
        st.exhausted();
        err = Some(Errno::Enospc);
    }
    st.mark_dirty();
    match err {
        None => Ok(got),
        Some(e) => { release(geo, table, st, &got); Err(e) }
    }
}

/// Give back clusters a failed allocation had already claimed.
/// # C: O(clusters)
fn release(geo: &Geometry, table: &mut [u8], st: &mut FreeState, clusters: &[u32]) {
    for cluster in clusters {
        if write_entry(geo.width, table, *cluster, FREE_MARK).is_ok() { st.gave_back(); }
    }
}

/// Attach a freshly allocated run to the last cluster of an existing chain.
///
/// Separate from the claim because the reference separates them: the run
/// exists as a valid standalone chain first, and only then becomes part of a
/// file. A failure here releases the run rather than leaving it orphaned.
/// # C: O(1)
pub fn chain_add(geo: &Geometry, table: &mut [u8], st: &mut FreeState, clusters: &[u32], tail: u32)
    -> Result<(), Errno> {
    let Some(first) = clusters.first() else { return Ok(()); };
    match write_entry(geo.width, table, tail, *first) {
        Ok(()) => Ok(()),
        Err(e) => { release(geo, table, st, clusters); Err(e) }
    }
}

/// Link `clusters` into a chain, ending it, and attach it to `tail` when one
/// is given. For a caller that already knows which clusters it holds.
/// # C: O(clusters)
pub fn link_chain(geo: &Geometry, table: &mut [u8], clusters: &[u32], tail: Option<u32>)
    -> Result<(), Errno> {
    if clusters.is_empty() { return Ok(()); }
    for (i, cluster) in clusters.iter().enumerate() {
        let value = match clusters.get(i + 1) { Some(next) => *next, None => end_mark(geo.width) };
        write_entry(geo.width, table, *cluster, value)?;
    }
    if let Some(tail) = tail { write_entry(geo.width, table, tail, clusters[0])?; }
    Ok(())
}

/// Claim `count` clusters and link them, optionally onto an existing chain's
/// last cluster, without persistent free-cluster state.
///
/// A `hint` below the first data cluster means "no previous allocation", which
/// starts the scan at the first data cluster; the reference reaches the same
/// place by wrapping, and so does this. The state is transient, so nothing
/// remembers the hint or the count afterwards — a volume that keeps a
/// `FreeState` should call `alloc_clusters` instead.
/// # C: O(total clusters)
pub fn allocate(geo: &Geometry, table: &mut [u8], hint: u32, count: usize, tail: Option<u32>)
    -> Result<Vec<u32>, Errno> {
    let mut st = FreeState::new();
    st.set_hint(if hint < FAT_START_ENT { geo.max_cluster.saturating_sub(1) } else { hint });
    let got = alloc_clusters(geo, table, &mut st, count)?;
    if let Some(tail) = tail { chain_add(geo, table, &mut st, &got, tail)?; }
    Ok(got)
}
