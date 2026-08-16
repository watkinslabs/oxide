//! Walking to the Nth cluster of a chain, using and extending the cache.

use syscall::errno::Errno;

use crate::chain::{self, Link};
use crate::cluster_alloc::valid_entry;
use crate::geometry::Geometry;

use super::lru::{CacheId, ChainCache};

/// Target meaning "walk to the chain's last cluster". The reference uses its
/// end-of-chain value for the same purpose.
pub const TO_EOF: u32 = 0x0FFF_FFFF;

/// Where a walk stopped.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Seek {
    /// The offset asked for exists, at this cluster.
    At { fclus: u32, dclus: u32 },
    /// The chain ended first. `fclus`/`dclus` name its last cluster, which is
    /// what a caller appending to the chain needs.
    Eof { fclus: u32, dclus: u32 },
}

impl Seek {
    /// The cluster reached, whether or not it was the one asked for.
    /// # C: O(1)
    pub fn dclus(self) -> u32 {
        match self { Seek::At { dclus, .. } | Seek::Eof { dclus, .. } => dclus }
    }

    /// The offset reached. # C: O(1)
    pub fn fclus(self) -> u32 {
        match self { Seek::At { fclus, .. } | Seek::Eof { fclus, .. } => fclus }
    }
}

/// Walk from `start` to the cluster `target` clusters in, consulting `cache`
/// and recording what the walk learns.
///
/// A free entry part-way along and a link naming a cluster this volume does
/// not have are corrupt tables and stop with `EIO`. So does a walk longer than
/// the volume has clusters, which is the bound that makes a CIRCULAR chain
/// terminate: no honest chain can visit more clusters than exist.
/// # C: O(clusters walked, after the nearest cached position)
pub fn get_cluster(geo: &Geometry, table: &[u8], cache: &mut ChainCache, start: u32, target: u32)
    -> Result<Seek, Errno> {
    if !valid_entry(geo, start) { return Err(Errno::Eio); }
    let mut fclus = 0u32;
    let mut dclus = start;
    if target == 0 { return Ok(Seek::At { fclus, dclus }); }

    let mut cid = match cache.lookup(target) {
        Some((cached_f, cached_d, cid)) => { fclus = cached_f; dclus = cached_d; cid }
        None => CacheId::dummy(),
    };

    while fclus < target {
        // A chain cannot honestly be longer than the volume has clusters, so
        // anything past that is a cycle rather than a very large file.
        if fclus > geo.total_clusters { return Err(Errno::Eio); }
        if !valid_entry(geo, dclus) { return Err(Errno::Eio); }
        match chain::read_entry(geo.width, table, dclus).ok_or(Errno::Eio)? {
            Link::Free => return Err(Errno::Eio),
            Link::End => { cache.add(&cid); return Ok(Seek::Eof { fclus, dclus }); }
            Link::Next(next) => {
                fclus += 1;
                dclus = next;
                if !cid.extend(dclus) { cid.restart(fclus, dclus); }
            }
        }
    }
    // The cluster a walk stops ON is validated too, not just the ones it read
    // through: a link naming a cluster off the volume must never be handed
    // back as a place to read data from.
    if !valid_entry(geo, dclus) { return Err(Errno::Eio); }
    cache.add(&cid);
    Ok(Seek::At { fclus, dclus })
}
