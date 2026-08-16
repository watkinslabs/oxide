//! The per-file set of remembered chain positions.
//!
//! Bounded, least-recently-used, and each entry covers a run: a position is
//! `(offset in file, cluster on disk, how many contiguous clusters follow)`,
//! so one entry answers every offset inside a contiguous run.
//!
//! Invalidation does NOT edit the entries. It bumps a generation number and
//! drops them, and any position a walk was carrying from before the bump is
//! discarded when it tries to record itself. Without that, a walk that started
//! before the chain was truncated could reinstate a position naming clusters
//! the file no longer owns — which is a read of another file's data.

use alloc::vec::Vec;

/// Positions remembered per file. The reference's bound, and small on purpose:
/// the list is walked linearly on every lookup.
pub const FAT_MAX_CACHE: usize = 8;

/// Generation number meaning "this position was not read from the cache", so
/// it can always be recorded. Every real generation is a different value.
pub const CACHE_ALWAYS_VALID: u32 = u32::MAX;

/// One remembered run.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct Run {
    /// Offset of the run's first cluster within the file, in clusters.
    fcluster: u32,
    /// That cluster's number on the volume.
    dcluster: u32,
    /// Contiguous clusters FOLLOWING the first, so a lone cluster is zero.
    nr_contig: u32,
}

/// A position being built by a walk, together with the generation it was
/// started under.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct CacheId {
    pub id: u32,
    /// `None` while the walk has not established a position worth recording.
    pub fcluster: Option<u32>,
    pub dcluster: u32,
    pub nr_contig: u32,
}

impl CacheId {
    /// A position no walk has established yet — recording it does nothing.
    /// # C: O(1)
    pub fn dummy() -> Self {
        CacheId { id: CACHE_ALWAYS_VALID, fcluster: None, dcluster: 0, nr_contig: 0 }
    }

    /// Begin a run at this offset. # C: O(1)
    pub fn restart(&mut self, fclus: u32, dclus: u32) {
        self.id = CACHE_ALWAYS_VALID;
        self.fcluster = Some(fclus);
        self.dcluster = dclus;
        self.nr_contig = 0;
    }

    /// Extend the run by one cluster, reporting whether `dclus` actually
    /// continues it. A caller that gets `false` restarts the run there.
    /// # C: O(1)
    pub fn extend(&mut self, dclus: u32) -> bool {
        self.nr_contig += 1;
        self.dcluster.checked_add(self.nr_contig) == Some(dclus)
    }
}

/// Remembered positions for one file's chain.
#[derive(Clone, Debug)]
pub struct ChainCache {
    /// Most recently used first.
    runs: Vec<Run>,
    generation: u32,
}

impl Default for ChainCache {
    fn default() -> Self { Self::new() }
}

impl ChainCache {
    /// # C: O(1)
    pub fn new() -> Self { ChainCache { runs: Vec::new(), generation: 0 } }

    /// Remembered positions currently held. # C: O(1)
    pub fn len(&self) -> usize { self.runs.len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.runs.is_empty() }

    /// The nearest remembered position at or before `fclus`.
    ///
    /// Returns the offset and cluster to resume the walk from, and the
    /// position to keep extending. `None` when nothing is remembered below
    /// that offset, which means walking from the chain's start.
    /// # C: O(FAT_MAX_CACHE)
    pub fn lookup(&mut self, fclus: u32) -> Option<(u32, u32, CacheId)> {
        let mut hit: Option<(usize, u32)> = None;
        for (i, run) in self.runs.iter().enumerate() {
            // A run beginning at offset zero is the chain's own start, which a
            // walk reaches for free; the reference does not treat it as a hit.
            if run.fcluster == 0 || run.fcluster > fclus { continue; }
            let better = match hit { None => true, Some((_, best)) => best < run.fcluster };
            if !better { continue; }
            hit = Some((i, run.fcluster));
            if run.fcluster + run.nr_contig >= fclus { break; }
        }
        let (index, _) = hit?;
        let run = self.runs[index];
        let offset = core::cmp::min(run.nr_contig, fclus - run.fcluster);
        self.touch(index);
        let cid = CacheId {
            id: self.generation,
            fcluster: Some(run.fcluster),
            dcluster: run.dcluster,
            nr_contig: run.nr_contig,
        };
        Some((run.fcluster + offset, run.dcluster + offset, cid))
    }

    /// Record a position a walk established.
    ///
    /// Dropped silently when the walk began before the last invalidation, or
    /// when it never established one. A position already held is widened
    /// rather than duplicated.
    /// # C: O(FAT_MAX_CACHE)
    pub fn add(&mut self, cid: &CacheId) {
        let Some(fcluster) = cid.fcluster else { return; };
        if cid.id != CACHE_ALWAYS_VALID && cid.id != self.generation { return; }
        if let Some(i) = self.runs.iter().position(|r| r.fcluster == fcluster) {
            if cid.nr_contig > self.runs[i].nr_contig { self.runs[i].nr_contig = cid.nr_contig; }
            self.touch(i);
            return;
        }
        let run = Run { fcluster, dcluster: cid.dcluster, nr_contig: cid.nr_contig };
        if self.runs.len() < FAT_MAX_CACHE {
            self.runs.insert(0, run);
        } else {
            // Evict the least recently used, which is the last.
            let last = self.runs.len() - 1;
            self.runs[last] = run;
            self.touch(last);
        }
    }

    /// Forget every position, and make any walk still in flight unable to
    /// record what it found. # C: O(FAT_MAX_CACHE)
    pub fn invalidate(&mut self) {
        self.runs.clear();
        self.generation = self.generation.wrapping_add(1);
        if self.generation == CACHE_ALWAYS_VALID { self.generation = self.generation.wrapping_add(1); }
    }

    fn touch(&mut self, index: usize) {
        if index == 0 { return; }
        let run = self.runs.remove(index);
        self.runs.insert(0, run);
    }
}
