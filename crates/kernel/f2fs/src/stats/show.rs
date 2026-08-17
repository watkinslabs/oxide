//! The `status` report, one section per mounted volume.
//!
//! The format is the ABI here, not the numbers: the tools that read this file
//! match on the labels and the column widths, so a field that moves is a
//! field that stops being read. Every line below is therefore written out
//! literally rather than assembled from a table, and the order is fixed.
//!
//! Module manifest:
//! - `head`:  the partition banner, the areas, the policy and the inode counts.
//! - `area`:  the per-log occupancy table and the segment tallies.
//! - `work`:  what checkpointing and cleaning have done.
//! - `cache`: the extent caches and the outstanding-work block.
//! - `tail`:  the block distribution, the write split, spread and memory.

pub mod head;
pub mod area;
pub mod work;
pub mod cache;
pub mod tail;

use alloc::string::String;

use super::sample::General;

/// One volume's section of the report.
///
/// `index` is the volume's position in the list of mounts, which is what the
/// banner numbers; `dev` names the medium; `now` is the wall clock in
/// seconds, which nothing below this layer can read.
/// # C: O(N segments already sampled) — formatting only
pub fn partition(g: &General, dev: &str, index: usize, now: u64) -> String {
    let mut o = String::new();
    head::render(&mut o, g, dev, index, now);
    area::render(&mut o, g);
    work::render(&mut o, g);
    cache::render(&mut o, g);
    tail::render(&mut o, g);
    o
}
