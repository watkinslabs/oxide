// Multi-level security: sensitivity levels with category sets, and the
// dominance relation over them.
//
// Dominance is the whole point of this module and the place a mistake grants
// access: `a` dominates `b` when `a`'s sensitivity is at least `b`'s AND
// `a`'s categories are a superset of `b`'s. Both halves, both directions —
// an inverted comparison here silently lets a low-clearance subject read a
// high-clearance object.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::ebitmap::Ebitmap;
use crate::error::Result;
use crate::reader::Reader;

/// One sensitivity level with its category set.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Level {
    /// Sensitivity value, indexing the policy's level symbol table.
    pub sens: u32,
    /// Category set, indexing the policy's category symbol table.
    pub cat: Ebitmap,
}

/// A low/high pair of levels.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Range {
    /// Lower bound of the range.
    pub low: Level,
    /// Upper bound of the range.
    pub high: Level,
}

impl Level {
    /// Whether two levels are the same sensitivity and category set. # C: O(chunks)
    pub fn eq_level(&self, other: &Self) -> bool {
        self.sens == other.sens && self.cat == other.cat
    }

    /// Whether this level dominates `other`. # C: O(chunks)
    ///
    /// Dominance requires BOTH a sensitivity at least as high AND a category
    /// set containing the other's. Dropping either half turns the lattice
    /// into a total order and grants reads it must refuse.
    pub fn dominates(&self, other: &Self) -> bool {
        self.sens >= other.sens && self.cat.contains(&other.cat)
    }

    /// Whether neither level dominates the other. # C: O(chunks)
    pub fn incomparable(&self, other: &Self) -> bool {
        !self.dominates(other) && !other.dominates(self)
    }

    /// Read one level: sensitivity then category bitmap. # C: O(categories)
    pub fn read(r: &mut Reader<'_>) -> Result<Self> {
        let sens = r.u32()?;
        let cat = Ebitmap::read(r)?;
        Ok(Self { sens, cat })
    }
}

impl Range {
    /// Whether `self` wholly contains `other`. # C: O(chunks)
    ///
    /// Containment is `other.low` dominating `self.low` and `self.high`
    /// dominating `other.high` — the inner range nested inside the outer.
    pub fn contains(&self, other: &Self) -> bool {
        other.low.dominates(&self.low) && self.high.dominates(&other.high)
    }

    /// Whether the range is ordered: high dominates low. # C: O(chunks)
    pub fn is_ordered(&self) -> bool { self.high.dominates(&self.low) }

    /// Range covering only one level. # C: O(chunks)
    pub fn single(level: Level) -> Self { Self { low: level.clone(), high: level } }

    /// Greatest lower bound of two ranges. # C: O(chunks)
    ///
    /// The low end takes the higher sensitivity and the category union; the
    /// high end takes the lower sensitivity and the category intersection.
    pub fn glblub(a: &Self, b: &Self) -> Self {
        let mut low = Level { sens: a.low.sens.max(b.low.sens), cat: a.low.cat.clone() };
        for bit in b.low.cat.iter() { low.cat.set(bit, true); }
        let mut high = Level { sens: a.high.sens.min(b.high.sens), cat: Ebitmap::new() };
        for bit in a.high.cat.iter() { if b.high.cat.get(bit) { high.cat.set(bit, true); } }
        Self { low, high }
    }

    /// Read one range: an item count, the sensitivities, then the category
    /// bitmaps, with a one-item range duplicating its single level. # C: O(categories)
    pub fn read(r: &mut Reader<'_>) -> Result<Self> {
        let items = r.u32()?;
        if items == 0 || items > 2 { return Err(crate::error::Error::Malformed); }
        let low_sens = r.u32()?;
        let high_sens = if items > 1 { r.u32()? } else { low_sens };
        let low_cat = Ebitmap::read(r)?;
        let high_cat = if items > 1 { Ebitmap::read(r)? } else { low_cat.clone() };
        Ok(Self {
            low: Level { sens: low_sens, cat: low_cat },
            high: Level { sens: high_sens, cat: high_cat },
        })
    }
}

/// One maximal run of consecutive categories, inclusive at both ends.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CatRun {
    /// First category of the run.
    pub head: u32,
    /// Last category of the run; equal to `head` for a single member.
    pub tail: u32,
}

impl CatRun {
    /// Separator preceding the tail name, or `None` for a single member. # C: O(1)
    ///
    /// A run of exactly two members is written `head,tail`; three or more is
    /// abbreviated `head.tail`. Getting this boundary wrong renders a two-member
    /// set as a range and silently widens the category set userspace reads back.
    pub const fn tail_separator(self) -> Option<char> {
        match self.tail.wrapping_sub(self.head) {
            0 => None,
            1 => Some(','),
            _ => Some('.'),
        }
    }
}

/// Maximal runs of consecutive categories, ascending. # C: O(categories)
pub fn cat_runs(level: &Level) -> Vec<CatRun> {
    let mut runs: Vec<CatRun> = Vec::new();
    for bit in level.cat.iter() {
        match runs.last_mut() {
            Some(run) if run.tail + 1 == bit => run.tail = bit,
            _ => runs.push(CatRun { head: bit, tail: bit }),
        }
    }
    runs
}

/// Render one level's category list, given a category namer. # C: O(categories)
///
/// The sensitivity name is the caller's to write; this appends only the
/// `:head[,.]tail,...` suffix so the same routine serves both range endpoints.
pub fn write_cat_list<F>(out: &mut String, level: &Level, name: F) -> core::fmt::Result
where F: Fn(&mut String, u32) -> core::fmt::Result,
{
    for (i, run) in cat_runs(level).iter().enumerate() {
        out.push(if i == 0 { ':' } else { ',' });
        name(out, run.head)?;
        if let Some(sep) = run.tail_separator() {
            out.push(sep);
            name(out, run.tail)?;
        }
    }
    Ok(())
}

/// Fallback category name when the policy does not name the value. # C: O(1)
pub fn write_unnamed_cat(out: &mut String, bit: u32) -> core::fmt::Result {
    write!(out, "c{bit}")
}

#[cfg(test)]
#[path = "tests/mls.rs"]
mod tests;
