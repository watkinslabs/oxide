//! `_BCL` brightness-level list normalisation.
//!
//! The firmware package is not a clean list: its first two entries are the
//! levels to use on mains and on battery, some tables repeat a level, some
//! omit the two special entries from the real list, and some publish the list
//! in descending order. Userspace is handed a dense `0..max` index, so all of
//! that has to be resolved once, here, where it can be tested without a
//! namespace.

use alloc::vec::Vec;

/// Index of the mains level in the raw package.
pub const AC_LEVEL: usize = 0;
/// Index of the battery level in the raw package.
pub const BATTERY_LEVEL: usize = 1;
/// First raw-package index that is a selectable brightness level.
pub const FIRST_LEVEL: usize = 2;

/// A normalised brightness-level list. `raw` keeps the two special entries at
/// the front so index arithmetic matches the firmware's own numbering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Levels {
    pub raw: Vec<u32>,
    /// The package omitted the mains/battery levels from the real list, so
    /// they were folded in.
    pub synthesised_ac_battery: bool,
    /// The package was published brightest-first.
    pub reversed: bool,
}

impl Levels {
    /// Highest selectable index — the class `max_brightness`. # C: O(1)
    pub fn max_index(&self) -> i32 { (self.raw.len() - FIRST_LEVEL - 1) as i32 }

    /// Firmware level for a selectable index. # C: O(1)
    pub fn level_at(&self, index: i32) -> Option<u32> {
        let index = usize::try_from(index).ok()?;
        self.raw.get(FIRST_LEVEL + index).copied()
    }

    /// Selectable index of a firmware level. # C: O(N_levels)
    pub fn index_of(&self, level: u32) -> Option<i32> {
        self.raw[FIRST_LEVEL..].iter().position(|entry| *entry == level)
            .map(|position| position as i32)
    }

    /// Number of selectable levels. # C: O(1)
    pub fn len(&self) -> usize { self.raw.len() - FIRST_LEVEL }

    /// Whether the list carries no selectable level. # C: O(1)
    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

/// Normalise a raw `_BCL` package. Returns `None` when the package is too
/// short to describe a panel, which is the same thing as the device having no
/// usable backlight. # C: O(N²) worst case on the ordering fix-up
pub fn normalise(package: &[u32]) -> Option<Levels> {
    if package.len() < FIRST_LEVEL { return None; }

    let mut raw: Vec<u32> = Vec::with_capacity(package.len() + FIRST_LEVEL);
    for value in package.iter().copied() {
        // A table that repeats a level would otherwise hand userspace two
        // indexes that do the same thing.
        if raw.len() > FIRST_LEVEL && raw.last() == Some(&value) { continue; }
        raw.push(value);
    }
    let max_level = raw.iter().copied().max()?;

    let mut synthesised_ac_battery = false;
    let duplicates = raw[FIRST_LEVEL..].iter()
        .filter(|entry| **entry == raw[AC_LEVEL] || **entry == raw[BATTERY_LEVEL])
        .count();
    if duplicates < FIRST_LEVEL {
        // The mains/battery entries are themselves selectable levels this
        // table forgot to list; fold them into the list rather than losing
        // two steps off the top of the slider.
        let shift = FIRST_LEVEL - duplicates;
        let previous = raw.clone();
        raw.resize(previous.len() + shift, 0);
        for index in (FIRST_LEVEL..raw.len()).rev() {
            raw[index] = previous[index - shift];
        }
        raw[AC_LEVEL] = previous[AC_LEVEL];
        raw[BATTERY_LEVEL] = previous[BATTERY_LEVEL];
        synthesised_ac_battery = true;
    }

    let reversed = raw.len() > FIRST_LEVEL && raw[FIRST_LEVEL] == max_level;
    if reversed { raw[FIRST_LEVEL..].sort_unstable(); }

    if raw.len() <= FIRST_LEVEL { return None; }
    Some(Levels { raw, synthesised_ac_battery, reversed })
}

/// How a `_BQC` return value must be read. Firmware disagrees on this, so it
/// is settled once by writing a known level and reading it back.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BqcMode {
    /// The method returns the firmware level.
    Level,
    /// The method returns the index into the selectable list.
    Index,
    /// The method agrees with neither and cannot be used.
    Unusable,
}

/// Classify a `_BQC` readback taken right after `written` was programmed.
/// # C: O(N_levels)
pub fn classify_bqc(levels: &Levels, written_index: i32, readback: u64) -> BqcMode {
    let Some(written_level) = levels.level_at(written_index) else { return BqcMode::Unusable; };
    if readback == u64::from(written_level) { return BqcMode::Level; }
    if readback == written_index as u64 { return BqcMode::Index; }
    BqcMode::Unusable
}

/// Convert a `_BQC` return value into a selectable index. # C: O(N_levels)
pub fn bqc_to_index(levels: &Levels, mode: BqcMode, value: u64) -> Option<i32> {
    match mode {
        BqcMode::Unusable => None,
        BqcMode::Index => {
            let index = i32::try_from(value).ok()?;
            if index <= levels.max_index() { Some(index) } else { None }
        }
        BqcMode::Level => levels.index_of(u32::try_from(value).ok()?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_well_formed_package_indexes_from_zero() {
        let levels = normalise(&[100, 50, 0, 25, 50, 75, 100]).expect("levels");
        assert!(!levels.synthesised_ac_battery);
        assert!(!levels.reversed);
        assert_eq!(levels.len(), 5);
        assert_eq!(levels.max_index(), 4);
        assert_eq!(levels.level_at(0), Some(0));
        assert_eq!(levels.level_at(4), Some(100));
        assert_eq!(levels.level_at(5), None);
        assert_eq!(levels.index_of(75), Some(3));
        assert_eq!(levels.index_of(77), None);
    }

    #[test]
    fn a_repeated_level_does_not_become_a_second_slider_step() {
        let levels = normalise(&[100, 50, 0, 50, 50, 100]).expect("levels");
        assert_eq!(levels.raw[FIRST_LEVEL..], [0, 50, 100]);
        assert_eq!(levels.len(), 3);
    }

    #[test]
    fn a_package_that_omits_the_special_levels_gains_them_back() {
        // Neither 90 nor 40 appears in the selectable list, so the table
        // meant them to be selectable too.
        let levels = normalise(&[90, 40, 0, 100]).expect("levels");
        assert!(levels.synthesised_ac_battery);
        assert_eq!(levels.raw[AC_LEVEL], 90);
        assert_eq!(levels.raw[BATTERY_LEVEL], 40);
        assert_eq!(levels.raw[FIRST_LEVEL..], [90, 40, 0, 100]);
        assert_eq!(levels.max_index(), 3);
    }

    #[test]
    fn a_descending_package_is_sorted_so_a_higher_index_is_brighter() {
        let levels = normalise(&[100, 20, 100, 75, 50, 20]).expect("levels");
        assert!(levels.reversed);
        assert_eq!(levels.raw[FIRST_LEVEL..], [20, 50, 75, 100]);
        assert_eq!(levels.level_at(0), Some(20));
        assert_eq!(levels.level_at(levels.max_index()), Some(100));
    }

    #[test]
    fn a_package_with_no_selectable_level_is_not_a_backlight() {
        assert_eq!(normalise(&[]), None);
        assert_eq!(normalise(&[100]), None);
    }

    #[test]
    fn a_readback_is_classified_as_a_level_or_an_index() {
        let levels = normalise(&[100, 50, 0, 25, 50, 75, 100]).expect("levels");
        assert_eq!(classify_bqc(&levels, 3, 75), BqcMode::Level);
        assert_eq!(classify_bqc(&levels, 4, 4), BqcMode::Index);
        assert_eq!(classify_bqc(&levels, 3, 9999), BqcMode::Unusable);
        assert_eq!(classify_bqc(&levels, 99, 0), BqcMode::Unusable);
    }

    #[test]
    fn index_zero_is_ambiguous_and_resolves_as_a_level() {
        // Written index 0 programs level 0, so a readback of 0 matches both
        // readings; taking it as the level is what keeps a firmware that
        // reports levels working.
        let levels = normalise(&[100, 50, 0, 25, 50, 75, 100]).expect("levels");
        assert_eq!(classify_bqc(&levels, 0, 0), BqcMode::Level);
    }

    #[test]
    fn a_readback_converts_back_to_the_index_userspace_sees() {
        let levels = normalise(&[100, 50, 0, 25, 50, 75, 100]).expect("levels");
        assert_eq!(bqc_to_index(&levels, BqcMode::Level, 50), Some(2));
        assert_eq!(bqc_to_index(&levels, BqcMode::Level, 51), None);
        assert_eq!(bqc_to_index(&levels, BqcMode::Index, 2), Some(2));
        assert_eq!(bqc_to_index(&levels, BqcMode::Index, 99), None);
        assert_eq!(bqc_to_index(&levels, BqcMode::Unusable, 0), None);
    }
}
