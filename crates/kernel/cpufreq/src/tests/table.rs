use super::*;

/// A descending table, the order firmware declares performance states in.
fn table() -> FreqTable {
    FreqTable::new(alloc::vec![
        FreqEntry::new(2_400_000, 0),
        FreqEntry::new(1_800_000, 1),
        FreqEntry::new(1_200_000, 2),
        FreqEntry::new(800_000, 3),
    ]).expect("table")
}

fn freq(table: &FreqTable, index: Option<usize>) -> Option<u32> {
    index.map(|index| table.entries[index].frequency)
}

#[test]
fn a_descending_declaration_is_recognised_as_a_ladder() {
    assert_eq!(table().sorted, Sorted::Descending);
    let ascending = FreqTable::new(alloc::vec![
        FreqEntry::new(800_000, 0), FreqEntry::new(2_400_000, 1),
    ]).expect("table");
    assert_eq!(ascending.sorted, Sorted::Ascending);
    let scrambled = FreqTable::new(alloc::vec![
        FreqEntry::new(1_200_000, 0), FreqEntry::new(2_400_000, 1), FreqEntry::new(800_000, 2),
    ]).expect("table");
    assert_eq!(scrambled.sorted, Sorted::Unsorted);
}

#[test]
fn a_table_with_two_entries_at_one_frequency_is_refused() {
    let duplicate = FreqTable::new(alloc::vec![
        FreqEntry::new(1_200_000, 0), FreqEntry::new(1_200_000, 1),
    ]);
    assert_eq!(duplicate.err(), Some(TableError::Duplicate));
}

#[test]
fn a_table_with_nothing_usable_is_refused() {
    assert_eq!(FreqTable::new(alloc::vec![]).err(), Some(TableError::NoValidEntry));
    let all_invalid = FreqTable::new(alloc::vec![
        FreqEntry { frequency: ENTRY_INVALID, driver_data: 0, flags: 0 },
    ]);
    assert_eq!(all_invalid.err(), Some(TableError::NoValidEntry));
}

#[test]
fn an_invalid_entry_is_ignored_without_condemning_the_table() {
    let mixed = FreqTable::new(alloc::vec![
        FreqEntry { frequency: ENTRY_INVALID, driver_data: 0, flags: 0 },
        FreqEntry::new(1_200_000, 1),
    ]).expect("table");
    assert_eq!(mixed.cpuinfo(false), Some((1_200_000, 1_200_000)));
    assert_eq!(mixed.available(false), alloc::vec![1_200_000]);
}

#[test]
fn the_declared_range_comes_from_the_usable_entries() {
    assert_eq!(table().cpuinfo(false), Some((800_000, 2_400_000)));
}

#[test]
fn a_boost_point_raises_the_ceiling_only_when_boost_is_on() {
    let mut entries = table().entries;
    entries.insert(0, FreqEntry { frequency: 3_600_000, driver_data: 9, flags: FLAG_BOOST });
    let boosted = FreqTable::new(entries).expect("table");
    assert!(boosted.boost_supported());
    assert_eq!(boosted.cpuinfo(false), Some((800_000, 2_400_000)),
               "reporting a boost ceiling as the sustained maximum misscales every target");
    assert_eq!(boosted.cpuinfo(true), Some((800_000, 3_600_000)));
    assert!(!boosted.available(false).contains(&3_600_000));
    assert!(boosted.available(true).contains(&3_600_000));
}

#[test]
fn a_minimum_constraint_never_resolves_below_what_was_asked() {
    let table = table();
    let at_or_above = |target| freq(&table,
        table.resolve(target, 800_000, 2_400_000, Relation::Lowest, false));
    assert_eq!(at_or_above(800_000), Some(800_000));
    assert_eq!(at_or_above(800_001), Some(1_200_000));
    assert_eq!(at_or_above(1_200_000), Some(1_200_000));
    assert_eq!(at_or_above(1_200_001), Some(1_800_000));
    assert_eq!(at_or_above(2_400_000), Some(2_400_000));
}

#[test]
fn a_maximum_constraint_never_resolves_above_what_was_asked() {
    let table = table();
    let at_or_below = |target| freq(&table,
        table.resolve(target, 800_000, 2_400_000, Relation::Highest, false));
    assert_eq!(at_or_below(2_400_000), Some(2_400_000));
    assert_eq!(at_or_below(2_399_999), Some(1_800_000));
    assert_eq!(at_or_below(1_200_000), Some(1_200_000));
    assert_eq!(at_or_below(1_199_999), Some(800_000));
    assert_eq!(at_or_below(800_000), Some(800_000));
}

#[test]
fn a_nearest_resolution_may_go_either_way_and_breaks_a_tie_upward() {
    let table = table();
    let nearest = |target| freq(&table,
        table.resolve(target, 800_000, 2_400_000, Relation::Closest, false));
    assert_eq!(nearest(1_100_000), Some(1_200_000));
    assert_eq!(nearest(900_000), Some(800_000));
    // Exactly between 800 000 and 1 200 000.
    assert_eq!(nearest(1_000_000), Some(1_200_000),
               "a tie resolves upward, so a load estimate is never rounded down");
}

#[test]
fn a_resolution_is_clamped_into_the_policy_limits_whatever_the_relation() {
    let table = table();
    let limited = |target, relation| freq(&table,
        table.resolve(target, 1_200_000, 1_800_000, relation, false));
    assert_eq!(limited(2_400_000, Relation::Lowest), Some(1_800_000),
               "a target above the ceiling must not resolve above it");
    assert_eq!(limited(0, Relation::Highest), Some(1_200_000),
               "a target below the floor must not resolve below it");
    assert_eq!(limited(2_400_000, Relation::Closest), Some(1_800_000));
}

#[test]
fn a_policy_pinned_to_one_frequency_resolves_to_it_from_either_side() {
    let table = table();
    for relation in [Relation::Lowest, Relation::Highest, Relation::Closest] {
        assert_eq!(freq(&table, table.resolve(2_400_000, 1_200_000, 1_200_000, relation, false)),
                   Some(1_200_000));
        assert_eq!(freq(&table, table.resolve(0, 1_200_000, 1_200_000, relation, false)),
                   Some(1_200_000));
    }
}

#[test]
fn inverted_limits_resolve_against_the_ceiling_rather_than_refusing() {
    let table = table();
    assert_eq!(freq(&table, table.resolve(1_800_000, 2_400_000, 800_000, Relation::Lowest,
                                          false)),
               Some(2_400_000),
               "a torn read of the two limits must still yield a frequency");
}

#[test]
fn an_inefficient_point_is_avoided_where_the_relation_allows_it() {
    let mut entries = table().entries;
    entries[2].flags |= FLAG_INEFFICIENT;   // 1 200 000
    let table = FreqTable::new(entries).expect("table");
    assert_eq!(freq(&table, table.resolve(1_000_000, 800_000, 2_400_000, Relation::Lowest,
                                          false)),
               Some(1_800_000), "skips the inefficient point on the way up");
    assert_eq!(freq(&table, table.resolve(1_200_000, 800_000, 2_400_000, Relation::Highest,
                                          false)),
               Some(1_200_000), "a ceiling resolution honours the point regardless");
}

#[test]
fn the_efficiency_preference_never_pushes_a_resolution_outside_the_limits() {
    let mut entries = table().entries;
    entries[3].flags |= FLAG_INEFFICIENT;   // 800 000, the only point in range below
    let table = FreqTable::new(entries).expect("table");
    assert_eq!(freq(&table, table.resolve(800_000, 800_000, 800_000, Relation::Lowest, false)),
               Some(800_000),
               "the preference is soft; the limits are not");
}

#[test]
fn a_boost_point_is_not_resolved_to_while_boost_is_off() {
    let mut entries = table().entries;
    entries.insert(0, FreqEntry { frequency: 3_600_000, driver_data: 9, flags: FLAG_BOOST });
    let table = FreqTable::new(entries).expect("table");
    assert_eq!(freq(&table, table.resolve(3_600_000, 800_000, 3_600_000, Relation::Closest,
                                          false)),
               Some(2_400_000));
    assert_eq!(freq(&table, table.resolve(3_600_000, 800_000, 3_600_000, Relation::Closest,
                                          true)),
               Some(3_600_000));
}

#[test]
fn a_resolution_reports_the_index_the_driver_declared_the_point_under() {
    let table = table();
    let index = table.resolve(1_800_000, 800_000, 2_400_000, Relation::Closest, false)
        .expect("resolve");
    assert_eq!(table.entries[index].driver_data, 1,
               "a driver is handed its own index, not the table position");
}

#[test]
fn the_available_list_is_ascending_however_the_table_was_declared() {
    assert_eq!(table().available(false),
               alloc::vec![800_000, 1_200_000, 1_800_000, 2_400_000]);
}
