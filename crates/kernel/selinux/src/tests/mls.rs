use super::*;
use alloc::vec;
use alloc::vec::Vec;

fn level(sens: u32, cats: &[u32]) -> Level {
    let mut cat = Ebitmap::new();
    for c in cats { cat.set(*c, true); }
    Level { sens, cat }
}

fn range(low: Level, high: Level) -> Range { Range { low, high } }

#[test]
fn equality_needs_both_the_sensitivity_and_the_categories() {
    assert!(level(1, &[0, 1]).eq_level(&level(1, &[0, 1])));
    assert!(!level(1, &[0, 1]).eq_level(&level(2, &[0, 1])));
    assert!(!level(1, &[0, 1]).eq_level(&level(1, &[0])));
}

#[test]
fn dominance_needs_both_halves_a_higher_sensitivity_alone_is_not_enough() {
    let high_sens_few_cats = level(5, &[0]);
    let low_sens_many_cats = level(1, &[0, 1, 2]);
    assert!(!high_sens_few_cats.dominates(&low_sens_many_cats),
            "a higher sensitivity must not override a missing category");
    assert!(!low_sens_many_cats.dominates(&high_sens_few_cats),
            "a superset of categories must not override a lower sensitivity");
}

#[test]
fn dominance_holds_when_both_halves_hold() {
    assert!(level(5, &[0, 1, 2]).dominates(&level(1, &[0, 2])));
    assert!(level(1, &[0]).dominates(&level(1, &[0])), "dominance is reflexive");
}

#[test]
fn a_strict_category_subset_does_not_dominate_at_equal_sensitivity() {
    let subset = level(3, &[0, 1]);
    let superset = level(3, &[0, 1, 2]);
    assert!(!subset.dominates(&superset),
            "the whole point of categories: equal clearance plus a missing compartment is a refusal");
    assert!(superset.dominates(&subset));
}

#[test]
fn incomparable_is_exactly_neither_direction() {
    let a = level(2, &[0]);
    let b = level(1, &[1]);
    assert!(a.incomparable(&b) && b.incomparable(&a));
    assert!(!a.incomparable(&a));
    assert!(!level(2, &[0, 1]).incomparable(&level(1, &[0])));
}

#[test]
fn range_containment_nests_the_inner_range_inside_the_outer() {
    let outer = range(level(0, &[]), level(9, &[0, 1, 2]));
    let inner = range(level(3, &[0]), level(5, &[0, 1]));
    assert!(outer.contains(&inner));
    assert!(!inner.contains(&outer));
}

#[test]
fn range_containment_fails_when_only_one_end_fits() {
    let outer = range(level(2, &[]), level(5, &[]));
    assert!(!outer.contains(&range(level(1, &[]), level(4, &[]))), "low end escapes below");
    assert!(!outer.contains(&range(level(3, &[]), level(9, &[]))), "high end escapes above");
    assert!(outer.contains(&range(level(3, &[]), level(4, &[]))));
}

#[test]
fn range_containment_fails_on_a_category_outside_the_outer_high_level() {
    let outer = range(level(0, &[]), level(5, &[0]));
    assert!(!outer.contains(&range(level(0, &[]), level(5, &[0, 1]))));
}

#[test]
fn a_range_is_ordered_only_when_its_high_end_dominates_its_low_end() {
    assert!(range(level(1, &[0]), level(3, &[0, 1])).is_ordered());
    assert!(!range(level(3, &[]), level(1, &[])).is_ordered());
    assert!(!range(level(1, &[0, 1]), level(1, &[0])).is_ordered(),
            "a high end missing one of the low end's categories is not ordered");
}

#[test]
fn a_single_level_range_contains_only_itself() {
    let r = Range::single(level(2, &[0]));
    assert!(r.is_ordered());
    assert!(r.contains(&r));
    assert!(!r.contains(&range(level(2, &[0]), level(3, &[0]))));
}

#[test]
fn the_greatest_lower_bound_raises_the_low_end_and_lowers_the_high_end() {
    let a = range(level(1, &[0]), level(8, &[0, 1, 2]));
    let b = range(level(3, &[1]), level(5, &[1, 2, 3]));
    let g = Range::glblub(&a, &b);
    assert_eq!(g.low.sens, 3, "the low end takes the HIGHER sensitivity");
    assert_eq!(g.low.cat.iter().collect::<Vec<_>>(), vec![0, 1], "and the category union");
    assert_eq!(g.high.sens, 5, "the high end takes the LOWER sensitivity");
    assert_eq!(g.high.cat.iter().collect::<Vec<_>>(), vec![1, 2], "and the category intersection");
}

#[test]
fn the_greatest_lower_bound_of_a_range_with_itself_is_that_range() {
    let a = range(level(2, &[0, 3]), level(7, &[0, 3, 4]));
    assert_eq!(Range::glblub(&a, &a), a);
}

#[test]
fn a_single_category_renders_as_one_run() {
    assert_eq!(cat_runs(&level(0, &[4])), vec![CatRun { head: 4, tail: 4 }]);
    assert_eq!(CatRun { head: 4, tail: 4 }.tail_separator(), None);
}

#[test]
fn two_adjacent_categories_are_a_comma_pair_not_a_range() {
    let runs = cat_runs(&level(0, &[0, 1]));
    assert_eq!(runs, vec![CatRun { head: 0, tail: 1 }]);
    assert_eq!(runs[0].tail_separator(), Some(','),
               "rendering a two-member set as a range widens what userspace reads back");
}

#[test]
fn three_or_more_adjacent_categories_abbreviate_to_a_range() {
    let runs = cat_runs(&level(0, &[7, 8, 9]));
    assert_eq!(runs, vec![CatRun { head: 7, tail: 9 }]);
    assert_eq!(runs[0].tail_separator(), Some('.'));
    assert_eq!(cat_runs(&level(0, &[0, 1, 2, 3]))[0].tail_separator(), Some('.'));
}

#[test]
fn runs_split_at_every_gap() {
    assert_eq!(cat_runs(&level(0, &[0, 2, 3, 4, 9])),
               vec![CatRun { head: 0, tail: 0 },
                    CatRun { head: 2, tail: 4 },
                    CatRun { head: 9, tail: 9 }]);
}

#[test]
fn the_category_list_renders_with_a_leading_colon_then_commas() {
    let mut out = alloc::string::String::new();
    write_cat_list(&mut out, &level(0, &[0, 2, 3, 4, 9]), write_unnamed_cat).expect("render");
    assert_eq!(out, ":c0,c2.c4,c9");
}

#[test]
fn a_level_without_categories_renders_nothing() {
    let mut out = alloc::string::String::new();
    write_cat_list(&mut out, &level(3, &[]), write_unnamed_cat).expect("render");
    assert_eq!(out, "");
}

#[test]
fn a_two_member_run_renders_with_a_comma() {
    let mut out = alloc::string::String::new();
    write_cat_list(&mut out, &level(0, &[5, 6]), write_unnamed_cat).expect("render");
    assert_eq!(out, ":c5,c6");
}

fn wire_range(items: u32, sens: &[u32], cats: &[&[u32]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&items.to_le_bytes());
    for s in sens { out.extend_from_slice(&s.to_le_bytes()); }
    for set in cats {
        let mut e = Ebitmap::new();
        for c in *set { e.set(*c, true); }
        out.extend_from_slice(&64u32.to_le_bytes());
        out.extend_from_slice(&e.highbit().to_le_bytes());
        let chunks: Vec<u32> = e.iter().collect();
        // Re-encode the set as explicit 64-bit chunks.
        let mut grouped: Vec<(u32, u64)> = Vec::new();
        for bit in chunks {
            let start = bit & !63;
            match grouped.last_mut() {
                Some(g) if g.0 == start => g.1 |= 1u64 << (bit - start),
                _ => grouped.push((start, 1u64 << (bit - start))),
            }
        }
        out.extend_from_slice(&(grouped.len() as u32).to_le_bytes());
        for (s, m) in grouped {
            out.extend_from_slice(&s.to_le_bytes());
            out.extend_from_slice(&m.to_le_bytes());
        }
    }
    out
}

#[test]
fn a_one_item_range_duplicates_its_single_level() {
    let bytes = wire_range(1, &[4], &[&[1, 2]]);
    let r = Range::read(&mut Reader::new(&bytes)).expect("one-item range");
    assert!(r.low.eq_level(&r.high), "a one-item range is a single level at both ends");
    assert_eq!(r.low.sens, 4);
    assert_eq!(r.low.cat.iter().collect::<Vec<_>>(), vec![1, 2]);
}

#[test]
fn a_two_item_range_reads_both_ends() {
    let bytes = wire_range(2, &[1, 6], &[&[0], &[0, 1, 2]]);
    let r = Range::read(&mut Reader::new(&bytes)).expect("two-item range");
    assert_eq!((r.low.sens, r.high.sens), (1, 6));
    assert_eq!(r.high.cat.iter().collect::<Vec<_>>(), vec![0, 1, 2]);
    assert!(r.is_ordered());
}

#[test]
fn an_item_count_outside_one_or_two_is_refused() {
    for items in [0u32, 3, 99] {
        let bytes = wire_range(items, &[1, 2], &[&[0], &[0]]);
        assert!(Range::read(&mut Reader::new(&bytes)).is_err(), "items={items}");
    }
}

#[test]
fn a_truncated_range_is_refused() {
    let full = wire_range(2, &[1, 6], &[&[0], &[0, 1]]);
    for cut in 0..full.len() {
        assert!(Range::read(&mut Reader::new(&full[..cut])).is_err(), "prefix {cut}");
    }
}
