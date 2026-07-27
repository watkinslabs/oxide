//! `convert_mode` / `find_msg` — the `msgtyp` selection rules in isolation.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::sysv::limits::{MSG_COPY, MSG_EXCEPT};
use crate::sysv::msg::model::Msg;
use crate::sysv::msg::select::{convert_mode, find_msg, Search};

const NO_FLAGS: i32 = 0;

fn queue(types: &[i64]) -> VecDeque<Msg> {
    types.iter().map(|t| Msg { mtype: *t, data: Vec::new() }).collect()
}

#[test]
fn convert_mode_matches_linux() {
    assert_eq!(convert_mode(0, NO_FLAGS), (Search::Any, 0));
    assert_eq!(convert_mode(7, NO_FLAGS), (Search::Equal, 7));
    assert_eq!(convert_mode(7, MSG_EXCEPT), (Search::NotEqual, 7));
    assert_eq!(convert_mode(-7, NO_FLAGS), (Search::LessEqual, 7));
    assert_eq!(convert_mode(3, MSG_COPY), (Search::Number, 3));
    // MSG_COPY wins over every other rule, including msgtyp == 0.
    assert_eq!(convert_mode(0, MSG_COPY), (Search::Number, 0));
}

#[test]
fn long_min_becomes_long_max_because_negating_it_is_undefined() {
    assert_eq!(convert_mode(i64::MIN, NO_FLAGS), (Search::LessEqual, i64::MAX));
}

#[test]
fn less_equal_picks_the_lowest_type_not_the_first_match() {
    let q = queue(&[9, 5, 7, 3, 4]);
    let mut typ = 9;
    assert_eq!(find_msg(&q, &mut typ, Search::LessEqual), Some(3));
}

#[test]
fn less_equal_breaks_ties_by_fifo_order() {
    let q = queue(&[8, 2, 5, 2, 2]);
    let mut typ = 8;
    assert_eq!(find_msg(&q, &mut typ, Search::LessEqual), Some(1),
        "the first message of the lowest type wins");
}

#[test]
fn less_equal_stops_at_the_type_one_floor() {
    let q = queue(&[4, 1, 1]);
    let mut typ = 4;
    assert_eq!(find_msg(&q, &mut typ, Search::LessEqual), Some(1));
}

#[test]
fn less_equal_ignores_types_above_the_bound() {
    let q = queue(&[9, 10]);
    let mut typ = 5;
    assert_eq!(find_msg(&q, &mut typ, Search::LessEqual), None);
    assert_eq!(typ, 5, "a failed scan leaves msgtyp untouched");
}

#[test]
fn number_mode_indexes_the_queue() {
    let q = queue(&[11, 22, 33]);
    for (index, expected) in [(0i64, Some(0usize)), (2, Some(2)), (3, None)] {
        let mut typ = index;
        assert_eq!(find_msg(&q, &mut typ, Search::Number), expected);
    }
}

#[test]
fn any_equal_and_notequal_take_the_first_match() {
    let q = queue(&[5, 6, 5]);
    let mut typ = 0;
    assert_eq!(find_msg(&q, &mut typ, Search::Any), Some(0));
    let mut typ = 5;
    assert_eq!(find_msg(&q, &mut typ, Search::Equal), Some(0));
    let mut typ = 5;
    assert_eq!(find_msg(&q, &mut typ, Search::NotEqual), Some(1));
}
