//! One row per site, armed or not.

use alloc::string::String;


use crate::fault::{Fault, Info, FAULT_MAX};
use crate::stats::inject::stats_body;

/// Every site is listed whether or not it is armed. Listing only the armed
/// ones would make "never fired" and "never asked to fire" the same absence,
/// and telling those apart is the whole use of the report.
#[test]
fn every_site_has_a_row_whether_or_not_it_is_armed() {
    let info = Info::new();
    let body = String::from_utf8(stats_body(&info)).unwrap();
    let lines: alloc::vec::Vec<&str> = body.lines().collect();
    assert_eq!(lines[0], "fault_type\t\tinjected_count");
    assert_eq!(lines.len() as u32, FAULT_MAX + 1);
    for i in 0..FAULT_MAX {
        let name = Fault::from_index(i).unwrap().name();
        assert!(lines[i as usize + 1].starts_with(name), "{}", lines[i as usize + 1]);
    }
}

/// Every count starts at zero and the rows are in site order.
#[test]
fn a_mount_that_has_injected_nothing_reports_a_zero_for_each_site() {
    let info = Info::new();
    let body = String::from_utf8(stats_body(&info)).unwrap();
    for line in body.lines().skip(1) {
        assert!(line.trim_end().ends_with('0'), "{line}");
    }
}
