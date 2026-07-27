// `/proc/<pid>/limits` rendering tests. These run in the HOSTED build — the
// point of `limits_render` living outside the `#[cfg(target_os =
// "oxide-kernel")] mod live` tree. A test written next to the `live` callers
// compiles out silently and proves nothing (B1442).

use super::*;
use alloc::string::String;
use sched::rlimit::{rlim, DEFAULT_RLIMITS, INFINITY};

fn text(limits: &[(u64, u64); rlim::COUNT]) -> String {
    String::from_utf8(limits_body_for_table(limits)).expect("limits body is ascii")
}

#[test]
fn the_body_is_a_header_plus_one_row_per_resource() {
    let t = text(&DEFAULT_RLIMITS);
    let mut lines = t.lines();
    assert!(lines.next().expect("header").starts_with("Limit "));
    assert_eq!(lines.count(), rlim::COUNT, "one row per RLIMIT_*, none dropped");
    assert!(t.ends_with('\n'), "every row is newline-terminated");
}

#[test]
fn the_rows_are_in_linux_declaration_order() {
    let t = text(&DEFAULT_RLIMITS);
    let labels: alloc::vec::Vec<&str> = t.lines().skip(1)
        .map(|l| l.split("  ").next().unwrap().trim()).collect();
    assert_eq!(labels, [
        "Max cpu time", "Max file size", "Max data size", "Max stack size",
        "Max core file size", "Max resident set", "Max processes",
        "Max open files", "Max locked memory", "Max address space",
        "Max file locks", "Max pending signals", "Max msgqueue size",
        "Max nice priority", "Max realtime priority", "Max realtime timeout",
    ]);
}

#[test]
fn rlim_infinity_renders_as_unlimited_in_both_columns() {
    let t = text(&DEFAULT_RLIMITS);
    assert!(t.contains("Max cpu time             unlimited            unlimited            seconds"),
        "{t}");
}

/// The hardcoded blob this renderer replaced claimed `Max locked memory 65536`
/// and `Max msgqueue size 819200`, contradicting `DEFAULT_RLIMITS`. Pin the
/// rendered values to the table so the two cannot drift apart again.
#[test]
fn the_rendered_defaults_track_default_rlimits_not_a_stale_blob() {
    let t = text(&DEFAULT_RLIMITS);
    assert!(t.contains("Max stack size           8388608              unlimited            bytes"),
        "_STK_LIM 8 MiB soft, unlimited hard: {t}");
    assert!(t.contains("Max open files           1024                 4096                 files"),
        "NR_OPEN_DEFAULT 1024/4096: {t}");
    assert!(t.contains("Max core file size       0                    unlimited            bytes"),
        "cores disabled by default: {t}");
    assert!(t.contains("Max locked memory        unlimited"),
        "MEMLOCK is unlimited here, NOT the old blob's 65536: {t}");
    assert!(t.contains("Max msgqueue size        unlimited"),
        "MSGQUEUE is unlimited here, NOT the old blob's 819200: {t}");
}

#[test]
fn a_modified_table_is_reflected_row_by_row() {
    // The whole reason /proc/self/limits stopped being a static blob:
    // setrlimit(2) must be visible through it.
    let mut limits = DEFAULT_RLIMITS;
    limits[rlim::NOFILE] = (8192, 16384);
    limits[rlim::CPU] = (60, 120);
    let t = text(&limits);
    assert!(t.contains("Max open files           8192                 16384                files"), "{t}");
    assert!(t.contains("Max cpu time             60                   120                  seconds"), "{t}");
}

#[test]
fn columns_stay_aligned_for_the_widest_possible_value() {
    // A 20-digit soft limit must not eat its own column separator.
    let mut limits = DEFAULT_RLIMITS;
    limits[rlim::FSIZE] = (u64::MAX - 1, INFINITY);
    let t = text(&limits);
    let row = t.lines().find(|l| l.starts_with("Max file size")).expect("fsize row");
    assert!(row.contains("18446744073709551614"), "{row}");
    assert!(row.ends_with("bytes"), "units survive a maximal value: {row}");
}

#[test]
fn the_unitless_priority_rows_have_no_trailing_unit() {
    let t = text(&DEFAULT_RLIMITS);
    for label in ["Max nice priority", "Max realtime priority"] {
        let row = t.lines().find(|l| l.starts_with(label)).expect(label);
        assert!(row.trim_end().ends_with("unlimited"),
            "{label} carries no unit string: {row}");
    }
}
