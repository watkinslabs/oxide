//! The rollups, the compressed twins, and the off switch.

use alloc::string::String;
use alloc::vec::Vec;

use crate::stats::iostat::*;

/// # C: O(1)
fn on() -> Iostat { let mut s = Iostat::new(); s.enable(true); s }

/// Accounting costs two additions on every block, so a mount nobody asked to
/// measure must pay nothing — and must not report a table of zeroes as if it
/// had measured and found nothing.
#[test]
fn nothing_is_recorded_until_accounting_is_asked_for() {
    let mut s = Iostat::new();
    s.update(Io::FsData, 4096, false);
    s.read_folio(0);
    assert_eq!(s.bytes[Io::FsData.idx()], 0);
    assert_eq!(s.count[Io::FsData.idx()], 0);
    assert!(info_body(&s, 1).is_empty());
}

/// The two application totals are rollups of their parts, so no site reports
/// them and the total can never disagree with what it is made of.
#[test]
fn the_application_totals_are_the_sum_of_their_parts() {
    let mut s = on();
    s.update(Io::AppBuffered, 100, false);
    s.update(Io::AppDirect, 20, false);
    s.update(Io::AppBufferedRead, 7, false);
    s.update(Io::AppDirectRead, 3, false);
    assert_eq!(s.bytes[Io::AppWrite.idx()], 120);
    assert_eq!(s.count[Io::AppWrite.idx()], 2);
    assert_eq!(s.bytes[Io::AppRead.idx()], 10);
    assert_eq!(s.count[Io::AppRead.idx()], 2);
}

/// A filesystem-side write is not application traffic and must not reach the
/// application rollup.
#[test]
fn filesystem_traffic_stays_out_of_the_application_totals() {
    let mut s = on();
    s.update(Io::FsNode, 4096, false);
    s.update(Io::FsMeta, 4096, false);
    assert_eq!(s.bytes[Io::AppWrite.idx()], 0);
    assert_eq!(s.bytes[Io::AppRead.idx()], 0);
}

/// A compressed file's traffic is counted twice on purpose: once under the
/// plain kind and once under the compressed one. The compressed figure
/// answers what share of the traffic was compressed, which a partition of the
/// total could not.
#[test]
fn a_compressed_files_traffic_appears_under_both_its_kinds() {
    let mut s = on();
    s.update(Io::AppBuffered, 64, true);
    assert_eq!(s.bytes[Io::AppBuffered.idx()], 64);
    assert_eq!(s.bytes[Io::AppBufferedCdata.idx()], 64);
    assert_eq!(s.bytes[Io::AppWrite.idx()], 64);
}

/// A kind with no compressed twin gains nothing from the file being one.
#[test]
fn a_kind_with_no_compressed_twin_is_counted_once() {
    let mut s = on();
    s.update(Io::FsMeta, 4096, true);
    assert_eq!(s.count[Io::FsMeta.idx()], 1);
    assert_eq!(s.count[Io::FsCdata.idx()], 0);
}

/// Each read direction gains its own compressed twin and no other.
#[test]
fn each_compressed_twin_follows_its_own_kind() {
    let mut s = on();
    s.update(Io::FsDataRead, 8, true);
    s.update(Io::AppMapped, 9, true);
    assert_eq!(s.bytes[Io::FsCdataRead.idx()], 8);
    assert_eq!(s.bytes[Io::AppMappedCdata.idx()], 9);
    assert_eq!(s.bytes[Io::AppMappedCdataRead.idx()], 0);
}

/// The mean is derived, never stored: a stored mean drifts from its own parts.
#[test]
fn the_mean_is_derived_and_is_zero_where_nothing_was_measured() {
    let mut s = on();
    assert_eq!(s.avg(Io::FsData), 0);
    s.update(Io::FsData, 10, false);
    s.update(Io::FsData, 20, false);
    assert_eq!(s.avg(Io::FsData), 15);
}

/// A read larger than the largest bucket lands in the last one rather than
/// being dropped or indexing past the array.
#[test]
fn an_oversized_read_lands_in_the_last_bucket() {
    let mut s = on();
    s.read_folio(0);
    s.read_folio(999);
    assert_eq!(s.read_folio_count[0], 1);
    assert_eq!(s.read_folio_count[NR_PAGE_ORDERS - 1], 1);
}

/// Turning accounting off narrows what the mount pays for; it is not a
/// request to throw the history away.
#[test]
fn switching_accounting_off_and_on_keeps_what_was_measured() {
    let mut s = on();
    s.update(Io::FsData, 5, false);
    s.enable(false);
    s.update(Io::FsData, 5, false);
    s.enable(true);
    assert_eq!(s.bytes[Io::FsData.idx()], 5);
}

/// Resetting clears the totals and leaves the switch where it was: a reset
/// that also disabled accounting would silently stop the measurement the
/// caller had just asked to restart.
#[test]
fn a_reset_clears_the_totals_and_leaves_accounting_on() {
    let mut s = on();
    s.update(Io::FsData, 5, false);
    s.reset();
    assert_eq!(s.bytes[Io::FsData.idx()], 0);
    assert!(s.enabled);
}

/// The report's shape is what tools parse: three sections, a header row, one
/// row per kind, and the order-histogram line.
#[test]
fn the_report_carries_every_kind_in_its_three_sections() {
    let mut s = on();
    s.update(Io::AppBuffered, 4096, false);
    let body = String::from_utf8(info_body(&s, 42)).unwrap();
    assert!(body.starts_with("time:\t\t42"), "{body}");
    assert!(body.contains("io_bytes"));
    assert!(body.contains("\n[WRITE]\n"));
    assert!(body.contains("\n[READ]\n"));
    assert!(body.contains("\n[OTHER]\n"));
    assert!(body.contains("app buffered data:"));
    assert!(body.contains("fs zone reset:"));
    assert!(body.contains("fs read folio order:"));
    // One row per kind, plus the time line, the column header, three section
    // headings and the order histogram.
    let rows = body.lines()
        .filter(|l| l.contains(':') && !l.starts_with("time") && !l.starts_with("fs read folio"))
        .count();
    assert_eq!(rows, NR_IO_TYPE - 2, "the two rollups have no row of their own");
}

/// The measured numbers reach the row they belong to.
#[test]
fn a_rows_three_figures_are_the_bytes_the_count_and_their_mean() {
    let mut s = on();
    s.update(Io::FsDiscard, 8192, false);
    s.update(Io::FsDiscard, 4096, false);
    let body = String::from_utf8(info_body(&s, 0)).unwrap();
    let row = body.lines().find(|l| l.starts_with("fs discard:")).unwrap();
    let f: Vec<&str> = row.split_whitespace().collect();
    assert_eq!(&f[2..], ["12288", "2", "6144"]);
}
