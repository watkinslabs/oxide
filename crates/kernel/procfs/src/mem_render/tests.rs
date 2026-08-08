use super::*;
use alloc::string::String;

const PAGE: u64 = 4096;

fn sample() -> MemStatus {
    MemStatus {
        total_vm_bytes:  100 * PAGE,
        locked_vm_bytes:   2 * PAGE,
        exec_vm_bytes:     8 * PAGE,
        data_vm_bytes:    20 * PAGE,
        stack_vm_bytes:    4 * PAGE,
        pgtable_bytes:     3 * PAGE,
        rss_anon_pages:   10,
        rss_file_pages:    5,
        rss_shmem_pages:   1,
        swap_pages:        7,
        hiwater_rss_pages: 40,
        hugetlb_pages:     0,
    }
}

fn text(m: &MemStatus) -> String { String::from_utf8(render_status_rows(m)).unwrap() }

fn row_of<'a>(body: &'a str, label: &str) -> &'a str {
    body.lines().find(|l| l.starts_with(label)).unwrap_or_else(|| panic!("no {label} row"))
        .split('\t').nth(1).unwrap().trim_end_matches(" kB").trim()
}

#[test]
fn resident_rows_are_the_three_classes_and_their_sum_in_kib() {
    let b = text(&sample());
    assert_eq!(row_of(&b, "RssAnon:"),  "40");
    assert_eq!(row_of(&b, "RssFile:"),  "20");
    assert_eq!(row_of(&b, "RssShmem:"), "4");
    // VmRSS is exactly anon+file+shmem, and excludes the 7 swapped pages.
    assert_eq!(row_of(&b, "VmRSS:"), "64");
    assert_eq!(row_of(&b, "VmSwap:"), "28");
}

#[test]
fn the_high_water_row_never_reports_below_the_live_resident_set() {
    let mut m = sample();
    // Latch (40 pages) above the live total (16 pages): the peak is preserved.
    assert_eq!(row_of(&text(&m), "VmHWM:"), "160");
    // Latch behind the live total: the live total wins, so a peak reached
    // since the last latch is still reported rather than under-counted.
    m.hiwater_rss_pages = 2;
    assert_eq!(row_of(&text(&m), "VmHWM:"), "64");
    assert_eq!(row_of(&text(&m), "VmRSS:"), "64");
}

#[test]
fn virtual_extent_rows_report_kib_not_pages_or_bytes() {
    let b = text(&sample());
    assert_eq!(row_of(&b, "VmSize:"), "400");
    assert_eq!(row_of(&b, "VmPeak:"), "400");
    assert_eq!(row_of(&b, "VmLck:"),  "8");
    assert_eq!(row_of(&b, "VmPin:"),  "0");
    assert_eq!(row_of(&b, "VmData:"), "80");
    assert_eq!(row_of(&b, "VmStk:"),  "16");
    assert_eq!(row_of(&b, "VmExe:"),  "32");
    assert_eq!(row_of(&b, "VmPTE:"),  "12");
}

#[test]
fn rows_appear_in_the_order_a_status_parser_expects() {
    let b = text(&sample());
    let labels: alloc::vec::Vec<&str> =
        b.lines().map(|l| l.split(':').next().unwrap()).collect();
    assert_eq!(labels, alloc::vec![
        "VmPeak", "VmSize", "VmLck", "VmPin", "VmHWM", "VmRSS",
        "RssAnon", "RssFile", "RssShmem", "VmData", "VmStk",
        "VmExe", "VmLib", "VmPTE", "VmSwap", "HugetlbPages",
    ]);
}

#[test]
fn every_row_carries_the_kib_suffix_and_a_tab_separator() {
    for line in text(&sample()).lines() {
        assert!(line.contains('\t'), "{line} must be tab-separated");
        assert!(line.ends_with(" kB"), "{line} must be in kB");
    }
}

#[test]
fn the_narrow_rows_are_right_aligned_in_an_eight_wide_field() {
    let b = text(&sample());
    // Linux prints VmExe/VmLib/VmPTE with `%8lu`; a parser splitting on
    // whitespace is unaffected, but a fixed-column reader is not.
    assert!(b.contains("VmExe:\t      32 kB"), "{b}");
    assert!(b.contains("VmLib:\t       0 kB"), "{b}");
}

#[test]
fn an_empty_address_space_renders_every_row_as_zero() {
    let b = text(&MemStatus::default());
    for line in b.lines() { assert!(line.contains("0 kB"), "{line}"); }
}

#[test]
fn statm_reports_seven_page_counts_with_lib_and_dt_hardwired_zero() {
    let out = String::from_utf8(render_statm(&sample())).unwrap();
    let f: alloc::vec::Vec<&str> = out.trim_end().split(' ').collect();
    assert_eq!(f.len(), 7);
    assert_eq!(f[0], "100");           // size = total_vm pages
    assert_eq!(f[1], "16");            // resident = shared + anon
    assert_eq!(f[2], "6");             // shared = file + shmem
    assert_eq!(f[3], "8");             // text = exec extent
    assert_eq!(f[4], "0");             // lib: zero since 2.6
    assert_eq!(f[5], "24");            // data = data_vm + stack_vm
    assert_eq!(f[6], "0");             // dt: zero since 2.6
    assert!(out.ends_with('\n'));
}

#[test]
fn statm_resident_agrees_with_the_status_rss_row() {
    let m = sample();
    let out = String::from_utf8(render_statm(&m)).unwrap();
    let resident_pages: u64 = out.split(' ').nth(1).unwrap().parse().unwrap();
    // Same counters behind both files: statm's pages scale to status's KiB.
    assert_eq!(resident_pages * 4, row_of(&text(&m), "VmRSS:").parse().unwrap());
}

#[test]
fn a_mapping_lands_in_exactly_one_accounting_bucket() {
    // exec, !write, !stack -> code.
    assert_eq!(classify(true, false, false, false), VmClass::Exec);
    // A writable executable mapping is NOT code; it is private data.
    assert_eq!(classify(true, true, false, false), VmClass::Data);
    // Stack wins over data even though a stack is writable and private.
    assert_eq!(classify(false, true, true, false), VmClass::Stack);
    // An executable stack is stack, not code.
    assert_eq!(classify(true, false, true, false), VmClass::Stack);
    // A shared writable file mapping counts toward total_vm only.
    assert_eq!(classify(false, true, false, true), VmClass::Other);
    // A read-only private file mapping likewise.
    assert_eq!(classify(false, false, false, false), VmClass::Other);
}

/// Huge pages are held down by the process but are NOT resident-set memory:
/// the reference keeps them out of every `Rss*` row and reports them on a row
/// of their own, so a tool summing RSS never double-counts a reservation.
#[test]
fn hugetlb_pages_are_reported_on_their_own_row_and_in_no_rss_row() {
    let m = MemStatus {
        rss_anon_pages: 4, rss_file_pages: 2, rss_shmem_pages: 1,
        hugetlb_pages: 1024,
        ..MemStatus::default()
    };
    let out = String::from_utf8(render_status_rows(&m)).unwrap();
    assert!(out.contains("HugetlbPages:\t"), "{out}");
    assert!(out.contains(&alloc::format!("HugetlbPages:\t{} kB", 1024 * 4)), "{out}");
    // 7 resident pages, and not one of the 1024 huge ones.
    assert!(out.contains(&alloc::format!("VmRSS:\t{} kB", 7 * 4)), "{out}");
    assert!(out.contains(&alloc::format!("RssFile:\t{} kB", 2 * 4)), "{out}");
}

/// `statm`'s resident and shared fields carry the same exclusion.
#[test]
fn statm_resident_excludes_hugetlb_pages() {
    let m = MemStatus { rss_anon_pages: 4, rss_file_pages: 2, hugetlb_pages: 4096,
                        ..MemStatus::default() };
    let out = String::from_utf8(render_statm(&m)).unwrap();
    let fields: alloc::vec::Vec<&str> = out.trim().split(' ').collect();
    assert_eq!(fields[1], "6", "resident is anon+file only: {out}");
    assert_eq!(fields[2], "2", "shared is file+shmem only: {out}");
}
