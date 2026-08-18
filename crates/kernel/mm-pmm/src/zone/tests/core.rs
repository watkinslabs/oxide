use crate::zone::*;

const PAGE: u64 = 4096;
const PFN_4G: u64 = (1u64 << 32) / PAGE;

fn limits(pfn_max: u64) -> ZoneLimits { ZoneLimits::x86_64(pfn_max, PAGE) }

#[test]
fn movablecore_reserves_an_aligned_tail_above_the_ordinary_zones() {
    let pfn_max = PFN_4G + 4096;
    let out = apply_memory_core_request(limits(pfn_max), b"movablecore=8M", pfn_max, PAGE);
    assert_eq!(out.movable_start_pfn, Some(PFN_4G + 2048));
}

#[test]
fn kernelcore_and_movablecore_keep_the_larger_kernel_reservation() {
    let pfn_max = PFN_4G + 8192;
    let out = apply_memory_core_request(limits(pfn_max), b"kernelcore=4120M movablecore=16M", pfn_max, PAGE);
    assert_eq!(out.movable_start_pfn, Some(PFN_4G + 6144));
    let out = apply_memory_core_request(limits(pfn_max), b"kernelcore=4096M movablecore=16M", pfn_max, PAGE);
    assert_eq!(out.movable_start_pfn, Some(PFN_4G + 4096));
}

#[test]
fn no_request_or_mirror_leaves_the_movable_zone_empty() {
    let pfn_max = PFN_4G + 4096;
    assert_eq!(apply_memory_core_request(limits(pfn_max), b"", pfn_max, PAGE).movable_start_pfn, None);
    assert_eq!(apply_memory_core_request(limits(pfn_max), b"kernelcore=mirror movablecore=8M", pfn_max, PAGE).movable_start_pfn, None);
}

#[test]
fn percentage_and_sub_page_requests_follow_page_and_pageblock_rounding() {
    let pfn_max = PFN_4G + 4096;
    let out = apply_memory_core_request(limits(pfn_max), b"movablecore=25%", pfn_max, PAGE);
    assert!(out.movable_start_pfn.unwrap() >= PFN_4G);
    assert_eq!(out.movable_start_pfn.unwrap() % PAGEBLOCK_PAGES, 0);
    let out = apply_memory_core_request(limits(pfn_max), b"movablecore=1", pfn_max, PAGE);
    assert_eq!(out.movable_start_pfn, None);
}
