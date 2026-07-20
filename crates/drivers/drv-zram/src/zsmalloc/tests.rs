//! Hosted zsmalloc foundation contracts.

use super::limits::{ZS_CLASS_DELTA_BYTES, ZS_MAX_PAGES_PER_ZSPAGE, ZS_MIN_OBJECT_BYTES};
use super::ZsPool;

const MINUS_ONE_BYTE: usize = 1;
const FIRST_PATTERN: u8 = 0x3a;
const SECOND_PATTERN: u8 = 0xc5;
const COMPACTION_OBJECT_BYTES: usize = 1024;
const COMPACTION_OBJECT_COUNT: usize = 9;
const COMPACTION_FREED_INDEX: usize = 0;
const COMPACTION_SOURCE_INDEX: usize = COMPACTION_OBJECT_COUNT - 1;
const COMPACTION_RELEASED_PAGE_COUNT: usize = 1;
const FULLNESS_EMPTY: usize = 0;
const FULLNESS_ALMOST_EMPTY: usize = 1;
const FULLNESS_MIDDLE: usize = 2;
const FULLNESS_ALMOST_FULL: usize = 3;
const FULLNESS_FULL: usize = 4;
const RESERVATION_PATTERN: u8 = 0x5d;
const RESERVATION_OBJECT_BYTES: usize = 1024;

#[test]
fn classes_follow_linux_delta_and_do_not_round_to_powers_of_two() {
    let minimum = ZsPool::class_for_test(MINUS_ONE_BYTE).unwrap();
    assert_eq!(minimum.object_bytes, ZS_MIN_OBJECT_BYTES);
    let request = ZS_MIN_OBJECT_BYTES + MINUS_ONE_BYTE;
    let stepped = ZsPool::class_for_test(request).unwrap();
    assert_eq!(stepped.object_bytes, ZS_MIN_OBJECT_BYTES + ZS_CLASS_DELTA_BYTES);
    assert!(!stepped.object_bytes.is_power_of_two());
}

#[test]
fn non_power_of_two_class_uses_least_waste_bounded_zspage_chain() {
    let page_bytes = hal::PAGE_SIZE_BYTES as usize;
    let request = page_bytes / 2 + MINUS_ONE_BYTE;
    let class = ZsPool::class_for_test(request).unwrap();
    let selected_waste = (class.pages_per_zspage * page_bytes) % class.object_bytes;
    assert!(class.pages_per_zspage <= ZS_MAX_PAGES_PER_ZSPAGE);
    for pages in 1..=ZS_MAX_PAGES_PER_ZSPAGE {
        assert!(selected_waste <= (pages * page_bytes) % class.object_bytes);
    }
}

#[test]
fn read_write_and_handle_identity_survive_allocator_activity() {
    let page_bytes = hal::PAGE_SIZE_BYTES as usize;
    let mut pool = ZsPool::new();
    let first = pool.alloc(&alloc::vec![FIRST_PATTERN; page_bytes / 2]).unwrap();
    let second = pool.alloc(&alloc::vec![SECOND_PATTERN; page_bytes / 2]).unwrap();
    pool.write_from(first, &alloc::vec![SECOND_PATTERN; page_bytes / 2]).unwrap();
    let mut output = alloc::vec![0; page_bytes / 2];
    pool.read_into(first, &mut output).unwrap();
    assert_eq!(output, alloc::vec![SECOND_PATTERN; page_bytes / 2]);
    pool.free(second).unwrap();
    let third = pool.alloc(&alloc::vec![FIRST_PATTERN; page_bytes / 2]).unwrap();
    assert_ne!(third, first);
    pool.read_into(first, &mut output).unwrap();
    assert_eq!(output, alloc::vec![SECOND_PATTERN; page_bytes / 2]);
}

#[test]
fn stale_handle_cannot_access_recycled_object_header() {
    let mut pool = ZsPool::new();
    let old = pool.alloc(&[FIRST_PATTERN]).unwrap();
    pool.free(old).unwrap();
    let new = pool.alloc(&[SECOND_PATTERN]).unwrap();
    assert_ne!(old, new);
    let mut output = [0; 1];
    assert!(pool.read_into(old, &mut output).is_err());
    pool.read_into(new, &mut output).unwrap();
    assert_eq!(output, [SECOND_PATTERN]);
}

#[test]
fn object_storage_can_cross_a_physical_page_in_multi_page_zspage() {
    let page_bytes = hal::PAGE_SIZE_BYTES as usize;
    let request = page_bytes / 2 + MINUS_ONE_BYTE;
    let mut pool = ZsPool::new();
    let first = pool.alloc(&alloc::vec![FIRST_PATTERN; request]).unwrap();
    let second = pool.alloc(&alloc::vec![SECOND_PATTERN; request]).unwrap();
    assert!(!pool.spans_page_boundary(first).unwrap());
    assert!(pool.spans_page_boundary(second).unwrap());
    let mut output = alloc::vec![0; request];
    pool.read_into(second, &mut output).unwrap();
    assert_eq!(output, alloc::vec![SECOND_PATTERN; request]);
}

#[test]
fn final_free_returns_all_pages_of_multi_page_zspage() {
    let page_bytes = hal::PAGE_SIZE_BYTES as usize;
    let request = page_bytes / 2 + MINUS_ONE_BYTE;
    let mut pool = ZsPool::new();
    let object = pool.alloc(&alloc::vec![FIRST_PATTERN; request]).unwrap();
    let class = ZsPool::class_for_test(request).unwrap();
    assert_eq!(pool.page_count(), class.pages_per_zspage);
    pool.free(object).unwrap();
    assert_eq!(pool.page_count(), 0);
}

#[test]
fn fullness_groups_are_derived_per_class_from_live_object_counts() {
    let mut pool = ZsPool::new();
    let mut handles = alloc::vec::Vec::new();
    for _ in 0..COMPACTION_OBJECT_COUNT {
        handles.push(pool.alloc(&alloc::vec![FIRST_PATTERN; COMPACTION_OBJECT_BYTES]).unwrap());
    }
    pool.free(handles[COMPACTION_FREED_INDEX]).unwrap();
    let class = ZsPool::class_for_test(COMPACTION_OBJECT_BYTES).unwrap();
    let counts = pool.fullness_counts_for_test(class);
    assert_eq!(counts[FULLNESS_EMPTY], 0);
    assert_eq!(counts[FULLNESS_ALMOST_EMPTY], 1);
    assert_eq!(counts[FULLNESS_MIDDLE], 1);
    assert_eq!(counts[FULLNESS_ALMOST_FULL], 0);
    assert_eq!(counts[FULLNESS_FULL], 1);
}

#[test]
fn compaction_moves_same_class_objects_without_changing_stable_handles() {
    let mut pool = ZsPool::new();
    let mut handles = alloc::vec::Vec::new();
    for index in 0..COMPACTION_OBJECT_COUNT {
        let pattern = if index == COMPACTION_SOURCE_INDEX { SECOND_PATTERN } else { FIRST_PATTERN };
        handles.push(pool.alloc(&alloc::vec![pattern; COMPACTION_OBJECT_BYTES]).unwrap());
    }
    pool.free(handles[COMPACTION_FREED_INDEX]).unwrap();
    let before = pool.stats();
    assert!(before.can_compact);
    assert_eq!(before.objects, COMPACTION_OBJECT_COUNT - 1);
    assert_eq!(pool.compact().unwrap(), COMPACTION_RELEASED_PAGE_COUNT);
    let after = pool.stats();
    assert_eq!(after.pages + COMPACTION_RELEASED_PAGE_COUNT, before.pages);
    assert_eq!(after.zspages + COMPACTION_RELEASED_PAGE_COUNT, before.zspages);
    assert_eq!(after.objects, before.objects);
    assert!(!after.can_compact);
    let mut output = alloc::vec![0; COMPACTION_OBJECT_BYTES];
    pool.read_into(handles[COMPACTION_SOURCE_INDEX], &mut output).unwrap();
    assert_eq!(output, alloc::vec![SECOND_PATTERN; COMPACTION_OBJECT_BYTES]);
    assert!(pool.read_into(handles[COMPACTION_FREED_INDEX], &mut output).is_err());
}

#[test]
fn compaction_does_not_rebuild_or_allocate_when_no_source_can_be_emptied() {
    let mut pool = ZsPool::new();
    for _ in 0..COMPACTION_OBJECT_BYTES / ZS_MIN_OBJECT_BYTES {
        pool.alloc(&[FIRST_PATTERN]).unwrap();
    }
    let before = pool.stats();
    assert!(!before.can_compact);
    assert_eq!(pool.compact().unwrap(), 0);
    assert_eq!(pool.stats(), before);
}

#[test]
fn compaction_never_uses_free_slots_from_a_different_size_class() {
    let mut pool = ZsPool::new();
    let class = ZsPool::class_for_test(COMPACTION_OBJECT_BYTES).unwrap();
    for _ in 0..class.objects_per_zspage + 1 {
        pool.alloc(&alloc::vec![FIRST_PATTERN; COMPACTION_OBJECT_BYTES]).unwrap();
    }
    pool.alloc(&alloc::vec![SECOND_PATTERN; COMPACTION_OBJECT_BYTES / 2]).unwrap();
    let before = pool.stats();
    assert!(!before.can_compact);
    assert_eq!(pool.compact().unwrap(), 0);
    assert_eq!(pool.stats(), before);
}

#[test]
fn stale_zspage_reservation_is_rescinded_after_a_serialized_commit() {
    let mut pool = ZsPool::new();
    // Both snapshots require a new zspage. The first attach makes the second
    // reservation stale; commit must return it rather than leaking PMM pages.
    let first = pool.allocation_plan(RESERVATION_OBJECT_BYTES).unwrap().reserve().unwrap();
    let second = pool.allocation_plan(RESERVATION_OBJECT_BYTES).unwrap().reserve().unwrap();
    let bytes = alloc::vec![RESERVATION_PATTERN; RESERVATION_OBJECT_BYTES];
    let (first_handle, unused) = pool.commit_reserved(first, &bytes).unwrap();
    assert!(unused.is_none());
    let (second_handle, unused) = pool.commit_reserved(second, &bytes).unwrap();
    assert!(unused.is_some());
    unused.unwrap().rescind();
    let mut output = alloc::vec![0; RESERVATION_OBJECT_BYTES];
    pool.read_into(first_handle, &mut output).unwrap();
    assert_eq!(output, bytes);
    pool.read_into(second_handle, &mut output).unwrap();
    assert_eq!(output, bytes);
}
