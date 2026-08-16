// Provenance: BDL construction and the DMA ring arithmetic. A descriptor
// crossing a 4 KiB boundary, or a period that is not a whole number of
// 128-byte blocks, is rejected by the controller.

use super::*;

#[test]
fn periods_align_down_to_a_whole_number_of_blocks() {
    assert_eq!(align_period(4096), 4096);
    assert_eq!(align_period(4000), 3968);
    assert_eq!(align_period(1), 128);
    assert_eq!(align_period(127), 128);
    assert_eq!(align_period(128), 128);
}

#[test]
fn one_entry_per_period_each_raising_an_interrupt() {
    let geometry = Geometry { period_bytes: 4096, periods: 4 };
    let entries = build(0x1000_0000, &geometry).expect("aligned buffer");
    assert_eq!(entries.len(), 4);
    assert!(entries.iter().all(|entry| entry.ioc));
    assert_eq!(entries[0].addr, 0x1000_0000);
    assert_eq!(entries[3].addr, 0x1000_3000);
    assert_eq!(geometry.buffer_bytes(), 16384);
}

#[test]
fn a_period_straddling_a_page_boundary_is_split_with_the_interrupt_last() {
    let geometry = Geometry { period_bytes: 2048, periods: 2 };
    // Starting 1 KiB into a page puts the second period across the boundary.
    let entries = build(0x1000_0400, &geometry).expect("split buffer");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0], Bdle { addr: 0x1000_0400, len: 2048, ioc: true });
    assert_eq!(entries[1], Bdle { addr: 0x1000_0c00, len: 1024, ioc: false });
    assert_eq!(entries[2], Bdle { addr: 0x1000_1000, len: 1024, ioc: true });
    // No descriptor crosses a 4 KiB boundary.
    assert!(entries.iter().all(|e| (e.addr & 0xfff) + u64::from(e.len) <= 0x1000));
    // Exactly one interrupt per period.
    assert_eq!(entries.iter().filter(|e| e.ioc).count(), 2);
}

#[test]
fn a_buffer_needing_more_descriptors_than_the_list_holds_is_refused() {
    let geometry = Geometry { period_bytes: 128, periods: BDL_MAX_ENTRIES as u32 + 1 };
    assert!(build(0x1000_0000, &geometry).is_none());
    assert!(build(0x1000_0000, &Geometry { period_bytes: 0, periods: 2 }).is_none());
    assert!(build(0x1000_0000, &Geometry { period_bytes: 128, periods: 0 }).is_none());
}

#[test]
fn a_descriptor_encodes_address_length_and_the_interrupt_flag() {
    assert_eq!(encode(&Bdle { addr: 0x1_2345_6789, len: 0x400, ioc: true }),
               [0x2345_6789, 0x1, 0x400, BDL_IOC]);
    assert_eq!(encode(&Bdle { addr: 0, len: 0, ioc: false })[3], 0);
}

#[test]
fn ring_space_never_lets_full_look_like_empty() {
    assert_eq!(writable(1024, 0, 0), 1023);
    assert_eq!(writable(1024, 512, 0), 511);
    // The hardware has caught up to one byte behind the writer.
    assert_eq!(writable(1024, 0, 1), 0);
    assert_eq!(writable(0, 0, 0), 0);
}

#[test]
fn ring_offsets_advance_and_split_at_the_wrap() {
    assert_eq!(advance(1024, 1000, 24), 0);
    assert_eq!(advance(1024, 1000, 25), 1);
    assert_eq!(split_at_wrap(1024, 1000, 100), (24, 76));
    assert_eq!(split_at_wrap(1024, 0, 100), (100, 0));
}

#[test]
fn total_frames_accumulates_completed_laps() {
    // Two full laps of a 4096-byte buffer plus 1024 bytes, 4 bytes a frame.
    assert_eq!(total_frames(2, 4096, 1024, 4), (2 * 4096 + 1024) / 4);
    assert_eq!(total_frames(0, 4096, 0, 4), 0);
    assert_eq!(total_frames(1, 4096, 0, 0), 0);
}
