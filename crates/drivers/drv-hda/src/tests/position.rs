// DMA position buffer preference and controller slot layout.

use super::*;

#[test]
fn the_controller_receives_both_halves_of_the_dma_address() {
    assert_eq!(base_words(0x1234_5678_9abc_d000), (0x9abc_d000, 0x1234_5678));
}

#[test]
fn each_stream_owns_its_eight_byte_slot() {
    assert_eq!(slot_va(0x8000, 0), 0x8000);
    assert_eq!(slot_va(0x8000, 3), 0x8018);
}

#[test]
fn a_nonzero_position_buffer_outranks_the_lagging_link_register() {
    assert_eq!(select(3072, 2048, 4096), 3072);
}

#[test]
fn zero_or_invalid_position_buffer_falls_back_to_the_link_register() {
    assert_eq!(select(0, 2048, 4096), 2048);
    assert_eq!(select(u32::MAX, 6144, 4096), 2048);
}

#[test]
fn an_out_of_range_position_is_not_reported_to_alsa() {
    assert_eq!(select(4096, 1024, 4096), 0);
    assert_eq!(select(1, 1, 0), 0);
}
