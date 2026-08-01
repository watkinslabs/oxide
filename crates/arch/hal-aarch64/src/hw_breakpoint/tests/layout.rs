// Byte layout of the hardware-debug regset buffer.

use crate::hw_breakpoint::idreg::{dbg_info, DEBUGVER_V8};
use crate::hw_breakpoint::layout::*;

#[test]
fn regset_layout_matches_the_abi_struct() {
    assert_eq!(DBG_INFO_OFF, 0);
    assert_eq!(HDR_PAD_OFF, 4);
    assert_eq!(DBG_REGS_OFF, 8);
    assert_eq!(SLOT_BYTES, 16);
    assert_eq!(REGSET_SLOTS, 16);
    assert_eq!(STATE_BYTES, 264);
    assert_eq!(REGSET_N, 66);
    assert_eq!(REGSET_GRANULE, 4);
}

#[test]
fn regset_slot_offsets_are_the_abi_offsets() {
    assert_eq!(slot_addr_off(0), 8);
    assert_eq!(slot_ctrl_off(0), 16);
    assert_eq!(slot_pad_off(0), 20);
    assert_eq!(slot_addr_off(1), 24);
    assert_eq!(slot_addr_off(REGSET_SLOTS - 1), STATE_BYTES - SLOT_BYTES);
}

#[test]
fn regset_offset_maps_back_to_its_slot() {
    assert_eq!(slot_of_off(0), None);
    assert_eq!(slot_of_off(DBG_REGS_OFF - 1), None);
    assert_eq!(slot_of_off(DBG_REGS_OFF), Some(0));
    assert_eq!(slot_of_off(DBG_REGS_OFF + SLOT_BYTES - 1), Some(0));
    assert_eq!(slot_of_off(DBG_REGS_OFF + SLOT_BYTES), Some(1));
    assert_eq!(slot_of_off(STATE_BYTES), None);
}

#[test]
fn regset_buffer_round_trips_header_and_slots() {
    let mut buf = [0xAAu8; STATE_BYTES];
    let info = dbg_info(DEBUGVER_V8, 6);
    assert!(put_header(&mut buf, info));
    for i in 0..REGSET_SLOTS {
        assert!(put_slot(&mut buf, i, 0x1000 + i as u64 * 8, 0x1e5 + i as u32));
    }
    assert_eq!(get_header(&buf), Some(info));
    for i in 0..REGSET_SLOTS {
        assert_eq!(get_slot(&buf, i), Some((0x1000 + i as u64 * 8, 0x1e5 + i as u32)));
    }
    // Both pads are zeroed by the writers.
    assert_eq!(&buf[HDR_PAD_OFF..HDR_PAD_OFF + 4], &[0, 0, 0, 0]);
    assert_eq!(&buf[slot_pad_off(3)..slot_pad_off(3) + 4], &[0, 0, 0, 0]);
}

#[test]
fn regset_buffer_writes_land_at_the_declared_offsets() {
    let mut buf = [0u8; STATE_BYTES];
    put_header(&mut buf, 0x0000_0606);
    put_slot(&mut buf, 2, 0x0807_0605_0403_0201, 0x1112_1314);
    let mut w = [0u8; 8];
    w.copy_from_slice(&buf[slot_addr_off(2)..slot_addr_off(2) + 8]);
    assert_eq!(u64::from_ne_bytes(w), 0x0807_0605_0403_0201);
    let mut c = [0u8; 4];
    c.copy_from_slice(&buf[slot_ctrl_off(2)..slot_ctrl_off(2) + 4]);
    assert_eq!(u32::from_ne_bytes(c), 0x1112_1314);
}

#[test]
fn regset_buffer_refuses_short_buffers_and_out_of_range_slots() {
    let mut short = [0u8; DBG_REGS_OFF - 1];
    assert!(!put_header(&mut short, 0));
    assert_eq!(get_header(&short), None);
    let mut buf = [0u8; STATE_BYTES];
    assert!(!put_slot(&mut buf, REGSET_SLOTS, 0, 0));
    assert_eq!(get_slot(&buf, REGSET_SLOTS), None);
    let mut one = [0u8; DBG_REGS_OFF + SLOT_BYTES];
    assert!(put_slot(&mut one, 0, 1, 2));
    assert!(!put_slot(&mut one, 1, 1, 2));
}

