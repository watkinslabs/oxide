use super::*;
use crate::devfs::handle_evdev_ioctl;
use crate::evdev_mask::{INPUT_MASK_BYTES, MASK_MAX_BYTES, MASK_UNSET_FILL, MASK_WORD_BYTES};

/// Mask commands read and write only the calling file description's own state,
/// so every test here can share one published evdev slot.
const EVDEV_ID: u32 = 6;
const KEY_MASK_BYTES: usize = MASK_MAX_BYTES;
const TYPE_WITH_NO_MASK: u32 = 0x14;
const KEY_A: u16 = 30;

fn descriptor_in(ev_type: u32, codes: &[u8]) -> [u8; INPUT_MASK_BYTES] {
    descriptor_raw(ev_type, codes.len() as u32, codes.as_ptr() as u64)
}

fn descriptor_out(ev_type: u32, codes: &mut [u8]) -> [u8; INPUT_MASK_BYTES] {
    descriptor_raw(ev_type, codes.len() as u32, codes.as_mut_ptr() as u64)
}

fn descriptor_raw(ev_type: u32, codes_size: u32, codes_ptr: u64) -> [u8; INPUT_MASK_BYTES] {
    let mut raw = [0u8; INPUT_MASK_BYTES];
    raw[0..4].copy_from_slice(&ev_type.to_le_bytes());
    raw[4..8].copy_from_slice(&codes_size.to_le_bytes());
    raw[8..16].copy_from_slice(&codes_ptr.to_le_bytes());
    raw
}

fn einval() -> Option<i64> {
    Some(-(syscall::errno::Errno::Einval.as_i32() as i64))
}

fn efault() -> Option<i64> {
    Some(-(syscall::errno::Errno::Efault.as_i32() as i64))
}

fn key_mask(code: u16) -> [u8; KEY_MASK_BYTES] {
    let mut bits = [0u8; KEY_MASK_BYTES];
    bits[usize::from(code) / u8::BITS as usize] |= 1 << (code % u8::BITS as u16);
    bits
}

#[test]
fn unset_mask_reads_back_as_every_code_admitted() {
    let _serial = super::serialize();
    const TAIL_BYTES: usize = 16;

    let file = test_file(EVDEV_ID);
    let mut codes = [0u8; KEY_MASK_BYTES + TAIL_BYTES];
    let desc = descriptor_out(u32::from(crate::EV_KEY), &mut codes);
    assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCGMASK, desc.as_ptr() as u64), Some(0));
    assert!(codes[..KEY_MASK_BYTES].iter().all(|b| *b == MASK_UNSET_FILL));
    assert!(codes[KEY_MASK_BYTES..].iter().all(|b| *b == 0));
}

#[test]
fn a_written_mask_reads_back_byte_for_byte() {
    let _serial = super::serialize();
    let file = test_file(EVDEV_ID);
    let wanted = key_mask(KEY_A);
    let set = descriptor_in(u32::from(crate::EV_KEY), &wanted);
    assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCSMASK, set.as_ptr() as u64), Some(0));

    let mut read_back = [MASK_UNSET_FILL; KEY_MASK_BYTES];
    let get = descriptor_out(u32::from(crate::EV_KEY), &mut read_back);
    assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCGMASK, get.as_ptr() as u64), Some(0));
    assert_eq!(read_back, wanted);
}

#[test]
fn a_short_read_buffer_truncates_rather_than_failing() {
    let _serial = super::serialize();
    const MARKER: u8 = 0xa5;

    let file = test_file(EVDEV_ID);
    let mut wanted = [0u8; KEY_MASK_BYTES];
    wanted[0] = MARKER;
    let set = descriptor_in(u32::from(crate::EV_KEY), &wanted);
    assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCSMASK, set.as_ptr() as u64), Some(0));

    let mut short = [0u8; MASK_WORD_BYTES];
    let get = descriptor_out(u32::from(crate::EV_KEY), &mut short);
    assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCGMASK, get.as_ptr() as u64), Some(0));
    assert_eq!(short[0], MARKER);
}

#[test]
fn a_write_buffer_that_is_not_whole_words_is_refused() {
    let _serial = super::serialize();
    const ODD_BYTES: usize = 5;

    let file = test_file(EVDEV_ID);
    let codes = [0u8; ODD_BYTES];
    let set = descriptor_in(u32::from(crate::EV_KEY), &codes);
    assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCSMASK, set.as_ptr() as u64), einval());
}

#[test]
fn a_type_with_no_mask_is_accepted_on_write_and_zeroed_on_read() {
    let _serial = super::serialize();
    const ODD_BYTES: usize = 5;

    let file = test_file(EVDEV_ID);
    let codes = [0xffu8; ODD_BYTES];
    let set = descriptor_in(TYPE_WITH_NO_MASK, &codes);
    assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCSMASK, set.as_ptr() as u64), Some(0));

    let mut out = [0xffu8; MASK_WORD_BYTES];
    let get = descriptor_out(TYPE_WITH_NO_MASK, &mut out);
    assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCGMASK, get.as_ptr() as u64), Some(0));
    assert!(out.iter().all(|b| *b == 0));
}

#[test]
fn a_zero_length_buffer_needs_no_valid_pointer() {
    let _serial = super::serialize();
    let file = test_file(EVDEV_ID);
    let get = descriptor_raw(u32::from(crate::EV_KEY), 0, 0);
    assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCGMASK, get.as_ptr() as u64), Some(0));
    let set = descriptor_raw(u32::from(crate::EV_KEY), 0, 0);
    assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCSMASK, set.as_ptr() as u64), Some(0));
}

#[test]
fn unreadable_descriptor_and_code_buffers_fault() {
    let _serial = super::serialize();
    let file = test_file(EVDEV_ID);
    assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCGMASK, 0), efault());
    assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCSMASK, 0), efault());
    let get = descriptor_raw(u32::from(crate::EV_KEY), MASK_WORD_BYTES as u32, 0);
    assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCGMASK, get.as_ptr() as u64), efault());
    let set = descriptor_raw(u32::from(crate::EV_KEY), MASK_WORD_BYTES as u32, 0);
    assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCSMASK, set.as_ptr() as u64), efault());
}

#[test]
fn masks_are_per_open_file_description() {
    let _serial = super::serialize();
    let first = test_file(EVDEV_ID);
    let second = test_file(EVDEV_ID);
    let wanted = key_mask(KEY_A);
    let set = descriptor_in(u32::from(crate::EV_KEY), &wanted);
    assert_eq!(handle_evdev_ioctl(&first, crate::EVIOCSMASK, set.as_ptr() as u64), Some(0));

    let mut read_back = [0u8; KEY_MASK_BYTES];
    let get = descriptor_out(u32::from(crate::EV_KEY), &mut read_back);
    assert_eq!(handle_evdev_ioctl(&second, crate::EVIOCGMASK, get.as_ptr() as u64), Some(0));
    assert!(read_back.iter().all(|b| *b == MASK_UNSET_FILL));
}

#[test]
fn a_masked_open_still_delivers_admitted_events_end_to_end() {
    let _serial = super::serialize();
    const DELIVERY_ID: u32 = 7;

    let file = test_file(DELIVERY_ID);
    let wanted = key_mask(KEY_A);
    let set = descriptor_in(u32::from(crate::EV_KEY), &wanted);
    assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCSMASK, set.as_ptr() as u64), Some(0));

    crate::evdev_queue::push_packet(DELIVERY_ID, &[
        input::InputValue { ev_type: crate::EV_KEY, code: KEY_A, value: 1 },
        input::InputValue { ev_type: crate::EV_SYN, code: crate::SYN_REPORT, value: 0 },
    ]);
    assert_eq!(file.poll() & vfs::POLL_IN, vfs::POLL_IN);
    let mut buf = [0u8; crate::evdev_queue::INPUT_EVENT_BYTES * 2];
    assert_eq!(file.read(&mut buf).expect("admitted packet"), buf.len());
}
