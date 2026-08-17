// A cached page's storage, and the one-way heap→frame conversion that makes it
// mappable.
//
// The conversion is the whole point of the type, so the tests are about the
// invariant that there is never a second copy: after `to_frame` the bytes read
// back through the SAME accessors, a write through the frame is visible to the
// page, and the address does not change on a second ask.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::pagecache::tests::{released_for, test_frame_ptr, with_frames};
use crate::types::PAGE_BYTES;

use super::PageBuf;

fn pattern(seed: u8) -> Vec<u8> {
    (0..PAGE_BYTES).map(|i| seed.wrapping_add(i as u8)).collect()
}

#[test]
fn a_page_with_no_frame_has_no_address_and_still_holds_its_bytes() {
    let bytes = pattern(3);
    let buf = PageBuf::from_vec(bytes.clone());
    assert_eq!(buf.pa(), None, "a heap page has no machine address to hand out");
    assert_eq!(&buf[..], &bytes[..]);
}

#[test]
fn converting_to_a_frame_moves_the_bytes_and_leaves_one_copy() {
    with_frames();
    let bytes = pattern(0x5A);
    let mut buf = PageBuf::from_vec(bytes.clone());
    let pa = buf.to_frame().expect("a frame is available");
    assert_ne!(pa, 0);
    assert_eq!(buf.pa(), Some(pa), "the address is the one the conversion chose");
    assert_eq!(&buf[..], &bytes[..], "every byte survived the move into the frame");

    // A store THROUGH the frame — what a user page table's write does — is
    // visible to the page, which is what "one copy" means.
    let base = test_frame_ptr(pa).expect("frame pointer");
    // SAFETY: `base` is this test pool's mapping of the page's own frame.
    unsafe { core::ptr::write_bytes(base, 0xC7, 16); }
    assert!(buf[..16].iter().all(|&b| b == 0xC7), "the page reads what was stored into its frame");
    assert_eq!(&buf[16..], &bytes[16..], "and nothing else moved");
}

#[test]
fn a_second_conversion_answers_the_same_frame() {
    with_frames();
    let mut buf = PageBuf::from_vec(pattern(1));
    let first = buf.to_frame().expect("first");
    let again = buf.to_frame().expect("second");
    assert_eq!(first, again, "a page's frame is chosen once, so a mapper's address is stable");
}

#[test]
fn a_shorter_buffer_is_zero_filled_into_the_frame() {
    with_frames();
    let mut buf = PageBuf::from_vec(vec![0xEE; 8]);
    let pa = buf.to_frame().expect("frame");
    let base = test_frame_ptr(pa).expect("frame pointer");
    // SAFETY: the pool page is PAGE_BYTES long and owned by this page.
    let seen = unsafe { core::slice::from_raw_parts(base, PAGE_BYTES) };
    assert!(seen[..8].iter().all(|&b| b == 0xEE));
    assert!(seen[8..].iter().all(|&b| b == 0), "the tail of a short buffer is zero, never stale frame bytes");
}

#[test]
fn dropping_a_framed_page_returns_its_reference() {
    with_frames();
    let mut pa = 0u64;
    { let mut buf = PageBuf::from_vec(pattern(9)); pa = buf.to_frame().expect("frame"); }
    assert_eq!(released_for(pa), 1, "the page's own reference is dropped exactly once");
}

// A heap page's `Drop` returning nothing has NO test here, deliberately. The
// only way to observe it is a release count, and a total is a counter every
// test in the binary steps — an assertion on it is a race, which is how it
// flaked before this note existed. Per-frame counts fix that for a frame a test
// OWNS, but a page that never took a frame owns none to ask about, so no
// per-frame assertion can fail either. The behaviour is a one-branch early
// return on `frame == 0` and is covered indirectly by
// `a_page_with_no_frame_has_no_address_and_still_holds_its_bytes`.
