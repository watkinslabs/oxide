// Ancillary conversion between the two ABIs: what a 32-bit sender's control
// stream becomes before any protocol parses it, and what a malformed one
// reports.

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::msg_layout::MsgLayout;
use crate::msg_layout::cmsg::{Entry, compat_to_native, header_bytes, walk};

const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;

/// One control entry in `layout`'s shape, padded to its aligned size.
fn entry(layout: MsgLayout, level: i32, ty: i32, data: &[u8]) -> Vec<u8> {
    let len = layout.cmsghdr_size() + data.len();
    let mut out = header_bytes(layout, len, level, ty);
    out.extend_from_slice(data);
    out.resize(layout.cmsg_aligned(len), 0);
    out
}

#[test]
fn a_compat_header_is_twelve_bytes_with_a_32_bit_length() {
    let compat = header_bytes(MsgLayout::Compat, 16, SOL_SOCKET, SCM_RIGHTS);
    assert_eq!(compat.len(), 12);
    assert_eq!(u32::from_ne_bytes(compat[0..4].try_into().unwrap()), 16);
    assert_eq!(i32::from_ne_bytes(compat[4..8].try_into().unwrap()), SOL_SOCKET);
    assert_eq!(i32::from_ne_bytes(compat[8..12].try_into().unwrap()), SCM_RIGHTS);

    let native = header_bytes(MsgLayout::Native, 20, SOL_SOCKET, SCM_RIGHTS);
    assert_eq!(native.len(), 16);
    assert_eq!(u64::from_ne_bytes(native[0..8].try_into().unwrap()), 20);
    assert_eq!(i32::from_ne_bytes(native[8..12].try_into().unwrap()), SOL_SOCKET);
    assert_eq!(i32::from_ne_bytes(native[12..16].try_into().unwrap()), SCM_RIGHTS);
}

#[test]
fn a_compat_walk_finds_every_entry_on_the_four_byte_grid() {
    let mut stream = entry(MsgLayout::Compat, SOL_SOCKET, SCM_RIGHTS, &[1, 2, 3, 4]);
    let second = stream.len();
    stream.extend_from_slice(&entry(MsgLayout::Compat, 6, 7, &[9]));
    let found = walk(MsgLayout::Compat, &stream).unwrap();
    assert_eq!(found, alloc::vec![
        Entry { at: 0, len: 16, level: SOL_SOCKET, ty: SCM_RIGHTS },
        Entry { at: second, len: 13, level: 6, ty: 7 }]);
    assert_eq!(found[0].data(MsgLayout::Compat, &stream), &[1, 2, 3, 4]);
    assert_eq!(found[1].data(MsgLayout::Compat, &stream), &[9]);
}

#[test]
fn a_control_length_too_short_for_one_header_yields_no_entry() {
    for len in 0..12usize {
        let stream = alloc::vec![0u8; len];
        assert_eq!(walk(MsgLayout::Compat, &stream), Ok(Vec::new()), "len={len}");
        // ... and a send that claimed to carry control data but produced no
        // entry is the caller's error, not a silent empty send.
        assert_eq!(compat_to_native(&stream), Err(Errno::Einval), "len={len}");
    }
}

#[test]
fn a_cmsg_len_below_a_header_or_past_the_buffer_is_einval() {
    let mut short = entry(MsgLayout::Compat, SOL_SOCKET, SCM_RIGHTS, &[0; 4]);
    short[0..4].copy_from_slice(&11u32.to_ne_bytes());
    assert_eq!(walk(MsgLayout::Compat, &short), Err(Errno::Einval));
    assert_eq!(compat_to_native(&short), Err(Errno::Einval));

    let mut over = entry(MsgLayout::Compat, SOL_SOCKET, SCM_RIGHTS, &[0; 4]);
    let past_end = (over.len() + 1) as u32;
    over[0..4].copy_from_slice(&past_end.to_ne_bytes());
    assert_eq!(walk(MsgLayout::Compat, &over), Err(Errno::Einval));
    assert_eq!(compat_to_native(&over), Err(Errno::Einval));
}

#[test]
fn a_trailing_remnant_too_short_to_hold_a_header_is_malformed() {
    // The walk advances onto a header that cannot fit. Whatever length were
    // read there would have to be <= the bytes left, which is fewer than one
    // header, so no well-formed entry can begin there.
    let mut stream = entry(MsgLayout::Compat, SOL_SOCKET, SCM_RIGHTS, &[1, 2, 3, 4]);
    stream.extend_from_slice(&[0u8; 4]);
    assert_eq!(walk(MsgLayout::Compat, &stream), Err(Errno::Einval));
}

#[test]
fn a_compat_stream_is_rebuilt_on_the_native_grid_with_its_payload_intact() {
    let mut stream = entry(MsgLayout::Compat, SOL_SOCKET, SCM_RIGHTS, &[1, 2, 3, 4]);
    stream.extend_from_slice(&entry(MsgLayout::Compat, 41, 42, &[7, 8]));
    let native = compat_to_native(&stream).unwrap();

    // Native: CMSG_SPACE(4) = 24, CMSG_SPACE(2) = 24.
    assert_eq!(native.len(), 48);
    assert_eq!(u64::from_ne_bytes(native[0..8].try_into().unwrap()), 20);
    assert_eq!(i32::from_ne_bytes(native[8..12].try_into().unwrap()), SOL_SOCKET);
    assert_eq!(i32::from_ne_bytes(native[12..16].try_into().unwrap()), SCM_RIGHTS);
    assert_eq!(&native[16..20], &[1, 2, 3, 4]);
    assert_eq!(&native[20..24], &[0; 4], "the alignment gap is zeroed, not payload");
    assert_eq!(u64::from_ne_bytes(native[24..32].try_into().unwrap()), 18);
    assert_eq!(i32::from_ne_bytes(native[32..36].try_into().unwrap()), 41);
    assert_eq!(i32::from_ne_bytes(native[36..40].try_into().unwrap()), 42);
    assert_eq!(&native[40..42], &[7, 8]);

    // The rebuilt stream is exactly what a native walk expects to find.
    let found = walk(MsgLayout::Native, &native).unwrap();
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].data(MsgLayout::Native, &native), &[1, 2, 3, 4]);
    assert_eq!(found[1].data(MsgLayout::Native, &native), &[7, 8]);
}

// The reason the conversion exists: handing a 32-bit stream straight to a
// native parser reads the level and type out of the payload.
#[test]
fn a_compat_stream_parsed_as_native_finds_the_wrong_entry() {
    let stream = entry(MsgLayout::Compat, SOL_SOCKET, SCM_RIGHTS, &[0xaa; 8]);
    let misread = walk(MsgLayout::Native, &stream);
    // Either the native walk rejects the stream outright or it finds an entry
    // that is not the one the sender wrote — never the sender's entry.
    assert_ne!(misread.ok().and_then(|found| found.first().map(|e| (e.level, e.ty))),
        Some((SOL_SOCKET, SCM_RIGHTS)));
    let converted = compat_to_native(&stream).unwrap();
    assert_eq!(walk(MsgLayout::Native, &converted).unwrap()[0].level, SOL_SOCKET);
    assert_eq!(walk(MsgLayout::Native, &converted).unwrap()[0].ty, SCM_RIGHTS);
}
