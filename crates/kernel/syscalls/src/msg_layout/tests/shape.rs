// The two ABI shapes, pinned as numbers. A drift here is a silently
// mis-parsed message rather than a compile error, so every offset a decoder
// reads is asserted against the value the ABI defines.

use crate::msg_layout::MsgLayout;

#[test]
fn the_native_msghdr_is_the_lp64_shape() {
    let native = MsgLayout::Native;
    assert!(!native.is_compat());
    assert_eq!(native.word(), 8);
    assert_eq!(native.msghdr_size(), 56);
    let at = native.msghdr();
    assert_eq!((at.name, at.namelen, at.iov, at.iovlen, at.control, at.controllen, at.flags),
        (0, 8, 16, 24, 32, 40, 48));
    assert_eq!(native.iovec_size(), 16);
    assert_eq!(native.cmsghdr_size(), 16);
    assert_eq!(native.cmsg_align(), 8);
}

#[test]
fn the_compat_msghdr_is_the_32_bit_shape() {
    let compat = MsgLayout::Compat;
    assert!(compat.is_compat());
    assert_eq!(compat.word(), 4);
    assert_eq!(compat.msghdr_size(), 28);
    let at = compat.msghdr();
    assert_eq!((at.name, at.namelen, at.iov, at.iovlen, at.control, at.controllen, at.flags),
        (0, 4, 8, 12, 16, 20, 24));
    assert_eq!(compat.iovec_size(), 8);
    assert_eq!(compat.cmsghdr_size(), 12);
    assert_eq!(compat.cmsg_align(), 4);
}

#[test]
fn the_mmsghdr_entry_stride_and_msg_len_offset_follow_the_header() {
    assert_eq!(MsgLayout::Native.mmsghdr_size(), 64);
    assert_eq!(MsgLayout::Native.mmsghdr_len_offset(), 56);
    assert_eq!(MsgLayout::Native.mmsghdr_flags_offset(), 48);
    // The 32-bit entry is HALF the native one. A batch that walked the wrong
    // stride would publish each `msg_len` into a neighbouring entry.
    assert_eq!(MsgLayout::Compat.mmsghdr_size(), 32);
    assert_eq!(MsgLayout::Compat.mmsghdr_len_offset(), 28);
    assert_eq!(MsgLayout::Compat.mmsghdr_flags_offset(), 24);
}

#[test]
fn cmsg_alignment_differs_by_more_than_the_header_size() {
    // 4-byte data: native takes 16+8=24, compat takes 12+4=16. The grids are
    // different, so a compat stream is not a native one with narrower fields.
    assert_eq!(MsgLayout::Native.cmsg_space(4), 24);
    assert_eq!(MsgLayout::Compat.cmsg_space(4), 16);
    assert_eq!(MsgLayout::Native.cmsg_aligned(17), 24);
    assert_eq!(MsgLayout::Compat.cmsg_aligned(17), 20);
    for n in 0..40usize {
        assert_eq!(MsgLayout::Native.cmsg_aligned(n) % 8, 0);
        assert_eq!(MsgLayout::Compat.cmsg_aligned(n) % 4, 0);
        assert!(MsgLayout::Native.cmsg_aligned(n) >= n);
        assert!(MsgLayout::Compat.cmsg_aligned(n) >= n);
    }
}

#[test]
fn a_compat_word_is_read_and_written_zero_extended() {
    let mut raw = [0xffu8; 8];
    raw[..4].copy_from_slice(&0xdead_beefu32.to_ne_bytes());
    assert_eq!(MsgLayout::Compat.word_at(&raw, 0), 0xdead_beef,
        "the high half is NOT part of a 32-bit pointer");
    assert_eq!(MsgLayout::Native.word_at(&raw, 0),
        u64::from_ne_bytes(raw), "the native read takes all eight bytes");
    assert_eq!(&MsgLayout::Compat.word_bytes(0x1_0000_0001)[..4], &1u32.to_ne_bytes(),
        "a value wider than the ABI truncates the way the ABI does");
    assert_eq!(MsgLayout::Native.word_bytes(0x1_0000_0001), 0x1_0000_0001u64.to_ne_bytes());
}
