// Hosted coverage for the receive-side msghdr import and writeback, both ABIs.

use super::*;

const NATIVE_IOVEC: usize = 16;


fn hdr(iov: u64, iovlen: u64) -> [u8; MSGHDR_MAX] {
    let mut out = [0u8; MSGHDR_MAX];
    out[16..24].copy_from_slice(&iov.to_ne_bytes());
    out[24..32].copy_from_slice(&iovlen.to_ne_bytes());
    out
}

// Linux `__copy_msghdr` rejects a negative `msg_namelen` (when a name
// buffer is supplied) before the receive; without a buffer it is ignored.
#[test]
fn negative_msg_namelen_with_name_buffer_is_einval() {
    let name = [0u8; 16];
    let mut h = hdr(0, 0);
    h[0..8].copy_from_slice(&(name.as_ptr() as u64).to_ne_bytes());
    h[8..12].copy_from_slice(&u32::MAX.to_ne_bytes()); // -1 as i32
    assert_eq!(import(h.as_ptr() as u64, MsgLayout::Native).err(), Some(errno(Errno::Einval)));
}

#[test]
fn negative_msg_namelen_without_name_buffer_is_ignored() {
    let mut h = hdr(0, 0);
    h[0..8].copy_from_slice(&0u64.to_ne_bytes()); // msg_name = NULL
    h[8..12].copy_from_slice(&u32::MAX.to_ne_bytes());
    // Import succeeds (no iovecs, empty receive capacity); the length is unused.
    assert!(import(h.as_ptr() as u64, MsgLayout::Native).is_ok());
}

#[test]
fn oversized_msg_namelen_is_clamped_to_sockaddr_storage() {
    let name = [0u8; 200];
    let mut h = hdr(0, 0);
    h[0..8].copy_from_slice(&(name.as_ptr() as u64).to_ne_bytes());
    h[8..12].copy_from_slice(&200u32.to_ne_bytes());
    let imported = import(h.as_ptr() as u64, MsgLayout::Native).unwrap();
    assert_eq!(imported.namelen, SOCKADDR_STORAGE_LEN);
}

#[test]
fn imports_all_iovecs_before_payload_copy() {
    let mut a = [0u8; 3];
    let mut b = [0u8; 2];
    let mut raw = [0u8; NATIVE_IOVEC * 2];
    raw[0..8].copy_from_slice(&(a.as_mut_ptr() as u64).to_ne_bytes());
    raw[8..16].copy_from_slice(&(a.len() as u64).to_ne_bytes());
    raw[16..24].copy_from_slice(&(b.as_mut_ptr() as u64).to_ne_bytes());
    raw[24..32].copy_from_slice(&(b.len() as u64).to_ne_bytes());
    let h = hdr(raw.as_ptr() as u64, 2);
    let imported = import(h.as_ptr() as u64, MsgLayout::Native).unwrap();
    assert_eq!(imported.capacity, 5);
    assert_eq!(imported.copy_payload(b"abcde"), Ok(5));
    assert_eq!(&a, b"abc");
    assert_eq!(&b, b"de");
}

#[test]
fn copies_waitall_suffix_across_iovec_boundary() {
    let mut a = [0u8; 3];
    let mut b = [0u8; 3];
    let imported = RecvUser { msgp: 0, name: 0, namelen: 0, name_len_ptr: 0, control: 0,
        controllen: 0, iov: vec![IoVec { base: a.as_mut_ptr() as u64, len: 3 },
            IoVec { base: b.as_mut_ptr() as u64, len: 3 }], capacity: 6, layout: MsgLayout::Native };
    assert_eq!(imported.copy_payload_at(0, b"ab"), Ok(2));
    assert_eq!(imported.copy_payload_at(2, b"cdef"), Ok(4));
    assert_eq!(&a, b"abc");
    assert_eq!(&b, b"def");
}

#[test]
fn record_copy_rejects_a_landed_prefix_while_stream_copy_returns_it() {
    let mut stream = [0u8; 1];
    let stream_user = RecvUser { msgp: 0, name: 0, namelen: 0, name_len_ptr: 0,
        control: 0, controllen: 0,
        iov: vec![IoVec { base: stream.as_mut_ptr() as u64, len: 1 }], capacity: 2, layout: MsgLayout::Native };
    assert_eq!(stream_user.copy_payload(b"ab"), Ok(1));
    assert_eq!(stream, *b"a");

    let mut record = [0u8; 1];
    let record_user = RecvUser { msgp: 0, name: 0, namelen: 0, name_len_ptr: 0,
        control: 0, controllen: 0,
        iov: vec![IoVec { base: record.as_mut_ptr() as u64, len: 1 }], capacity: 2, layout: MsgLayout::Native };
    assert_eq!(record_user.copy_payload_record(b"ab"), Err(errno(Errno::Efault)));
    assert_eq!(record, *b"a");
}

#[test]
fn rejects_iov_count_with_linux_emsgsize() {
    let h = hdr(0, (UIO_MAXIOV + 1) as u64);
    assert_eq!(import(h.as_ptr() as u64, MsgLayout::Native).err(), Some(errno(Errno::Emsgsize)));
}

#[test]
fn recvfrom_defers_payload_fault_until_copy() {
    let user = import_recvfrom(1, 4, 0, 0);
    assert_eq!(user.capacity, 4);
    assert_eq!(user.iov, vec![IoVec { base: 1, len: 4 }]);
    assert_eq!(user.validate_payload_range(), Ok(()));
}

#[test]
fn recvfrom_rejects_out_of_range_payload_before_receive() {
    let user = import_recvfrom(u64::MAX, 0, 0, 0);
    assert_eq!(user.validate_payload_range(), Err(errno(Errno::Efault)));
}

#[test]
fn recvfrom_source_length_is_late_and_reports_true_size() {
    let mut addr = [0xa5u8; 2];
    let mut len = 2i32;
    let user = import_recvfrom(0, 0, addr.as_mut_ptr() as u64,
        (&mut len as *mut i32) as u64);
    assert_eq!(user.copy_name(b"abcd"), Ok(()));
    assert_eq!(addr, *b"ab");
    assert_eq!(len, 4);
}

#[test]
fn recvfrom_negative_source_length_fails_after_payload_phase() {
    let mut addr = [0xa5u8; 4];
    let mut len = -1i32;
    let user = import_recvfrom(0, 0, addr.as_mut_ptr() as u64,
        (&mut len as *mut i32) as u64);
    assert_eq!(user.copy_name(b"abcd"), Err(errno(Errno::Einval)));
    assert_eq!(addr, [0xa5; 4]);
    assert_eq!(len, -1);
}

#[test]
fn recvfrom_null_source_ignores_length_pointer() {
    let user = import_recvfrom(0, 0, 0, 1);
    assert_eq!(user.copy_name(b"abcd"), Ok(()));
}

#[test]
fn recvfrom_nonnull_source_requires_length_pointer_late() {
    let mut addr = [0xa5u8; 4];
    let user = import_recvfrom(0, 0, addr.as_mut_ptr() as u64, 0);
    assert_eq!(user.copy_name(b"abcd"), Err(errno(Errno::Efault)));
    assert_eq!(addr, [0xa5; 4]);
}

#[test]
fn null_name_leaves_namelen_untouched() {
    let mut h = [0u8; MSGHDR_MAX];
    h[8..12].copy_from_slice(&77u32.to_ne_bytes());
    let user = RecvUser { msgp: h.as_mut_ptr() as u64, name: 0, namelen: 77, name_len_ptr: 0,
        control: 0, controllen: 0, iov: Vec::new(), capacity: 0, layout: MsgLayout::Native };
    assert_eq!(user.copy_name(b"ignored"), Ok(()));
    assert_eq!(MsgLayout::Native.u32_at(&h, 8), 77);
}

// ------------------------------------------------------ the compat layout --
//
// A 32-bit `msghdr` is 28 bytes with every pointer and size 4 wide, so each
// field sits where a native decoder would find a DIFFERENT one. These tests
// read the same bytes both ways: the compat verdict and the native verdict
// must disagree, which is the whole reason the layout is decided once and
// carried as a value.

/// A compat msghdr with a null name, null control, and the given iovec array
/// and control length.
fn compat_hdr(iovlen: u32, controllen: u32) -> [u8; 28] {
    let mut out = [0u8; 28];
    out[12..16].copy_from_slice(&iovlen.to_ne_bytes());
    out[20..24].copy_from_slice(&controllen.to_ne_bytes());
    out
}

#[test]
fn a_compat_iovlen_is_read_from_its_own_offset() {
    // Over the limit at the COMPAT offset (12) and zero at the native one
    // (24), so only a compat decode can produce EMSGSIZE.
    let h = compat_hdr((UIO_MAXIOV + 1) as u32, 0);
    assert_eq!(import(h.as_ptr() as u64, MsgLayout::Compat).err(), Some(errno(Errno::Emsgsize)));
    let mut wide = [0u8; MSGHDR_MAX];
    wide[..28].copy_from_slice(&h);
    assert!(import(wide.as_ptr() as u64, MsgLayout::Native).is_ok(),
        "the same bytes read natively carry no iovec at all");
}

#[test]
fn a_compat_controllen_is_read_from_its_own_offset() {
    let h = compat_hdr(0, 0x1234);
    let imported = import(h.as_ptr() as u64, MsgLayout::Compat).unwrap();
    assert_eq!(imported.controllen, 0x1234);
    assert_eq!(imported.layout, MsgLayout::Compat);
}

#[test]
fn a_compat_receive_publishes_its_lengths_and_flags_in_32_bit_fields() {
    let mut hdr = [0xa5u8; 28];
    let user = RecvUser { msgp: hdr.as_mut_ptr() as u64, name: 0, namelen: 0, name_len_ptr: 0,
        control: 0, controllen: 0, iov: Vec::new(), capacity: 0, layout: MsgLayout::Compat };
    user.finish(24, net::uapi::MSG_CTRUNC as u32).unwrap();
    assert_eq!(u32::from_ne_bytes(hdr[20..24].try_into().unwrap()), 24, "controllen at 20");
    assert_eq!(u32::from_ne_bytes(hdr[24..28].try_into().unwrap()),
        net::uapi::MSG_CTRUNC as u32, "msg_flags at 24");
    assert_eq!(&hdr[..20], &[0xa5; 20], "no native offset is touched");
}

#[test]
fn a_compat_source_length_lands_at_offset_four_not_eight() {
    let mut hdr = [0u8; 28];
    let mut addr = [0u8; 8];
    let user = RecvUser { msgp: hdr.as_mut_ptr() as u64, name: addr.as_mut_ptr() as u64,
        namelen: addr.len() as u32, name_len_ptr: 0, control: 0, controllen: 0,
        iov: Vec::new(), capacity: 0, layout: MsgLayout::Compat };
    user.copy_name(b"abcd").unwrap();
    assert_eq!(u32::from_ne_bytes(hdr[4..8].try_into().unwrap()), 4);
    assert_eq!(u32::from_ne_bytes(hdr[8..12].try_into().unwrap()), 0,
        "the native `msg_namelen` offset is a 32-bit caller's `msg_iov`");
}

// `MSG_CMSG_COMPAT` records which layout the call speaks. It is kernel
// bookkeeping and must never appear in the `msg_flags` the caller reads back.
#[test]
fn the_compat_marker_is_stripped_from_published_msg_flags() {
    for (layout, at) in [(MsgLayout::Native, 48usize), (MsgLayout::Compat, 24)] {
        let mut hdr = [0u8; MSGHDR_MAX];
        let user = RecvUser { msgp: hdr.as_mut_ptr() as u64, name: 0, namelen: 0,
            name_len_ptr: 0, control: 0, controllen: 0, iov: Vec::new(), capacity: 0, layout };
        user.finish(0, net::uapi::MSG_CMSG_COMPAT as u32 | net::uapi::MSG_TRUNC as u32).unwrap();
        assert_eq!(u32::from_ne_bytes(hdr[at..at + 4].try_into().unwrap()),
            net::uapi::MSG_TRUNC as u32, "layout={layout:?}");
    }
}
