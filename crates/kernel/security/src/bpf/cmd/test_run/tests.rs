use super::*;

fn attr32(pairs: &[(usize, u32)]) -> Attr {
    let mut a = Attr::zeroed();
    for (off, value) in pairs { a.bytes[*off..*off + 4].copy_from_slice(&value.to_ne_bytes()); }
    a
}

fn put64(a: &mut Attr, off: usize, value: u64) {
    a.bytes[off..off + 8].copy_from_slice(&value.to_ne_bytes());
}

#[test]
fn check_attr_boundary_is_offsetofend_test_batch_size() {
    use uapi::off::test as o;
    assert_eq!(o::PROG_FD, 0);
    assert_eq!(o::RETVAL, 4);
    assert_eq!(o::DATA_SIZE_IN, 8);
    assert_eq!(o::DATA_SIZE_OUT, 12);
    assert_eq!(o::DATA_IN, 16);
    assert_eq!(o::DATA_OUT, 24);
    assert_eq!(o::REPEAT, 32);
    assert_eq!(o::DURATION, 36);
    assert_eq!(o::CTX_SIZE_IN, 40);
    assert_eq!(o::CTX_SIZE_OUT, 44);
    assert_eq!(o::CTX_IN, 48);
    assert_eq!(o::CTX_OUT, 56);
    assert_eq!(o::FLAGS, 64);
    assert_eq!(o::CPU, 68);
    assert_eq!(o::BATCH_SIZE, 72);
    assert_eq!(o::LAST_END, 76);
}

/// The zero-tail check runs before everything, including the context
/// pairing rules and the program descriptor.
#[test]
fn the_attr_tail_is_checked_first() {
    let mut a = attr32(&[(uapi::off::test::PROG_FD, u32::MAX)]);
    a.bytes[uapi::off::test::LAST_END] = 1;
    assert_eq!(test_run(&a, 0), Err(Errno::Einval));
}

/// A size without a buffer, or a buffer without a size, is a caller
/// error in each direction independently — and it is diagnosed before
/// the program descriptor, so a bad pairing with a closed fd is EINVAL.
#[test]
fn context_size_and_pointer_must_agree_in_each_direction() {
    assert_eq!(ctx_pairing_verdict(0, 0), Ok(()));
    assert_eq!(ctx_pairing_verdict(8, 0x1000), Ok(()));
    assert_eq!(ctx_pairing_verdict(8, 0), Err(Errno::Einval));
    assert_eq!(ctx_pairing_verdict(0, 0x1000), Err(Errno::Einval));

    let mut a = attr32(&[
        (uapi::off::test::PROG_FD, u32::MAX),
        (uapi::off::test::CTX_SIZE_IN, 8),
    ]);
    assert_eq!(test_run(&a, 0), Err(Errno::Einval));
    put64(&mut a, uapi::off::test::CTX_IN, 0x1000);
    // In-direction now agrees; the out direction is still clean, so the
    // descriptor is what fails.
    assert_eq!(test_run(&a, 0), Err(Errno::Ebadf));
}

/// Only program types with a test-run implementation can be run, and a
/// type without one is ENOTSUPP (524) rather than EINVAL or EOPNOTSUPP.
#[test]
fn program_types_without_a_test_run_implementation_are_enotsupp() {
    use uapi::prog_type as p;
    assert_eq!(runner_for(p::SOCKET_FILTER), Some(Runner::Skb));
    assert_eq!(runner_for(p::CGROUP_SKB), Some(Runner::Skb));
    for none in [p::CGROUP_DEVICE, p::CGROUP_SOCK_ADDR, p::XDP, p::LSM, p::UNSPEC] {
        assert_eq!(runner_for(none), None);
    }
    assert_eq!(Errno::Enotsupp.as_i32(), 524);
}

#[test]
fn an_skb_run_accepts_only_the_checksum_flag_and_no_cpu_or_batch() {
    assert_eq!(skb_flag_verdict(0, 0, 0), Ok(()));
    assert_eq!(skb_flag_verdict(uapi::test_flags::SKB_CHECKSUM_COMPLETE, 0, 0), Ok(()));
    assert_eq!(skb_flag_verdict(uapi::test_flags::RUN_ON_CPU, 0, 0), Err(Errno::Einval));
    assert_eq!(skb_flag_verdict(uapi::test_flags::XDP_LIVE_FRAMES, 0, 0), Err(Errno::Einval));
    assert_eq!(skb_flag_verdict(0, 1, 0), Err(Errno::Einval));
    assert_eq!(skb_flag_verdict(0, 0, 1), Err(Errno::Einval));
}

#[test]
fn an_skb_run_needs_at_least_a_link_layer_header() {
    assert_eq!(uapi::ETH_HLEN, 14);
    for short in [0u32, 1, uapi::ETH_HLEN - 1] {
        assert_eq!(skb_data_size_verdict(short), Err(Errno::Einval));
    }
    assert_eq!(skb_data_size_verdict(uapi::ETH_HLEN), Ok(()));
    assert_eq!(skb_data_size_verdict(uapi::TEST_RUN_DATA_MAX), Ok(()));
    assert_eq!(skb_data_size_verdict(uapi::TEST_RUN_DATA_MAX + 1), Err(Errno::Enomem));
}

#[test]
fn a_zero_repeat_means_one_run() {
    assert_eq!(repeat_count(0), 1);
    assert_eq!(repeat_count(1), 1);
    assert_eq!(repeat_count(9), 9);
}

#[test]
fn the_reported_duration_is_per_run() {
    assert_eq!(duration_per_run(1000, 10), 100);
    assert_eq!(duration_per_run(1000, 0), 1000);
    assert_eq!(duration_per_run(u64::MAX, 1), u32::MAX);
}

/// A context longer than this kernel's is admitted only when the excess
/// is zero; a nonzero excess means a field this kernel does not have.
#[test]
fn an_oversized_input_context_must_be_zero_past_this_kernels_layout() {
    let mut buf = [0u8; skb_ctx::SIZE + 8];
    let ptr = buf.as_ptr() as u64;
    assert_eq!(ctx_tail_verdict(ptr, skb_ctx::SIZE, skb_ctx::SIZE as u32), Ok(()));
    assert_eq!(ctx_tail_verdict(ptr, skb_ctx::SIZE, 8), Ok(()));
    assert_eq!(ctx_tail_verdict(ptr, skb_ctx::SIZE, buf.len() as u32), Ok(()));
    buf[skb_ctx::SIZE] = 1;
    let ptr = buf.as_ptr() as u64;
    assert_eq!(ctx_tail_verdict(ptr, skb_ctx::SIZE, buf.len() as u32), Err(Errno::E2big));
    assert_eq!(ctx_tail_verdict(ptr, skb_ctx::SIZE, uapi::PAGE_SIZE + 1), Err(Errno::E2big));
}

/// Neither direction requested means no context at all, which is what
/// lets a caller run a program without supplying one.
#[test]
fn no_context_pointers_means_no_context() {
    let a = Attr::zeroed();
    assert_eq!(ctx_init(&a), Ok(None));
}

/// A context requested for output only starts zeroed rather than
/// reading the caller's output buffer.
#[test]
fn an_output_only_context_starts_zeroed() {
    let mut out = [0xAAu8; skb_ctx::SIZE];
    let mut a = Attr::zeroed();
    put64(&mut a, uapi::off::test::CTX_OUT, out.as_mut_ptr() as u64);
    let mut b = a;
    b.bytes[uapi::off::test::CTX_SIZE_OUT..uapi::off::test::CTX_SIZE_OUT + 4]
        .copy_from_slice(&(skb_ctx::SIZE as u32).to_ne_bytes());
    assert_eq!(ctx_init(&b), Ok(Some([0u8; skb_ctx::SIZE])));
}

/// A short output buffer clamps the copy and reports ENOSPC, but every
/// metadata field is written anyway.
#[test]
fn a_short_data_out_reports_enospc_and_still_writes_the_metadata() {
    use uapi::off::test as o;
    let mut attr_store = [0u8; uapi::ATTR_SIZE];
    let attr_ptr = attr_store.as_mut_ptr() as u64;
    let mut out = [0u8; 4];
    let mut a = Attr::zeroed();
    put64(&mut a, o::DATA_OUT, out.as_mut_ptr() as u64);
    a.bytes[o::DATA_SIZE_OUT..o::DATA_SIZE_OUT + 4].copy_from_slice(&4u32.to_ne_bytes());

    let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(test_finish(&a, attr_ptr, &data, 7, 11), Err(Errno::Enospc));
    assert_eq!(out, [1, 2, 3, 4]);
    let read = |off: usize| u32::from_ne_bytes(attr_store[off..off + 4].try_into().unwrap());
    assert_eq!(read(o::DATA_SIZE_OUT), 8);
    assert_eq!(read(o::RETVAL), 7);
    assert_eq!(read(o::DURATION), 11);
}

/// A `data_size_out` of zero is "no size hint": the whole frame is
/// copied and the call succeeds.
#[test]
fn a_zero_data_size_out_copies_the_whole_frame() {
    use uapi::off::test as o;
    let mut attr_store = [0u8; uapi::ATTR_SIZE];
    let attr_ptr = attr_store.as_mut_ptr() as u64;
    let mut out = [0u8; 8];
    let mut a = Attr::zeroed();
    put64(&mut a, o::DATA_OUT, out.as_mut_ptr() as u64);
    let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(test_finish(&a, attr_ptr, &data, 0, 0), Ok(0));
    assert_eq!(out, data);
}

/// A short `ctx_size_out` clamps the context copy, reports ENOSPC, and
/// still records the real context size.
#[test]
fn a_short_ctx_size_out_reports_enospc_and_records_the_real_size() {
    use uapi::off::test as o;
    let mut attr_store = [0u8; uapi::ATTR_SIZE];
    let attr_ptr = attr_store.as_mut_ptr() as u64;
    let mut out = [0u8; skb_ctx::SIZE];
    let mut a = Attr::zeroed();
    put64(&mut a, o::CTX_OUT, out.as_mut_ptr() as u64);
    a.bytes[o::CTX_SIZE_OUT..o::CTX_SIZE_OUT + 4].copy_from_slice(&8u32.to_ne_bytes());
    let ctx = [0x5Au8; skb_ctx::SIZE];
    assert_eq!(ctx_finish(&a, attr_ptr, Some(&ctx)), Err(Errno::Enospc));
    assert_eq!(&out[..8], &[0x5A; 8]);
    assert_eq!(out[8], 0);
    let size = u32::from_ne_bytes(
        attr_store[o::CTX_SIZE_OUT..o::CTX_SIZE_OUT + 4].try_into().unwrap(),
    );
    assert_eq!(size, skb_ctx::SIZE as u32);

    a.bytes[o::CTX_SIZE_OUT..o::CTX_SIZE_OUT + 4]
        .copy_from_slice(&(skb_ctx::SIZE as u32).to_ne_bytes());
    assert_eq!(ctx_finish(&a, attr_ptr, Some(&ctx)), Ok(0));
}

#[test]
fn no_context_out_pointer_means_nothing_is_written_back() {
    let a = Attr::zeroed();
    assert_eq!(ctx_finish(&a, 0, None), Ok(0));
    assert_eq!(ctx_finish(&a, 0, Some(&[0u8; skb_ctx::SIZE])), Ok(0));
}
