// Layout, length and chunking rules of ptrace's user-buffer transfers. These
// run hosted BECAUSE they live beside an ungated module: the four call sites
// they cover (`info.rs`, `mem.rs`, `regset.rs`, `sig.rs`) are whole-file
// kernel-gated and a test written there would compile to nothing.

use super::*;

#[test]
fn an_iovec_is_a_base_and_a_length_at_offsets_zero_and_eight() {
    let mut rec = [0u8; IOVEC_BYTES];
    rec[0..8].copy_from_slice(&0x7fff_dead_0000u64.to_ne_bytes());
    rec[8..16].copy_from_slice(&216u64.to_ne_bytes());
    assert_eq!(parse_iovec(&rec), (0x7fff_dead_0000, 216));
}

#[test]
fn a_read_only_iovec_transfers_before_the_length_writeback_faults() {
    let transferred = core::cell::Cell::new(false);
    let result = regset_iovec(
        || Ok(()), // RANGE-only access_ok accepts this read-only mapping.
        |rec| {
            rec[0..8].copy_from_slice(&0x7000u64.to_ne_bytes());
            rec[8..16].copy_from_slice(&32u64.to_ne_bytes());
            Ok(())
        },
        |base, len| {
            assert_eq!((base, len), (0x7000, 32));
            transferred.set(true);
            Ok(32)
        },
        |_| Err(Errno::Efault),
    );
    assert_eq!(result, Err(Errno::Efault));
    assert!(transferred.get(), "the regset transfer must precede iov_len write-back");
}

#[test]
fn a_copy_out_writes_no_more_than_the_buffer_offered() {
    assert_eq!(copy_len(88, 4096), 88);
    assert_eq!(copy_len(88, 16), 16);
    assert_eq!(copy_len(88, 0), 0);
    assert_eq!(copy_len(0, 4096), 0);
}

#[test]
fn a_trailing_partial_word_is_still_a_chunk() {
    assert_eq!(nr_chunks(0), 0);
    assert_eq!(nr_chunks(8), 1);
    assert_eq!(nr_chunks(9), 2);
    assert_eq!(nr_chunks(216), 27);
    assert_eq!(chunk_len(9, 0), 8);
    assert_eq!(chunk_len(9, 1), 1);
    assert_eq!(chunk_len(4, 0), 4);
}

#[test]
fn a_short_word_keeps_the_bytes_the_tracer_did_not_supply() {
    let word = u64::from_ne_bytes([9, 9, 9, 9, 9, 9, 9, 9]);
    let merged = merge_tail(word, &[1, 2, 3]);
    assert_eq!(merged.to_ne_bytes(), [1, 2, 3, 9, 9, 9, 9, 9]);
    assert_eq!(merge_tail(word, &[]), word);
}

#[test]
fn a_regset_copy_out_is_byte_granular_not_word_granular() {
    // `iov_len` that is not a multiple of 8 must still transfer its remainder;
    // dividing the length by 8 would silently drop the last 4 bytes.
    let regs = [0x0807_0605_0403_0201u64, 0x100f_0e0d_0c0b_0a09];
    let mut seen = std::vec::Vec::new();
    regs_out(&regs, 12, |off, b| { seen.push((off, b.to_vec())); Ok(()) }).unwrap();
    assert_eq!(seen, std::vec![
        (0usize, std::vec![1u8, 2, 3, 4, 5, 6, 7, 8]),
        (8usize, std::vec![9u8, 10, 11, 12]),
    ]);
}

#[test]
fn a_regset_copy_out_of_zero_bytes_touches_nothing() {
    let regs = [1u64, 2];
    let mut calls = 0;
    regs_out(&regs, 0, |_, _| { calls += 1; Ok(()) }).unwrap();
    assert_eq!(calls, 0);
}

#[test]
fn a_regset_copy_out_reports_the_first_fault() {
    let regs = [1u64, 2, 3];
    let mut calls = 0;
    let r = regs_out(&regs, 24, |off, _| {
        calls += 1;
        if off == 8 { Err(Errno::Efault) } else { Ok(()) }
    });
    assert_eq!(r, Err(Errno::Efault));
    assert_eq!(calls, 2, "the transfer stops at the faulting chunk");
}

#[test]
fn a_short_regset_copy_in_leaves_the_untouched_registers_alone() {
    let mut regs = [0xaaaa_aaaa_aaaa_aaaau64; 3];
    regs_in(&mut regs, 12, |off, b| {
        for (i, v) in b.iter_mut().enumerate() { *v = (off + i) as u8; }
        Ok(())
    }).unwrap();
    assert_eq!(regs[0].to_ne_bytes(), [0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(regs[1].to_ne_bytes(), [8, 9, 10, 11, 0xaa, 0xaa, 0xaa, 0xaa]);
    assert_eq!(regs[2], 0xaaaa_aaaa_aaaa_aaaa);
}

#[test]
fn a_regset_copy_in_that_faults_reports_efault() {
    let mut regs = [0u64; 3];
    assert_eq!(regs_in(&mut regs, 24, |_, _| Err(Errno::Efault)), Err(Errno::Efault));
}

#[test]
fn a_sock_filter_is_code_jt_jf_k() {
    let b = sock_filter_bytes(0x0006, 1, 2, 0x7fff_0000);
    assert_eq!(&b[0..2], &0x0006u16.to_ne_bytes());
    assert_eq!(b[2], 1);
    assert_eq!(b[3], 2);
    assert_eq!(&b[4..8], &0x7fff_0000u32.to_ne_bytes());
}

#[test]
fn seccomp_metadata_clamps_to_the_record_and_refuses_a_buffer_too_small_for_filter_off() {
    assert_eq!(metadata_size(4096), Ok(16));
    assert_eq!(metadata_size(16), Ok(16));
    assert_eq!(metadata_size(8), Ok(8));
    assert_eq!(metadata_size(7), Err(Errno::Einval));
    assert_eq!(metadata_size(0), Err(Errno::Einval));
}

#[test]
fn a_seccomp_metadata_record_is_filter_off_then_flags() {
    let b = metadata_rec(3, 0x11);
    assert_eq!(&b[0..8], &3u64.to_ne_bytes());
    assert_eq!(&b[8..16], &0x11u64.to_ne_bytes());
}

#[test]
fn an_rseq_configuration_is_pointer_size_signature_then_zero_flags_and_pad() {
    let b = rseq_rec(0x1000, 32, 0x5309);
    assert_eq!(&b[0..8], &0x1000u64.to_ne_bytes());
    assert_eq!(&b[8..12], &32u32.to_ne_bytes());
    assert_eq!(&b[12..16], &0x5309u32.to_ne_bytes());
    assert_eq!(&b[16..24], &[0u8; 8]);
}

#[test]
fn peeksiginfo_args_are_off_flags_then_a_signed_count() {
    let mut rec = [0u8; 16];
    rec[0..8].copy_from_slice(&7u64.to_ne_bytes());
    rec[8..12].copy_from_slice(&1u32.to_ne_bytes());
    rec[12..16].copy_from_slice(&(-1i32).to_ne_bytes());
    assert_eq!(parse_peeksiginfo_args(&rec), (7, 1, -1));
}

#[test]
fn setsiginfo_reads_signo_at_zero_and_code_at_eight() {
    let mut rec = [0u8; SIGINFO_BYTES];
    rec[0..4].copy_from_slice(&11u32.to_ne_bytes());
    rec[8..12].copy_from_slice(&(-6i32).to_ne_bytes());
    assert_eq!(siginfo_prefix(&rec), (11, -6));
    assert_eq!(SIGINFO_KERNEL_PREFIX, 48);
}
