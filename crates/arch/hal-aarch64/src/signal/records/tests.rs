// Host tests for the `sigcontext.__reserved` record chain: the exact bytes
// Linux writes, and the exact rejection table `parse_user_sigframe` applies.

use super::*;
// The magics this kernel rejects live in their own module so the whole table
// carries one `dead_code` allow; the rejection test below names each entry.
use super::unsupported_magic::*;

/// A frame base and `__reserved` address that satisfy Linux's 16-alignment
/// precondition; the real ones come from `super::RESERVED_IN_FRAME`.
const FRAME_VA: u64 = 0x7fff_0000_0000;
const RESERVED_VA: u64 = FRAME_VA + 592;

fn put_u64(b: &mut [u8], off: usize, v: u64) { b[off..off + 8].copy_from_slice(&v.to_le_bytes()); }

fn head(b: &mut [u8], off: usize, magic: u32, size: u32) {
    put_u32(b, off, magic);
    put_u32(b, off + 4, size);
}

fn scan(r: &[u8]) -> Result<Scan, ()> { scan_region(r, RESERVED_VA, FRAME_VA, false, false) }

#[test]
fn record_sizes_match_the_linux_uapi() {
    assert_eq!(FPSIMD_CONTEXT_BYTES, 0x210);
    assert_eq!(TERMINATOR_SIZE, 0x10);
    assert_eq!(EXTRA_CONTEXT_SIZE, 0x20);
    assert_eq!(RESERVED_BYTES, 4096);
    assert_eq!(FPSIMD_MAGIC, 0x46508001);
    assert_eq!(FPSIMD_FPSR_OFF, 8);
    assert_eq!(FPSIMD_FPCR_OFF, 12);
    assert_eq!(FPSIMD_VREGS_OFF, 16);
}

/// Linux `preserve_fpsimd_context`: magic, size, then fpsr BEFORE fpcr —
/// the reverse of `struct user_fpsimd_state` (and of our own save area), so a
/// straight memcpy would silently swap the two control words.
#[test]
fn write_chain_emits_a_linux_shaped_fpsimd_record_then_a_terminator() {
    let mut r = [0u8; RESERVED_BYTES];
    let mut q = [0u8; 32 * 16];
    for (i, b) in q.iter_mut().enumerate() { *b = (i as u8) ^ 0x3c; }
    assert!(write_chain(&mut r, &q, 0x0080_0000, 0x1000_0010));

    assert_eq!(get_u32(&r, 0), FPSIMD_MAGIC);
    assert_eq!(get_u32(&r, 4), FPSIMD_CONTEXT_BYTES as u32);
    assert_eq!(get_u32(&r, FPSIMD_FPSR_OFF), 0x1000_0010, "fpsr must precede fpcr");
    assert_eq!(get_u32(&r, FPSIMD_FPCR_OFF), 0x0080_0000);
    assert_eq!(&r[FPSIMD_VREGS_OFF..FPSIMD_VREGS_OFF + 32 * 16], &q[..]);
    // The terminator Linux's parser stops on.
    assert_eq!(get_u32(&r, FPSIMD_CONTEXT_BYTES), 0);
    assert_eq!(get_u32(&r, FPSIMD_CONTEXT_BYTES + 4), 0);
    // ...and the chain the parser then accepts.
    let s = scan(&r).unwrap();
    assert_eq!(s.fpsimd, Some((0, FPSIMD_CONTEXT_BYTES as u32)));
    assert_eq!(s.rebase, None);
    assert_eq!(read_fpsimd(&r, 0, FPSIMD_CONTEXT_BYTES as u32),
               Ok((0x1000_0010, 0x0080_0000, FPSIMD_VREGS_OFF)));
}

/// Linux `init_user_layout`: the cursor stops `TERMINATOR_SIZE +
/// EXTRA_CONTEXT_SIZE` short of the end so an overflow can always be spilled.
/// Our record set fits with room to spare; an oversized one reports `-ENOMEM`
/// rather than truncating the chain.
#[test]
fn the_reserved_allocator_matches_linuxs_limit_arithmetic() {
    let a = ReservedAlloc::new();
    assert_eq!(a.limit, RESERVED_BYTES - TERMINATOR_SIZE - EXTRA_CONTEXT_SIZE);
    let mut a = ReservedAlloc::new();
    assert_eq!(a.alloc(FPSIMD_CONTEXT_BYTES), Some(0));
    assert_eq!(a.alloc_end(), Some(FPSIMD_CONTEXT_BYTES));
    assert_eq!(a.size, FPSIMD_CONTEXT_BYTES + TERMINATOR_SIZE);
    assert!(a.size < RESERVED_BYTES, "the fpsimd chain fits __reserved with room to spare");
    // Sizes are padded to 16, and the ceiling is real.
    let mut a = ReservedAlloc::new();
    assert_eq!(a.alloc(1), Some(0));
    assert_eq!(a.size, 16);
    let mut a = ReservedAlloc::new();
    assert_eq!(a.alloc(RESERVED_BYTES), None, "an overflowing record must report -ENOMEM");
}

/// Linux `parse_user_sigframe` rejects with `-EINVAL` — it never sanitises,
/// and never accepts a partially-understood chain.
#[test]
fn a_malformed_record_chain_is_rejected_the_way_linux_rejects_it() {
    let mut good = [0u8; RESERVED_BYTES];
    assert!(write_chain(&mut good, &[0u8; 32 * 16], 0, 0));
    assert!(scan(&good).is_ok());

    // A record whose size runs past the region.
    let mut r = good; head(&mut r, 0, FPSIMD_MAGIC, (RESERVED_BYTES + 16) as u32);
    assert_eq!(scan(&r), Err(()), "oversized record size accepted");

    // A record size that leaves the cursor misaligned.
    let mut r = good; head(&mut r, 0, ESR_MAGIC, 24);
    assert_eq!(scan(&r), Err(()), "non-16-multiple size accepted");

    // A record smaller than its own head.
    let mut r = good; head(&mut r, 0, ESR_MAGIC, 4);
    assert_eq!(scan(&r), Err(()), "size < sizeof(_aarch64_ctx) accepted");

    // A terminator with a non-zero size.
    let mut r = good; head(&mut r, FPSIMD_CONTEXT_BYTES, 0, 16);
    assert_eq!(scan(&r), Err(()), "terminator with size accepted");

    // Two fpsimd records.
    let mut r = good;
    head(&mut r, FPSIMD_CONTEXT_BYTES, FPSIMD_MAGIC, FPSIMD_CONTEXT_BYTES as u32);
    head(&mut r, 2 * FPSIMD_CONTEXT_BYTES, 0, 0);
    assert_eq!(scan(&r), Err(()), "duplicate fpsimd accepted");

    // An unknown magic.
    let mut r = good; head(&mut r, 0, 0xdead_beef, 16);
    assert_eq!(scan(&r), Err(()), "unknown magic accepted");

    // A `__reserved` base that is not 16-aligned.
    assert_eq!(scan_region(&good, RESERVED_VA + 8, FRAME_VA, false, false), Err(()));

    // No terminator at all — the walk runs out of region.
    let r = [0xffu8; RESERVED_BYTES];
    assert_eq!(scan(&r), Err(()), "unterminated chain accepted");
}

/// This kernel enables neither SVE nor SME for EL0, so Linux's own parser
/// would send each of these magics down `default: goto invalid`. Rejecting
/// them is the CORRECT behaviour for this configuration, not an omission —
/// and accepting an SVE record we cannot restore would be worse.
#[test]
fn sve_and_sme_records_are_rejected_as_they_are_on_a_non_sve_cpu() {
    let mut good = [0u8; RESERVED_BYTES];
    assert!(write_chain(&mut good, &[0u8; 32 * 16], 0, 0));
    for magic in [SVE_MAGIC, ZA_MAGIC, ZT_MAGIC, TPIDR2_MAGIC, FPMR_MAGIC, POE_MAGIC, GCS_MAGIC] {
        let mut r = good;
        head(&mut r, FPSIMD_CONTEXT_BYTES, magic, 16);
        head(&mut r, FPSIMD_CONTEXT_BYTES + 16, 0, 0);
        assert_eq!(scan(&r), Err(()), "magic {magic:#x} accepted without CPU support");
    }
    // `ESR_MAGIC` is the one Linux ignores rather than rejects.
    let mut r = good;
    head(&mut r, FPSIMD_CONTEXT_BYTES, ESR_MAGIC, 16);
    head(&mut r, FPSIMD_CONTEXT_BYTES + 16, 0, 0);
    assert!(scan(&r).is_ok(), "esr_context must be ignored, not rejected");
}

/// `extra_context` re-bases the walk into a spill area. A process (or CRIU
/// restoring a checkpoint) may hand us one, so the parser implements the full
/// rule set even though this kernel's own record set never overflows.
#[test]
fn extra_context_rebases_only_under_the_full_linux_rule_set() {
    // fpsimd, then extra_context, then the MANDATORY terminator right after.
    let ex = FPSIMD_CONTEXT_BYTES;
    let datap = RESERVED_VA + (ex + EXTRA_CONTEXT_SIZE + TERMINATOR_SIZE) as u64;
    let build = |datap: u64, size: u32, ecsize: u32, term: (u32, u32)| {
        let mut r = [0u8; RESERVED_BYTES];
        assert!(write_chain(&mut r, &[0u8; 32 * 16], 0, 0));
        head(&mut r, ex, EXTRA_MAGIC, ecsize);
        put_u64(&mut r, ex + CTX_HEAD_BYTES, datap);
        put_u32(&mut r, ex + CTX_HEAD_BYTES + 8, size);
        head(&mut r, ex + ecsize as usize, term.0, term.1);
        r
    };
    let r = build(datap, 64, EXTRA_CONTEXT_SIZE as u32, (0, 0));
    assert_eq!(scan(&r).unwrap().rebase, Some((datap, 64)));

    // `datap` must be EXACTLY past the terminator — that is what makes
    // extra_context the last record and stops it aiming anywhere else.
    let r = build(datap + 16, 64, EXTRA_CONTEXT_SIZE as u32, (0, 0));
    assert_eq!(scan(&r), Err(()), "datap away from the terminator accepted");
    let r = build(datap - 16, 64, EXTRA_CONTEXT_SIZE as u32, (0, 0));
    assert_eq!(scan(&r), Err(()));

    // Misaligned `datap`, non-16-multiple size, undersized record.
    let r = build(datap + 8, 64, EXTRA_CONTEXT_SIZE as u32, (0, 0));
    assert_eq!(scan(&r), Err(()), "unaligned datap accepted");
    let r = build(datap, 60, EXTRA_CONTEXT_SIZE as u32, (0, 0));
    assert_eq!(scan(&r), Err(()), "non-16-multiple extra size accepted");
    let r = build(datap, 64, 16, (0, 0));
    assert_eq!(scan(&r), Err(()), "extra_context smaller than its own struct accepted");

    // The record after extra_context MUST be `{0, 0}`.
    let r = build(datap, 64, EXTRA_CONTEXT_SIZE as u32, (ESR_MAGIC, 16));
    assert_eq!(scan(&r), Err(()), "missing post-extra terminator accepted");

    // "Reject unreasonably large frames".
    let r = build(datap, (SIGFRAME_MAXSZ as u32) + 16, EXTRA_CONTEXT_SIZE as u32, (0, 0));
    assert_eq!(scan(&r), Err(()), "extra area past SIGFRAME_MAXSZ accepted");

    // Only ONE extra_context — a second must not re-base and loop.
    let r = build(datap, 64, EXTRA_CONTEXT_SIZE as u32, (0, 0));
    assert_eq!(scan_region(&r, RESERVED_VA, FRAME_VA, false, true), Err(()),
               "a second extra_context accepted");
}

/// Linux `read_fpsimd_context`: `if (user->fpsimd_size != sizeof(struct
/// fpsimd_context)) return -EINVAL` — an EXACT size, not a lower bound.
#[test]
fn a_truncated_or_oversized_fpsimd_record_is_rejected() {
    let mut r = [0u8; RESERVED_BYTES];
    assert!(write_chain(&mut r, &[0u8; 32 * 16], 0, 0));
    assert!(read_fpsimd(&r, 0, FPSIMD_CONTEXT_BYTES as u32).is_ok());
    assert_eq!(read_fpsimd(&r, 0, (FPSIMD_CONTEXT_BYTES - 16) as u32), Err(()));
    assert_eq!(read_fpsimd(&r, 0, (FPSIMD_CONTEXT_BYTES + 16) as u32), Err(()));
    // A record whose payload would run off the end of the region.
    assert_eq!(read_fpsimd(&r, RESERVED_BYTES - 16, FPSIMD_CONTEXT_BYTES as u32), Err(()));
}

/// A chain with NO fpsimd record parses fine but carries nothing — the caller
/// turns that into Linux's `if (!user.fpsimd) return -EINVAL`.
#[test]
fn a_chain_without_an_fpsimd_record_yields_no_record() {
    let mut r = [0u8; RESERVED_BYTES];
    head(&mut r, 0, 0, 0);   // bare terminator: the frame we used to build
    assert_eq!(scan(&r).unwrap().fpsimd, None);
}
