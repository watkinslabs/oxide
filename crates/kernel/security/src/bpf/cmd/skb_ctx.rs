// The `struct __sk_buff` a `BPF_PROG_TEST_RUN` caller may supply and read
// back.
//
// Only some of the context's fields are the caller's to set: the rest are
// derived from the frame, and a caller that writes one is asking for a
// state the kernel would have to invent. Those fields must therefore
// arrive zeroed, and the zero ranges below are the whole rule — a field
// added to the middle of one of them becomes settable by accident, so
// each range is pinned by an offset the tests re-derive.

use syscall::errno::Errno;

use crate::bpf_verify::context::sk_buff;

/// `sizeof(struct __sk_buff)`.
pub(crate) const SIZE: usize = sk_buff::SIZE;

/// `GSO_MAX_SEGS`.
const GSO_MAX_SEGS: u32 = 65535;
/// `GSO_LEGACY_MAX_SIZE`.
const GSO_LEGACY_MAX_SIZE: u32 = 65536;

/// The device a test-run frame is attributed to. The reference uses the
/// network namespace's loopback device, whose index is 1.
pub(crate) const LOOPBACK_IFINDEX: u32 = 1;

/// Byte ranges of the context a caller must leave zeroed, in offset
/// order. Everything outside them is either settable or, in the case of
/// `data_end`, checked separately.
const MUST_BE_ZERO: [(usize, usize); 7] = [
    (0, sk_buff::MARK),
    (sk_buff::MARK + sk_buff::WORD, sk_buff::PRIORITY),
    (sk_buff::IFINDEX + sk_buff::WORD, sk_buff::CB),
    (sk_buff::CB_END, sk_buff::DATA_END),
    (sk_buff::DATA_END + sk_buff::WORD, sk_buff::TSTAMP),
    (sk_buff::GSO_SEGS + sk_buff::WORD, sk_buff::GSO_SIZE),
    (sk_buff::GSO_SIZE + sk_buff::WORD, sk_buff::HWTSTAMP),
];

fn word(ctx: &[u8; SIZE], at: usize) -> u32 {
    u32::from_ne_bytes(ctx[at..at + sk_buff::WORD].try_into().unwrap())
}

fn put_word(ctx: &mut [u8; SIZE], at: usize, value: u32) {
    ctx[at..at + sk_buff::WORD].copy_from_slice(&value.to_ne_bytes());
}

/// Pointer-shaped fields the caller may never set: the kernel owns where
/// the frame lives. `data_end` is the one exception — it selects how much
/// of the input is linear — and is bounded by the input itself.
/// # C: O(1)
pub(crate) fn pointer_verdict(ctx: &[u8; SIZE], data_size_in: u32) -> Result<(), Errno> {
    if word(ctx, sk_buff::DATA_END) > data_size_in { return Err(Errno::Einval); }
    if word(ctx, sk_buff::DATA) != 0 { return Err(Errno::Einval); }
    if word(ctx, sk_buff::DATA_META) != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Every derived field must arrive zeroed. # C: O(SIZE)
pub(crate) fn zero_verdict(ctx: &[u8; SIZE]) -> Result<(), Errno> {
    for (from, to) in MUST_BE_ZERO {
        if ctx[from..to].iter().any(|byte| *byte != 0) { return Err(Errno::Einval); }
    }
    Ok(())
}

/// `wire_len` describes the frame as it was on the wire, so it may not be
/// shorter than the bytes actually present, and `gso_segs` is bounded by
/// what a segmented frame can carry. A zero `wire_len` means "as long as
/// the frame". Returns the resulting `wire_len`. # C: O(1)
pub(crate) fn size_verdict(ctx: &[u8; SIZE], skb_len: u32) -> Result<u32, Errno> {
    let wire_len = word(ctx, sk_buff::WIRE_LEN);
    let wire_len = if wire_len == 0 {
        skb_len
    } else {
        if wire_len < skb_len || wire_len > GSO_LEGACY_MAX_SIZE { return Err(Errno::Einval); }
        wire_len
    };
    if word(ctx, sk_buff::GSO_SEGS) > GSO_MAX_SEGS { return Err(Errno::Einval); }
    Ok(wire_len)
}

/// The whole inbound conversion, in the order the reference applies it:
/// pointer fields, then the derived-field zero ranges, then the sizes.
/// Returns the `wire_len` the frame runs with. # C: O(SIZE)
pub(crate) fn convert_in(ctx: &[u8; SIZE], data_size_in: u32, skb_len: u32) -> Result<u32, Errno> {
    pointer_verdict(ctx, data_size_in)?;
    zero_verdict(ctx)?;
    size_verdict(ctx, skb_len)
}

/// Fill the context the program actually reads: the caller's settable
/// fields, plus the frame's own length and device. # C: O(1)
pub(crate) fn program_context(ctx: &[u8; SIZE], skb_len: u32) -> [u8; SIZE] {
    let mut run = *ctx;
    put_word(&mut run, sk_buff::LEN, skb_len);
    put_word(&mut run, sk_buff::IFINDEX, LOOPBACK_IFINDEX);
    run
}

/// Update the caller's context from the frame after the run. The fields
/// the program could not set are the ones that change here.
/// # C: O(1)
pub(crate) fn convert_out(ctx: &mut [u8; SIZE], run: &[u8; SIZE], skb_len: u32, wire_len: u32) {
    ctx[sk_buff::MARK..sk_buff::MARK + sk_buff::WORD]
        .copy_from_slice(&run[sk_buff::MARK..sk_buff::MARK + sk_buff::WORD]);
    ctx[sk_buff::PRIORITY..sk_buff::PRIORITY + sk_buff::WORD]
        .copy_from_slice(&run[sk_buff::PRIORITY..sk_buff::PRIORITY + sk_buff::WORD]);
    ctx[sk_buff::CB..sk_buff::CB_END].copy_from_slice(&run[sk_buff::CB..sk_buff::CB_END]);
    ctx[sk_buff::TSTAMP..sk_buff::TSTAMP + sk_buff::WIDE]
        .copy_from_slice(&run[sk_buff::TSTAMP..sk_buff::TSTAMP + sk_buff::WIDE]);
    let _ = skb_len;
    put_word(ctx, sk_buff::IFINDEX, LOOPBACK_IFINDEX);
    put_word(ctx, sk_buff::WIRE_LEN, wire_len);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> [u8; SIZE] { [0u8; SIZE] }

    /// The context this kernel converts is exactly the one the verifier
    /// admits field accesses against — one layout, not two.
    #[test]
    fn the_context_is_the_verifier_sk_buff_layout() {
        assert_eq!(SIZE, 192);
        assert_eq!(sk_buff::MARK, 8);
        assert_eq!(sk_buff::PRIORITY, 32);
        assert_eq!(sk_buff::IFINDEX, 40);
        assert_eq!(sk_buff::CB, 48);
        assert_eq!(sk_buff::CB_END, 68);
        assert_eq!(sk_buff::DATA, 76);
        assert_eq!(sk_buff::DATA_END, 80);
        assert_eq!(sk_buff::DATA_META, 140);
        assert_eq!(sk_buff::TSTAMP, 152);
        assert_eq!(sk_buff::WIRE_LEN, 160);
        assert_eq!(sk_buff::GSO_SEGS, 164);
        assert_eq!(sk_buff::GSO_SIZE, 176);
        assert_eq!(sk_buff::HWTSTAMP, 184);
    }

    /// The settable fields are exactly the gaps between the zero ranges,
    /// so a byte in any gap is accepted and a byte in any range is not.
    #[test]
    fn only_the_settable_fields_may_be_nonzero() {
        let settable = [
            sk_buff::MARK, sk_buff::PRIORITY, sk_buff::INGRESS_IFINDEX,
            sk_buff::IFINDEX, sk_buff::CB, sk_buff::CB + 16, sk_buff::DATA_END,
            sk_buff::TSTAMP, sk_buff::WIRE_LEN, sk_buff::GSO_SEGS,
            sk_buff::GSO_SIZE, sk_buff::HWTSTAMP,
        ];
        for at in settable {
            let mut c = ctx();
            c[at] = 1;
            assert_eq!(zero_verdict(&c), Ok(()), "offset {at} should be settable");
        }
        let derived = [
            sk_buff::LEN, sk_buff::PKT_TYPE, sk_buff::QUEUE_MAPPING,
            sk_buff::PROTOCOL, sk_buff::VLAN_TCI, sk_buff::TC_INDEX,
            sk_buff::HASH, sk_buff::TC_CLASSID, sk_buff::DATA,
            sk_buff::NAPI_ID, sk_buff::FAMILY, sk_buff::LOCAL_PORT,
            sk_buff::DATA_META, sk_buff::FLOW_KEYS, sk_buff::SK,
            sk_buff::TSTAMP_TYPE, sk_buff::PADDING,
        ];
        for at in derived {
            let mut c = ctx();
            c[at] = 1;
            assert_eq!(zero_verdict(&c), Err(Errno::Einval), "offset {at} must be zero");
        }
    }

    #[test]
    fn data_end_is_bounded_by_the_input_and_the_pointers_must_be_null() {
        let mut c = ctx();
        put_word(&mut c, sk_buff::DATA_END, 100);
        assert_eq!(pointer_verdict(&c, 100), Ok(()));
        assert_eq!(pointer_verdict(&c, 99), Err(Errno::Einval));
        let mut c = ctx();
        put_word(&mut c, sk_buff::DATA, 1);
        assert_eq!(pointer_verdict(&c, 100), Err(Errno::Einval));
        let mut c = ctx();
        put_word(&mut c, sk_buff::DATA_META, 1);
        assert_eq!(pointer_verdict(&c, 100), Err(Errno::Einval));
    }

    #[test]
    fn wire_len_may_not_be_shorter_than_the_frame_or_larger_than_a_gso_frame() {
        let mut c = ctx();
        assert_eq!(size_verdict(&c, 64), Ok(64));
        put_word(&mut c, sk_buff::WIRE_LEN, 63);
        assert_eq!(size_verdict(&c, 64), Err(Errno::Einval));
        put_word(&mut c, sk_buff::WIRE_LEN, 64);
        assert_eq!(size_verdict(&c, 64), Ok(64));
        put_word(&mut c, sk_buff::WIRE_LEN, GSO_LEGACY_MAX_SIZE);
        assert_eq!(size_verdict(&c, 64), Ok(GSO_LEGACY_MAX_SIZE));
        put_word(&mut c, sk_buff::WIRE_LEN, GSO_LEGACY_MAX_SIZE + 1);
        assert_eq!(size_verdict(&c, 64), Err(Errno::Einval));
    }

    #[test]
    fn gso_segs_is_bounded() {
        let mut c = ctx();
        put_word(&mut c, sk_buff::GSO_SEGS, GSO_MAX_SEGS);
        assert_eq!(size_verdict(&c, 0), Ok(0));
        put_word(&mut c, sk_buff::GSO_SEGS, GSO_MAX_SEGS + 1);
        assert_eq!(size_verdict(&c, 0), Err(Errno::Einval));
    }

    /// The pointer check runs before the zero ranges: a context that
    /// violates both reports the pointer verdict.
    #[test]
    fn the_pointer_check_precedes_the_zero_ranges() {
        let mut c = ctx();
        put_word(&mut c, sk_buff::DATA_END, 200);
        c[sk_buff::LEN] = 1;
        assert_eq!(convert_in(&c, 100, 100), Err(Errno::Einval));
        assert_eq!(pointer_verdict(&c, 100), Err(Errno::Einval));
    }

    /// The program sees the frame's real length and device, whatever the
    /// caller left in those fields' neighbours.
    #[test]
    fn the_program_context_carries_the_frame_length_and_device() {
        let mut c = ctx();
        put_word(&mut c, sk_buff::MARK, 7);
        let run = program_context(&c, 128);
        assert_eq!(word(&run, sk_buff::LEN), 128);
        assert_eq!(word(&run, sk_buff::IFINDEX), LOOPBACK_IFINDEX);
        assert_eq!(word(&run, sk_buff::MARK), 7);
    }

    /// What the program wrote comes back; what it could not set is
    /// replaced by the frame's own values.
    #[test]
    fn the_outbound_context_reports_what_the_program_changed() {
        let mut caller = ctx();
        let mut run = ctx();
        put_word(&mut run, sk_buff::MARK, 9);
        put_word(&mut run, sk_buff::PRIORITY, 11);
        run[sk_buff::CB] = 0xAB;
        put_word(&mut run, sk_buff::TSTAMP, 5);
        convert_out(&mut caller, &run, 128, 256);
        assert_eq!(word(&caller, sk_buff::MARK), 9);
        assert_eq!(word(&caller, sk_buff::PRIORITY), 11);
        assert_eq!(caller[sk_buff::CB], 0xAB);
        assert_eq!(word(&caller, sk_buff::TSTAMP), 5);
        assert_eq!(word(&caller, sk_buff::IFINDEX), LOOPBACK_IFINDEX);
        assert_eq!(word(&caller, sk_buff::WIRE_LEN), 256);
    }
}
