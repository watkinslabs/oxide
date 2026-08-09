// `IORING_REGISTER_BPF_FILTER`: the import ladder, the payload-size
// negotiation, the record a filter reads, and what a filter set decides —
// including that a filter which cannot run denies rather than allows.

use super::*;
use crate::io_uring_abi::ops::*;
use security::seccomp::insn::{SockFilter, BPF_ABS, BPF_ALU, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD,
                              BPF_RET, BPF_W, BPF_NEG};
use security::seccomp::interp::run_filter_bytes;
use security::seccomp::verifier::{bpf_check_classic, check_cbpf_ctx_filter};

fn ok_reg() -> IouBpf {
    IouBpf {
        cmd_type: IO_URING_BPF_CMD_FILTER, cmd_flags: 0, resv: 0,
        opcode: IORING_OP_NOP as u32, flags: 0, filter_len: 1, pdu_size: 0,
        f_resv: [0; 3], filter_ptr: 0x1000, f_resv2: [0; 5],
    }
}

/// `return k` — the one-instruction program every ladder test needs.
fn ret(k: u32) -> Vec<u64> { alloc::vec![SockFilter::new(BPF_RET | BPF_K, 0, 0, k).encode()] }

/// `A = ctx[off]; if A == want return 1; return 0` — the shape a real policy
/// filter has.
fn allow_if_word_eq(off: u32, want: u32) -> Vec<u64> {
    alloc::vec![
        SockFilter::new(BPF_LD | BPF_W | BPF_ABS, 0, 0, off).encode(),
        SockFilter::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, want).encode(),
        SockFilter::new(BPF_RET | BPF_K, 0, 0, 1).encode(),
        SockFilter::new(BPF_RET | BPF_K, 0, 0, 0).encode(),
    ]
}

// --- wire form -----------------------------------------------------------

#[test]
fn the_wire_sizes_are_the_abi_sizes() {
    assert_eq!(IOU_BPF_BYTES, 72);
    assert_eq!(BPF_FILTER_BYTES, 64);
    assert_eq!(BPF_FILTER_OFF, 8);
    assert_eq!(BPF_CTX_BYTES, 40);
}

#[test]
fn the_registration_record_decodes_from_its_wire_image() {
    let r = IouBpf { pdu_size: PDU_OPEN, opcode: IORING_OP_OPENAT as u32,
                     flags: IO_URING_BPF_FILTER_SZ_STRICT, filter_len: 7,
                     filter_ptr: 0xdead_0000, ..ok_reg() };
    let mut b = [0u8; IOU_BPF_BYTES as usize];
    b[0..2].copy_from_slice(&r.cmd_type.to_le_bytes());
    b[BPF_FILTER_OFF as usize..].copy_from_slice(&r.filter_bytes());
    assert_eq!(IouBpf::from_bytes(&b), r);
}

// --- import ladder -------------------------------------------------------

#[test]
fn a_well_formed_registration_is_admitted() {
    assert_eq!(admit_bpf_reg(&ok_reg()), Ok(()));
}

#[test]
fn only_the_filter_command_is_recognised() {
    for t in [0u16, 2, 9] {
        assert_eq!(admit_bpf_reg(&IouBpf { cmd_type: t, ..ok_reg() }), Err(Errno::Einval), "type {t}");
    }
}

#[test]
fn every_reserved_field_must_be_zero() {
    assert_eq!(admit_bpf_reg(&IouBpf { cmd_flags: 1, ..ok_reg() }), Err(Errno::Einval));
    assert_eq!(admit_bpf_reg(&IouBpf { resv: 1, ..ok_reg() }), Err(Errno::Einval));
    assert_eq!(admit_bpf_reg(&IouBpf { f_resv: [0, 1, 0], ..ok_reg() }), Err(Errno::Einval));
    assert_eq!(admit_bpf_reg(&IouBpf { f_resv2: [0, 0, 3, 0, 0], ..ok_reg() }), Err(Errno::Einval));
}

#[test]
fn an_opcode_past_the_table_is_einval() {
    assert_eq!(admit_bpf_reg(&IouBpf { opcode: OP_LAST as u32, ..ok_reg() }), Err(Errno::Einval));
    assert_eq!(admit_bpf_reg(&IouBpf { opcode: OP_LAST as u32 - 1, ..ok_reg() }), Ok(()));
}

#[test]
fn unknown_filter_flags_are_refused() {
    assert_eq!(admit_bpf_reg(&IouBpf { flags: 1 << 5, ..ok_reg() }), Err(Errno::Einval));
    assert_eq!(admit_bpf_reg(&IouBpf { flags: IO_URING_BPF_FILTER_FLAGS, ..ok_reg() }), Ok(()));
}

#[test]
fn an_empty_or_oversized_program_is_refused() {
    assert_eq!(admit_bpf_reg(&IouBpf { filter_len: 0, ..ok_reg() }), Err(Errno::Einval));
    assert_eq!(admit_bpf_reg(&IouBpf { filter_len: BPF_MAXINSNS + 1, ..ok_reg() }), Err(Errno::Einval));
    assert_eq!(admit_bpf_reg(&IouBpf { filter_len: BPF_MAXINSNS, ..ok_reg() }), Ok(()));
}

// --- payload size --------------------------------------------------------

#[test]
fn this_kernel_supplies_a_payload_for_exactly_the_four_opcodes_that_have_one() {
    assert_eq!(pdu_size_for(IORING_OP_SOCKET as u32), PDU_SOCKET);
    assert_eq!(pdu_size_for(IORING_OP_OPENAT as u32), PDU_OPEN);
    assert_eq!(pdu_size_for(IORING_OP_OPENAT2 as u32), PDU_OPEN);
    assert_eq!(pdu_size_for(IORING_OP_CONNECT as u32), PDU_CONNECT);
    for op in [IORING_OP_NOP, IORING_OP_READ, IORING_OP_ACCEPT, IORING_OP_SEND] {
        assert_eq!(pdu_size_for(op as u32), 0, "op {op}");
    }
    // Every payload must fit the record it lives in.
    for op in 0..OP_LAST as u32 {
        assert!(CTX_PDU + pdu_size_for(op) as usize <= BPF_CTX_BYTES as usize, "op {op}");
    }
}

#[test]
fn agreeing_on_the_payload_size_is_always_accepted() {
    for flags in [0, IO_URING_BPF_FILTER_SZ_STRICT] {
        assert_eq!(admit_pdu_size(PDU_OPEN, PDU_OPEN, flags), Ok(()));
    }
}

#[test]
fn a_caller_expecting_more_than_this_kernel_supplies_is_refused() {
    // It would be reading fields that do not exist.
    assert_eq!(admit_pdu_size(PDU_OPEN, PDU_SOCKET, 0), Err(Errno::Emsgsize));
    assert_eq!(admit_pdu_size(1, 0, 0), Err(Errno::Emsgsize));
}

#[test]
fn a_caller_expecting_less_is_accepted_unless_it_asked_to_be_strict() {
    assert_eq!(admit_pdu_size(PDU_SOCKET, PDU_OPEN, 0), Ok(()));
    assert_eq!(admit_pdu_size(PDU_SOCKET, PDU_OPEN, IO_URING_BPF_FILTER_SZ_STRICT),
               Err(Errno::Emsgsize));
}

// --- the record ----------------------------------------------------------

#[test]
fn the_record_carries_the_request_header() {
    let b = build_ctx(IORING_OP_NOP, 0x05, 0xfeed_face_dead_beef, &Pdu::None);
    assert_eq!(&b[CTX_USER_DATA..CTX_USER_DATA + 8], &0xfeed_face_dead_beef_u64.to_ne_bytes());
    assert_eq!(b[CTX_OPCODE], IORING_OP_NOP);
    assert_eq!(b[CTX_SQE_FLAGS], 0x05);
    assert_eq!(b[CTX_PDU_SIZE], 0);
    assert!(b[CTX_PDU..].iter().all(|&x| x == 0), "an opcode with no payload shows none");
}

#[test]
fn the_socket_payload_lands_where_a_filter_looks_for_it() {
    let b = build_ctx(IORING_OP_SOCKET, 0, 0, &Pdu::Socket { family: 2, ty: 1, protocol: 6 });
    assert_eq!(b[CTX_PDU_SIZE], PDU_SOCKET);
    use security::seccomp::insn::ctx_word;
    assert_eq!(ctx_word(&b, CTX_PDU as u32), 2);
    assert_eq!(ctx_word(&b, CTX_PDU as u32 + 4), 1);
    assert_eq!(ctx_word(&b, CTX_PDU as u32 + 8), 6);
}

#[test]
fn the_open_payload_lands_where_a_filter_looks_for_it() {
    let b = build_ctx(IORING_OP_OPENAT2, 0, 0, &Pdu::Open { flags: 0o102, mode: 0o644, resolve: 8 });
    assert_eq!(b[CTX_PDU_SIZE], PDU_OPEN);
    assert_eq!(&b[CTX_PDU..CTX_PDU + 8], &0o102u64.to_ne_bytes());
    assert_eq!(&b[CTX_PDU + 8..CTX_PDU + 16], &0o644u64.to_ne_bytes());
    assert_eq!(&b[CTX_PDU + 16..CTX_PDU + 24], &8u64.to_ne_bytes());
}

#[test]
fn the_connect_address_stays_in_network_order() {
    let mut addr = [0u8; 16];
    addr[0..4].copy_from_slice(&[10, 0, 0, 7]);
    let b = build_ctx(IORING_OP_CONNECT, 0, 0, &Pdu::Connect { family: 2, port: 443, addr });
    assert_eq!(b[CTX_PDU_SIZE], PDU_CONNECT);
    // 443 == 0x01bb; big-endian on the wire whatever the host order is.
    assert_eq!(&b[CTX_PDU + 4..CTX_PDU + 6], &[0x01, 0xbb]);
    assert_eq!(&b[CTX_PDU + 8..CTX_PDU + 12], &[10, 0, 0, 7]);
}

#[test]
fn a_record_never_carries_residue_from_the_previous_request() {
    // Same buffer shape, two requests: the second must show none of the first.
    let first = build_ctx(IORING_OP_OPENAT, 0, 1, &Pdu::Open { flags: !0, mode: !0, resolve: !0 });
    assert_ne!(&first[CTX_PDU..], &[0u8; 24][..]);
    let second = build_ctx(IORING_OP_NOP, 0, 2, &Pdu::None);
    assert!(second[CTX_PDU..].iter().all(|&x| x == 0));
    assert_eq!(second[CTX_PDU_SIZE], 0);
}

// --- verification is the seccomp verifier, with this record's length -----

#[test]
fn a_load_past_this_records_end_is_refused_by_the_shared_verifier() {
    let prog = allow_if_word_eq(BPF_CTX_BYTES, 0);
    assert_eq!(bpf_check_classic(&prog), Ok(()), "structurally fine");
    assert_eq!(check_cbpf_ctx_filter(&prog, BPF_CTX_BYTES), Err(Errno::Einval),
        "the offset is outside the record a filter is given");
    // The last word that IS inside passes.
    let ok = allow_if_word_eq(BPF_CTX_BYTES - 4, 0);
    assert_eq!(check_cbpf_ctx_filter(&ok, BPF_CTX_BYTES), Ok(()));
}

#[test]
fn an_unaligned_load_is_refused() {
    let prog = allow_if_word_eq(CTX_PDU as u32 + 1, 0);
    assert_eq!(check_cbpf_ctx_filter(&prog, BPF_CTX_BYTES), Err(Errno::Einval));
}

#[test]
fn the_opcode_whitelist_excludes_what_it_excludes_for_seccomp() {
    // A packet-relative load has no meaning against a fixed record.
    use security::seccomp::insn::{BPF_IND, BPF_B, BPF_LDX, BPF_MEM};
    let prog = alloc::vec![
        SockFilter::new(BPF_LD | BPF_B | BPF_IND, 0, 0, 0).encode(),
        SockFilter::new(BPF_RET | BPF_K, 0, 0, 1).encode(),
    ];
    assert_eq!(check_cbpf_ctx_filter(&prog, BPF_CTX_BYTES), Err(Errno::Einval));
    // A scratch load is fine structurally (liveness is the classic check's job).
    let ok = alloc::vec![
        SockFilter::new(BPF_LDX | BPF_MEM, 0, 0, 0).encode(),
        SockFilter::new(BPF_RET | BPF_K, 0, 0, 1).encode(),
    ];
    assert_eq!(check_cbpf_ctx_filter(&ok, BPF_CTX_BYTES), Ok(()));
}

// --- running -------------------------------------------------------------

#[test]
fn a_filter_reads_the_record_it_was_given() {
    // Allow SOCKET only for AF_INET (2).
    let prog = allow_if_word_eq(CTX_PDU as u32, 2);
    assert_eq!(bpf_check_classic(&prog), Ok(()));
    assert_eq!(check_cbpf_ctx_filter(&prog, BPF_CTX_BYTES), Ok(()));

    let inet = build_ctx(IORING_OP_SOCKET, 0, 0, &Pdu::Socket { family: 2, ty: 1, protocol: 0 });
    assert!(filter_allows(run_filter_bytes(&prog, &inet)));

    let unix = build_ctx(IORING_OP_SOCKET, 0, 0, &Pdu::Socket { family: 1, ty: 1, protocol: 0 });
    assert!(!filter_allows(run_filter_bytes(&prog, &unix)));
}

#[test]
fn the_record_length_is_what_bpf_len_reports() {
    use security::seccomp::insn::{BPF_LEN, BPF_A, BPF_RVAL_MASK};
    let _ = BPF_RVAL_MASK;
    let prog = alloc::vec![
        SockFilter::new(BPF_LD | BPF_W | BPF_LEN, 0, 0, 0).encode(),
        SockFilter::new(BPF_RET | BPF_A, 0, 0, 0).encode(),
    ];
    let ctx = build_ctx(IORING_OP_NOP, 0, 0, &Pdu::None);
    assert_eq!(run_filter_bytes(&prog, &ctx), Some(BPF_CTX_BYTES));
}

#[test]
fn a_filter_that_cannot_run_denies_rather_than_allows() {
    // An opcode the interpreter refuses: it returns "no answer", and no answer
    // must never read as permission.
    let prog = alloc::vec![
        SockFilter::new(BPF_ALU | BPF_NEG | 0x40, 0, 0, 0).encode(),
        SockFilter::new(BPF_RET | BPF_K, 0, 0, 1).encode(),
    ];
    let ctx = build_ctx(IORING_OP_NOP, 0, 0, &Pdu::None);
    assert_eq!(run_filter_bytes(&prog, &ctx), None);
    assert!(!filter_allows(None), "an unrunnable filter denies");
}

#[test]
fn zero_denies_and_anything_else_allows() {
    assert!(!filter_allows(Some(0)));
    assert!(filter_allows(Some(1)));
    assert!(filter_allows(Some(u32::MAX)));
}

// --- the installed set ---------------------------------------------------

fn verdict_is_allow(s: &FilterSet, op: u8) -> bool { matches!(s.verdict(op), Verdict::Allow) }
fn verdict_is_deny(s: &FilterSet, op: u8) -> bool { matches!(s.verdict(op), Verdict::Deny) }

#[test]
fn an_empty_set_allows_everything_and_costs_nothing_to_ask() {
    let s = FilterSet::new();
    assert!(!s.active());
    for op in 0..OP_LAST { assert!(verdict_is_allow(&s, op), "op {op}"); }
}

#[test]
fn a_filter_applies_to_its_own_opcode_only() {
    let mut s = FilterSet::new();
    s.install(IORING_OP_SOCKET as u32, Arc::new(ret(1)), false);
    assert!(s.active());
    assert!(matches!(s.verdict(IORING_OP_SOCKET), Verdict::Run(p) if p.len() == 1));
    assert!(verdict_is_allow(&s, IORING_OP_CONNECT));
}

#[test]
fn filters_stack_newest_first_rather_than_replacing() {
    let mut s = FilterSet::new();
    let old = Arc::new(ret(1));
    let new = Arc::new(ret(0));
    s.install(IORING_OP_OPENAT as u32, Arc::clone(&old), false);
    s.install(IORING_OP_OPENAT as u32, Arc::clone(&new), false);
    let Verdict::Run(progs) = s.verdict(IORING_OP_OPENAT) else { panic!("expected programs") };
    assert_eq!(progs.len(), 2, "the second registration must not have replaced the first");
    assert!(Arc::ptr_eq(&progs[0], &new), "newest runs first");
    assert!(Arc::ptr_eq(&progs[1], &old));
}

#[test]
fn deny_rest_turns_the_set_into_a_default_deny_policy() {
    let mut s = FilterSet::new();
    s.install(IORING_OP_SOCKET as u32, Arc::new(ret(1)), true);
    assert!(matches!(s.verdict(IORING_OP_SOCKET), Verdict::Run(_)),
        "the opcode being registered keeps its filter");
    for op in 0..OP_LAST {
        if op == IORING_OP_SOCKET { continue; }
        assert!(verdict_is_deny(&s, op), "op {op} must be denied");
    }
}

#[test]
fn deny_rest_leaves_opcodes_that_already_have_a_filter_alone() {
    let mut s = FilterSet::new();
    s.install(IORING_OP_CONNECT as u32, Arc::new(ret(1)), false);
    s.install(IORING_OP_SOCKET as u32, Arc::new(ret(1)), true);
    assert!(matches!(s.verdict(IORING_OP_CONNECT), Verdict::Run(_)),
        "an opcode the caller already reasoned about keeps its own rule");
    assert!(verdict_is_deny(&s, IORING_OP_NOP));
}

#[test]
fn a_filter_registered_after_deny_rest_still_cannot_open_the_opcode() {
    // The marker sits at the tail of the chain, so the opcode stays denied
    // however many filters are stacked in front of it.
    let mut s = FilterSet::new();
    s.install(IORING_OP_SOCKET as u32, Arc::new(ret(1)), true);
    assert!(verdict_is_deny(&s, IORING_OP_NOP));
    s.install(IORING_OP_NOP as u32, Arc::new(ret(1)), false);
    assert!(verdict_is_deny(&s, IORING_OP_NOP),
        "a later filter must not undo a deny marker");
}

#[test]
fn the_register_ladder_bounds_the_filter_opcode_on_both_forms() {
    use crate::io_uring_abi::register_op::*;
    assert_eq!(decode(IORING_REGISTER_BPF_FILTER, 3, 0x1000, 1).map(|r| r.op),
               Ok(RegisterOp::BpfFilter { arg: 0x1000 }));
    assert_eq!(decode(IORING_REGISTER_BPF_FILTER, 3, 0x1000, 0).err(), Some(Errno::Einval));
    assert_eq!(decode(IORING_REGISTER_BPF_FILTER, 3, 0x1000, 2).err(), Some(Errno::Einval));
    // The blind form takes no ring: a task installs the filter on itself, and
    // its argument count travels with the request because the permission check
    // must be decided first.
    assert_eq!(decode(IORING_REGISTER_BPF_FILTER, -1, 0x1000, 3).map(|r| r.op),
               Ok(RegisterOp::BpfFilterTask { arg: 0x1000, nr: 3 }));
}
