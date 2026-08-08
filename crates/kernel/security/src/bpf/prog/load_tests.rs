use alloc::vec::Vec;
use core::cell::Cell;

use syscall::errno::Errno;

use super::{gpl_compatible, load_check_attach_then, verify};
use super::super::attr::ProgLoad;
use super::super::uapi;

/// A load request naming nothing beyond its type and attach direction.
fn request(prog_type: u32, expected_attach_type: u32, attach_btf_id: u32) -> ProgLoad {
    ProgLoad {
        prog_type, expected_attach_type, attach_btf_id,
        insn_cnt: 1, insns: 0, license: 0, attach_btf_obj_fd: 0,
    }
}

#[test]
fn invalid_expected_attach_type_precedes_bad_user_pointer() {
    let copied = Cell::new(false);
    let result = load_check_attach_then(
        &request(uapi::prog_type::CGROUP_SKB, uapi::attach_type::MAX, 0),
        || {
            copied.set(true);
            Err::<(), _>(Errno::Efault)
        },
    );
    assert_eq!(result, Err(Errno::Einval));
    assert!(!copied.get(), "instruction and license copies must not run");
}

#[test]
fn invalid_attach_target_precedes_bad_user_pointer() {
    for request in [
        // A type id no object could declare.
        request(uapi::prog_type::LSM, uapi::attach_type::LSM_MAC, u32::MAX),
        // A type id named by a program type that attaches to no target.
        request(uapi::prog_type::SOCKET_FILTER, 0, 1),
    ] {
        let copied = Cell::new(false);
        let result = load_check_attach_then(&request, || {
            copied.set(true);
            Err::<(), _>(Errno::Efault)
        });
        assert_eq!(result, Err(Errno::Einval));
        assert!(!copied.get(), "instruction and license copies must not run");
    }
}

#[test]
fn a_program_naming_no_attach_target_reaches_the_user_copy() {
    // Control for the two cases above: the same call must reach `next`
    // when nothing about the attach contract is wrong, so the assertions
    // there are about the ladder and not about the closure never running.
    for request in [
        request(uapi::prog_type::SOCKET_FILTER, 0, 0),
        request(uapi::prog_type::LSM, uapi::attach_type::LSM_MAC, 1),
    ] {
        let copied = Cell::new(false);
        let result = load_check_attach_then(&request, || {
            copied.set(true);
            Err::<(), _>(Errno::Efault)
        });
        assert_eq!(result, Err(Errno::Efault));
        assert!(copied.get());
    }
}

fn returns(value: i32) -> Vec<u8> {
    let mut insns = Vec::new();
    insns.extend_from_slice(&[0xb7, 0, 0, 0]);
    insns.extend_from_slice(&value.to_le_bytes());
    insns.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
    insns
}

/// Type id of the `file_open` hook stub in the kernel's own type
/// information, which is what an LSM program names as its attach target.
const FILE_OPEN_BTF_ID: u32 = 5;
const GPL: bool = true;

#[test]
fn load_carries_verifier_egress_attach_contract() {
    let egress = request(
        uapi::prog_type::CGROUP_SKB, uapi::attach_type::CGROUP_INET_EGRESS, 0,
    );
    let ingress = request(
        uapi::prog_type::CGROUP_SKB, uapi::attach_type::CGROUP_INET_INGRESS, 0,
    );
    assert_eq!(verify(&egress, GPL, &returns(2), &[]), Ok(true));
    assert_eq!(verify(&egress, GPL, &returns(1), &[]), Ok(false));
    assert_eq!(verify(&ingress, GPL, &returns(1), &[]), Ok(false));
}

#[test]
fn an_lsm_program_verifies_against_the_hook_it_named() {
    let p = request(uapi::prog_type::LSM, uapi::attach_type::LSM_MAC, FILE_OPEN_BTF_ID);
    assert_eq!(verify(&p, GPL, &returns(0), &[]), Ok(false));
    assert_eq!(verify(&p, GPL, &returns(-13), &[]), Ok(false));
    // The hook's return contract, not the program type's, decides.
    assert_eq!(verify(&p, GPL, &returns(1), &[]), Err(Errno::Einval));
}

#[test]
fn an_lsm_program_under_other_terms_is_refused() {
    let p = request(uapi::prog_type::LSM, uapi::attach_type::LSM_MAC, FILE_OPEN_BTF_ID);
    assert_eq!(verify(&p, false, &returns(0), &[]), Err(Errno::Einval));
}

#[test]
fn an_lsm_program_naming_no_hook_stub_is_refused() {
    // Every type id in the published object that is not a hook stub, plus
    // "named no target at all".
    for attach_btf_id in [0, 1, 2, 3, 4, FILE_OPEN_BTF_ID + 1] {
        let p = request(uapi::prog_type::LSM, uapi::attach_type::LSM_MAC, attach_btf_id);
        assert_eq!(verify(&p, GPL, &returns(0), &[]), Err(Errno::Einval),
            "attach target {attach_btf_id} was admitted");
    }
}

#[test]
fn an_lsm_program_attaching_anywhere_but_a_hook_is_refused() {
    for expected_attach_type in [0, uapi::attach_type::CGROUP_INET_INGRESS, uapi::attach_type::MAX] {
        let p = request(uapi::prog_type::LSM, expected_attach_type, FILE_OPEN_BTF_ID);
        assert_eq!(verify(&p, GPL, &returns(0), &[]), Err(Errno::Einval),
            "attach type {expected_attach_type} was admitted");
    }
}

#[test]
fn the_kernels_own_terms_are_the_ones_a_hook_accepts() {
    for license in [&b"GPL"[..], b"GPL v2", b"GPL and additional rights",
        b"Dual BSD/GPL", b"Dual MIT/GPL", b"Dual MPL/GPL"] {
        assert!(gpl_compatible(license), "{license:?}");
    }
    for license in [&b""[..], b"BSD", b"MIT", b"Proprietary", b"gpl", b"GPL v3",
        b"GPLv2", b"Dual BSD/GPL ", b"GPL\0"] {
        assert!(!gpl_compatible(license), "{license:?}");
    }
}

#[test]
fn an_access_the_context_does_not_admit_is_a_refusal_not_a_malformed_program() {
    // `r2 = *(u64 *)(r1 + 16)` — past the last slot a one-argument hook
    // publishes. The program is well formed, so the answer is EACCES.
    let mut insns = alloc::vec![0x79, 0x12, 16, 0, 0, 0, 0, 0];
    insns.extend_from_slice(&returns(0));
    let p = request(uapi::prog_type::LSM, uapi::attach_type::LSM_MAC, FILE_OPEN_BTF_ID);
    assert_eq!(verify(&p, GPL, &insns, &[]), Err(Errno::Eacces));
    // A malformed program stays EINVAL: an opcode no runner implements.
    let mut bad = alloc::vec![0x20, 0, 0, 0, 0, 0, 0, 0];
    bad.extend_from_slice(&returns(0));
    assert_eq!(verify(&p, GPL, &bad, &[]), Err(Errno::Einval));
}

/// Type id of `bpf_iter_bpf_prog` in the published object: the hook stubs
/// come first, then one forward declaration, one pointer, the prototype and
/// the stub per iterator argument.
const ITER_BPF_PROG_BTF_ID: u32 = 11;

#[test]
fn an_iterator_program_loads_against_a_published_target() {
    let p = request(
        uapi::prog_type::TRACING, uapi::attach_type::TRACE_ITER, ITER_BPF_PROG_BTF_ID,
    );
    assert_eq!(
        super::super::btf::iter_target_by_btf_id(ITER_BPF_PROG_BTF_ID),
        Some(super::super::IterTarget::BpfProg),
    );
    assert_eq!(verify(&p, GPL, &returns(0), &[]), Ok(false));
    // A step's other answer is equally admitted.
    assert_eq!(verify(&p, GPL, &returns(1), &[]), Ok(false));
}

#[test]
fn an_iterator_program_naming_no_published_target_is_refused() {
    // Reject control for the load above: the same program body, refused
    // because its attach target names nothing this kernel can walk.
    for attach_btf_id in [0, FILE_OPEN_BTF_ID, u32::MAX] {
        let p = request(uapi::prog_type::TRACING, uapi::attach_type::TRACE_ITER, attach_btf_id);
        assert_eq!(verify(&p, GPL, &returns(0), &[]), Err(Errno::Einval),
            "target {attach_btf_id} was admitted");
    }
}

#[test]
fn a_tracing_program_that_is_not_an_iterator_is_refused() {
    // The only tracing attachment this kernel serves is the iterator one.
    for attach_type in [0, uapi::attach_type::LSM_MAC, uapi::attach_type::CGROUP_DEVICE] {
        let p = request(uapi::prog_type::TRACING, attach_type, ITER_BPF_PROG_BTF_ID);
        assert_eq!(verify(&p, GPL, &returns(0), &[]), Err(Errno::Einval),
            "attach type {attach_type} was admitted");
    }
}
