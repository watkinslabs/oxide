// `bpf_check_classic` + `check_load_and_stores` + `seccomp_check_filter`.
// Before B1478 there was NO verifier: a filter went straight from userspace
// into the interpreter, so an out-of-bounds `BPF_LD|BPF_W|BPF_ABS` was a
// kernel-memory read primitive and an uninitialised `M[]` read leaked
// whatever the interpreter's frame held.

use alloc::vec::Vec;
use crate::seccomp::insn::*;
use crate::seccomp::uapi::*;
use crate::seccomp::verifier::*;
use syscall::errno::Errno;

fn p(insns: &[(u16, u8, u8, u32)]) -> Vec<u64> {
    insns.iter().map(|&(c, jt, jf, k)| SockFilter::new(c, jt, jf, k).encode()).collect()
}
const RET_ALLOW: (u16, u8, u8, u32) = (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW);
const LD_NR:     (u16, u8, u8, u32) = (BPF_LD | BPF_W | BPF_ABS, 0, 0, 0);

#[test]
fn a_minimal_well_formed_filter_verifies() {
    assert_eq!(check_seccomp_filter(&p(&[RET_ALLOW])), Ok(()));
    assert_eq!(check_seccomp_filter(&p(&[
        LD_NR,
        (BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 42),
        (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | 1),
        RET_ALLOW,
    ])), Ok(()));
}

#[test]
fn an_empty_or_oversized_program_is_rejected() {
    assert_eq!(check_seccomp_filter(&[]), Err(Errno::Einval));
    let big: Vec<u64> = core::iter::repeat(SockFilter::new(BPF_RET | BPF_K, 0, 0, 0).encode())
        .take(BPF_MAXINSNS + 1).collect();
    assert_eq!(check_seccomp_filter(&big), Err(Errno::Einval));
}

// The read primitive: `seccomp_check_filter` bounds every ABS load to
// `k < sizeof(struct seccomp_data)` AND `k & 3 == 0`.
#[test]
fn an_out_of_bounds_seccomp_data_load_is_rejected() {
    for k in [SECCOMP_DATA_BYTES, SECCOMP_DATA_BYTES + 4, 0x1000, 0xffff_f000, u32::MAX & !3] {
        assert_eq!(check_seccomp_filter(&p(&[(BPF_LD | BPF_W | BPF_ABS, 0, 0, k), RET_ALLOW])),
                   Err(Errno::Einval), "k = {:#x}", k);
    }
    // The last legal offset is args[5]'s high half at 60.
    assert_eq!(check_seccomp_filter(&p(&[(BPF_LD | BPF_W | BPF_ABS, 0, 0, 60), RET_ALLOW])), Ok(()));
}

#[test]
fn an_unaligned_seccomp_data_load_is_rejected() {
    for k in [1u32, 2, 3, 5, 17, 63] {
        assert_eq!(check_seccomp_filter(&p(&[(BPF_LD | BPF_W | BPF_ABS, 0, 0, k), RET_ALLOW])),
                   Err(Errno::Einval), "k = {}", k);
    }
}

#[test]
fn a_program_not_ending_in_ret_is_rejected() {
    assert_eq!(check_seccomp_filter(&p(&[LD_NR])), Err(Errno::Einval));
    assert_eq!(check_seccomp_filter(&p(&[RET_ALLOW, LD_NR])), Err(Errno::Einval));
    // `BPF_RET|BPF_A` is the other legal terminator.
    assert_eq!(check_seccomp_filter(&p(&[(BPF_LD | BPF_IMM, 0, 0, SECCOMP_RET_ALLOW),
                                         (BPF_RET | BPF_A, 0, 0, 0)])), Ok(()));
}

#[test]
fn an_out_of_range_conditional_jump_is_rejected() {
    // jt lands one past the end.
    assert_eq!(check_seccomp_filter(&p(&[
        LD_NR, (BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 1), RET_ALLOW])), Err(Errno::Einval));
    // jf lands one past the end.
    assert_eq!(check_seccomp_filter(&p(&[
        LD_NR, (BPF_JMP | BPF_JEQ | BPF_K, 0, 2, 1), RET_ALLOW])), Err(Errno::Einval));
    assert_eq!(check_seccomp_filter(&p(&[
        LD_NR, (BPF_JMP | BPF_JEQ | BPF_K, 1, 1, 1), RET_ALLOW, RET_ALLOW])), Ok(()));
}

// `if (ftest->k >= (unsigned int)(flen - pc - 1)) return -EINVAL;` — an
// unconditional jump past the end, and (because k is unsigned) any attempt to
// encode a BACKWARD jump, which is how a cBPF program would loop.
#[test]
fn an_out_of_range_unconditional_jump_is_rejected() {
    assert_eq!(check_seccomp_filter(&p(&[(BPF_JMP | BPF_JA, 0, 0, 1), RET_ALLOW])),
               Err(Errno::Einval));
    assert_eq!(check_seccomp_filter(&p(&[(BPF_JMP | BPF_JA, 0, 0, u32::MAX), RET_ALLOW])),
               Err(Errno::Einval));
    assert_eq!(check_seccomp_filter(&p(&[(BPF_JMP | BPF_JA, 0, 0, 0), RET_ALLOW])), Ok(()));
}

#[test]
fn an_out_of_range_scratch_index_is_rejected() {
    for c in [BPF_ST, BPF_STX, BPF_LD | BPF_MEM, BPF_LDX | BPF_MEM] {
        assert_eq!(check_seccomp_filter(&p(&[(c, 0, 0, BPF_MEMWORDS as u32), RET_ALLOW])),
                   Err(Errno::Einval), "code {:#x}", c);
    }
}

// `check_load_and_stores`: reading `M[k]` on a path that never wrote it would
// hand userspace whatever the interpreter's scratch array happened to hold.
#[test]
fn reading_an_uninitialised_scratch_cell_is_rejected() {
    assert_eq!(check_seccomp_filter(&p(&[(BPF_LD | BPF_MEM, 0, 0, 3), RET_ALLOW])),
               Err(Errno::Einval));
    assert_eq!(check_seccomp_filter(&p(&[(BPF_LDX | BPF_MEM, 0, 0, 0), RET_ALLOW])),
               Err(Errno::Einval));
    // Written first: fine.
    assert_eq!(check_seccomp_filter(&p(&[
        LD_NR, (BPF_ST, 0, 0, 3), (BPF_LD | BPF_MEM, 0, 0, 3), RET_ALLOW])), Ok(()));
}

// A cell written only on the taken branch is not live on the fall-through.
#[test]
fn a_scratch_cell_written_on_only_one_branch_is_rejected() {
    assert_eq!(check_seccomp_filter(&p(&[
        LD_NR,
        (BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 42), // not equal -> skip the store
        (BPF_ST, 0, 0, 0),
        (BPF_LD | BPF_MEM, 0, 0, 0),
        RET_ALLOW,
    ])), Err(Errno::Einval));
}

#[test]
fn division_or_modulo_by_a_zero_constant_is_rejected() {
    assert_eq!(check_seccomp_filter(&p(&[LD_NR, (BPF_ALU | BPF_DIV | BPF_K, 0, 0, 0), RET_ALLOW])),
               Err(Errno::Einval));
    assert_eq!(check_seccomp_filter(&p(&[LD_NR, (BPF_ALU | BPF_MOD | BPF_K, 0, 0, 0), RET_ALLOW])),
               Err(Errno::Einval));
    assert_eq!(check_seccomp_filter(&p(&[LD_NR, (BPF_ALU | BPF_DIV | BPF_K, 0, 0, 2), RET_ALLOW])),
               Ok(()));
}

#[test]
fn a_constant_shift_of_thirty_two_or_more_is_rejected() {
    for k in [32u32, 33, 64, u32::MAX] {
        assert_eq!(check_seccomp_filter(&p(&[LD_NR, (BPF_ALU | BPF_LSH | BPF_K, 0, 0, k), RET_ALLOW])),
                   Err(Errno::Einval), "k = {}", k);
        assert_eq!(check_seccomp_filter(&p(&[LD_NR, (BPF_ALU | BPF_RSH | BPF_K, 0, 0, k), RET_ALLOW])),
                   Err(Errno::Einval), "k = {}", k);
    }
    assert_eq!(check_seccomp_filter(&p(&[LD_NR, (BPF_ALU | BPF_LSH | BPF_K, 0, 0, 31), RET_ALLOW])),
               Ok(()));
}

// `seccomp_check_filter`'s whitelist is NARROWER than `chk_code_allowed`:
// BPF_MOD is legal in a socket filter and illegal in a seccomp filter, and no
// packet-relative form survives at all.
#[test]
fn the_seccomp_whitelist_rejects_forms_a_socket_filter_may_use() {
    const BPF_MSH: u16 = 0xa0;
    for c in [BPF_ALU | BPF_MOD | BPF_K, BPF_ALU | BPF_MOD | BPF_X,
              BPF_LD | BPF_B | BPF_ABS, BPF_LD | BPF_H | BPF_ABS,
              BPF_LD | BPF_W | BPF_IND, BPF_LDX | BPF_B | BPF_MSH] {
        let prog = p(&[LD_NR, (c, 0, 0, 4), RET_ALLOW]);
        // `bpf_check_classic` allows them...
        assert_eq!(bpf_check_classic(&prog), Ok(()), "code {:#x}", c);
        // ...and `seccomp_check_filter` does not.
        assert_eq!(seccomp_check_filter(&prog), Err(Errno::Einval), "code {:#x}", c);
        assert_eq!(check_seccomp_filter(&prog), Err(Errno::Einval), "code {:#x}", c);
    }
}

#[test]
fn an_undefined_opcode_is_rejected() {
    for c in [0x0fu16, 0x9c, 0xff, 0x5f] {
        assert_eq!(check_seccomp_filter(&p(&[(c, 0, 0, 0), RET_ALLOW])), Err(Errno::Einval),
                   "code {:#x}", c);
    }
}

// A real libseccomp-shaped preamble: check the arch, then the syscall number.
#[test]
fn a_libseccomp_shaped_preamble_verifies() {
    assert_eq!(check_seccomp_filter(&p(&[
        (BPF_LD | BPF_W | BPF_ABS, 0, 0, 4),                       // arch
        (BPF_JMP | BPF_JEQ | BPF_K, 1, 0, native_audit_arch()),
        (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        (BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),                       // nr
        (BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 60),
        (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),
        (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | 1),
    ])), Ok(()));
}
