// Classification contract for the `prctl` options added alongside the
// syscall-user-dispatch / IO-flusher / auxv / timer-id / futex-hash /
// rseq-slice work, plus the options this port deliberately refuses.
//
// Split from `decide/tests.rs` to keep both files under the size cap.

use super::super::sud;
use super::super::timer_ids::RestoreIds;
use super::super::uapi::*;
use super::{classify, Op};
use syscall::errno::Errno;

#[test]
fn io_flusher_carries_its_raw_arguments_to_the_permission_check() {
    // No argument rule runs in `classify`: CAP_SYS_RESOURCE is tested first,
    // so even a malformed call must reach the owner intact.
    assert_eq!(classify(PR_SET_IO_FLUSHER, 9, 8, 7, 6),
               Ok(Op::SetIoFlusher { a2: 9, a3: 8, a4: 7, a5: 6 }));
    assert_eq!(classify(PR_GET_IO_FLUSHER, 1, 2, 3, 4),
               Ok(Op::GetIoFlusher { a2: 1, a3: 2, a4: 3, a5: 4 }));
}

#[test]
fn syscall_user_dispatch_classifies_through_the_mode_ladder() {
    let sel = 0x7fff_0000_1000;
    assert_eq!(classify(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0, 0, 0),
               Ok(Op::SetSyscallUserDispatch(
                   sud::Config { on: false, offset: 0, len: 0, selector: 0 })));
    assert_eq!(classify(PR_SET_SYSCALL_USER_DISPATCH,
                        PR_SYS_DISPATCH_EXCLUSIVE_ON, 0x1000, 0x100, sel),
               Ok(Op::SetSyscallUserDispatch(
                   sud::Config { on: true, offset: 0x1000, len: 0x100, selector: sel })));
    // OFF with a non-zero tail, an unknown mode, and a zero-length
    // INCLUSIVE range are all EINVAL from the ladder, not from the switch.
    assert_eq!(classify(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0, 0, sel),
               Err(Errno::Einval));
    assert_eq!(classify(PR_SET_SYSCALL_USER_DISPATCH, 3, 0, 0, 0), Err(Errno::Einval));
    assert_eq!(classify(PR_SET_SYSCALL_USER_DISPATCH,
                        PR_SYS_DISPATCH_INCLUSIVE_ON, 0x1000, 0, sel), Err(Errno::Einval));
}

#[test]
fn get_auxv_takes_a_free_buffer_and_length_but_a_zero_tail() {
    assert_eq!(classify(PR_GET_AUXV, 0xdead_0000, 512, 0, 0),
               Ok(Op::GetAuxv { ptr: 0xdead_0000, len: 512 }));
    assert_eq!(classify(PR_GET_AUXV, 0, 0, 0, 0), Ok(Op::GetAuxv { ptr: 0, len: 0 }));
    assert_eq!(classify(PR_GET_AUXV, 0, 0, 1, 0), Err(Errno::Einval));
    assert_eq!(classify(PR_GET_AUXV, 0, 0, 0, 1), Err(Errno::Einval));
}

#[test]
fn timer_create_restore_ids_rejects_a_non_zero_tail_before_the_sub_command() {
    assert_eq!(classify(PR_TIMER_CREATE_RESTORE_IDS, PR_TIMER_CREATE_RESTORE_IDS_ON, 0, 0, 0),
               Ok(Op::TimerCreateRestoreIds(RestoreIds::On)));
    assert_eq!(classify(PR_TIMER_CREATE_RESTORE_IDS, PR_TIMER_CREATE_RESTORE_IDS_OFF, 0, 0, 0),
               Ok(Op::TimerCreateRestoreIds(RestoreIds::Off)));
    assert_eq!(classify(PR_TIMER_CREATE_RESTORE_IDS, PR_TIMER_CREATE_RESTORE_IDS_GET, 0, 0, 0),
               Ok(Op::TimerCreateRestoreIds(RestoreIds::Get)));
    // The tail rule beats an otherwise-valid sub-command.
    assert_eq!(classify(PR_TIMER_CREATE_RESTORE_IDS, PR_TIMER_CREATE_RESTORE_IDS_ON, 1, 0, 0),
               Err(Errno::Einval));
    assert_eq!(classify(PR_TIMER_CREATE_RESTORE_IDS, 3, 0, 0, 0), Err(Errno::Einval));
}

#[test]
fn futex_hash_and_rseq_slice_reach_their_owners_with_raw_arguments() {
    assert_eq!(classify(PR_FUTEX_HASH, PR_FUTEX_HASH_GET_SLOTS, 0, 0, 0),
               Ok(Op::FutexHash { cmd: PR_FUTEX_HASH_GET_SLOTS, slots: 0, a4: 0 }));
    // arg5 is not read by `futex_hash_prctl` at all, so it must not be
    // rejected here.
    assert_eq!(classify(PR_FUTEX_HASH, PR_FUTEX_HASH_SET_SLOTS, 4096, 0, 7),
               Ok(Op::FutexHash { cmd: PR_FUTEX_HASH_SET_SLOTS, slots: 4096, a4: 0 }));
    assert_eq!(classify(PR_RSEQ_SLICE_EXTENSION, PR_RSEQ_SLICE_EXTENSION_GET, 0, 0, 0),
               Ok(Op::RseqSliceExtension {
                   cmd: PR_RSEQ_SLICE_EXTENSION_GET, ctrl: 0, a4: 0, a5: 0 }));
}

#[test]
fn architecture_options_this_port_exposes_no_hardware_for_are_einval() {
    // arm64 answers EINVAL for each of these without SVE / SME / pointer
    // authentication / the tagged-address ABI, and x86_64 answers EINVAL for
    // all of them unconditionally. This port programs TCR_EL1 with top-byte-
    // ignore OFF and exposes no SVE/SME/PAuth, so EINVAL is the truthful
    // answer on both arches rather than a deferral.
    for opt in [PR_SVE_SET_VL, PR_SVE_GET_VL, PR_SME_SET_VL, PR_SME_GET_VL,
                PR_PAC_RESET_KEYS, PR_PAC_SET_ENABLED_KEYS, PR_PAC_GET_ENABLED_KEYS,
                PR_SET_TAGGED_ADDR_CTRL, PR_GET_TAGGED_ADDR_CTRL] {
        assert_eq!(classify(opt, 0, 0, 0, 0), Err(Errno::Einval), "option {opt}");
    }
    // The generic `(-EINVAL)` macro group: no architecture this port targets
    // overrides them (FP_MODE is MIPS-only, ENDIAN is powerpc-only).
    for opt in [PR_GET_UNALIGN, PR_SET_UNALIGN, PR_GET_FPEMU, PR_SET_FPEMU,
                PR_GET_FPEXC, PR_SET_FPEXC, PR_GET_ENDIAN, PR_SET_ENDIAN,
                PR_SET_FP_MODE, PR_GET_FP_MODE] {
        assert_eq!(classify(opt, 0, 0, 0, 0), Err(Errno::Einval), "option {opt}");
    }
    // MPX is an explicit "no longer implemented" EINVAL arm upstream, not an
    // unknown option.
    assert_eq!(classify(PR_MPX_ENABLE_MANAGEMENT, 0, 0, 0, 0), Err(Errno::Einval));
    assert_eq!(classify(PR_MPX_DISABLE_MANAGEMENT, 0, 0, 0, 0), Err(Errno::Einval));
}
