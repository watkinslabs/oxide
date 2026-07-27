// Hosted coverage for the `prctl(2)` option classification and per-option
// argument rules. These live beside the ungated decision core on purpose: the
// slot file and the executor arms are kernel-only, so a `#[cfg(test)]` block
// written there would compile out and report "ok" without ever running.

use super::*;

fn einval<T: core::fmt::Debug>(r: Result<T, Errno>) { assert_eq!(r.err(), Some(Errno::Einval)); }

#[test]
fn unknown_option_is_einval() {
    for opt in [0u64, 5, 6, 9, 10, 11, 12, 17, 18, 19, 20, 48, 49, 999, u64::MAX] {
        einval(classify(opt, 0, 0, 0, 0));
    }
}

// ---- PR_SET_PDEATHSIG --------------------------------------------------

#[test]
fn pdeathsig_accepts_zero_through_nsig() {
    assert_eq!(classify(PR_SET_PDEATHSIG, 0, 0, 0, 0), Ok(Op::SetPdeathsig(0)));
    assert_eq!(classify(PR_SET_PDEATHSIG, 9, 0, 0, 0), Ok(Op::SetPdeathsig(9)));
    assert_eq!(classify(PR_SET_PDEATHSIG, NSIG, 0, 0, 0), Ok(Op::SetPdeathsig(64)));
}

#[test]
fn pdeathsig_rejects_above_nsig_without_truncating() {
    einval(classify(PR_SET_PDEATHSIG, NSIG + 1, 0, 0, 0));
    // The bug this pins: `arg2 as u32` first would turn 0x1_0000_0009 into 9
    // and accept it. Linux's `valid_signal()` takes the full unsigned long.
    einval(classify(PR_SET_PDEATHSIG, 0x1_0000_0009, 0, 0, 0));
    einval(classify(PR_SET_PDEATHSIG, u64::MAX, 0, 0, 0));
}

#[test]
fn pdeathsig_ignores_tail_args_like_linux() {
    // Linux checks only `valid_signal(arg2)` here — no arg3..arg5 rule.
    assert_eq!(classify(PR_SET_PDEATHSIG, 9, 1, 2, 3), Ok(Op::SetPdeathsig(9)));
}

// ---- PR_SET_DUMPABLE ---------------------------------------------------

#[test]
fn dumpable_accepts_only_off_and_owner() {
    assert_eq!(classify(PR_SET_DUMPABLE, 0, 0, 0, 0), Ok(Op::SetDumpable(0)));
    assert_eq!(classify(PR_SET_DUMPABLE, 1, 0, 0, 0), Ok(Op::SetDumpable(1)));
    // SUID_DUMP_ROOT is kernel-set only.
    einval(classify(PR_SET_DUMPABLE, 2, 0, 0, 0));
    einval(classify(PR_SET_DUMPABLE, 3, 0, 0, 0));
}

// ---- value-returning options ------------------------------------------

#[test]
fn get_timing_reports_statistical_which_is_zero() {
    assert_eq!(classify(PR_GET_TIMING, 0, 0, 0, 0), Ok(Op::GetTiming));
    assert_eq!(PR_TIMING_STATISTICAL, 0, "PR_TIMING_STATISTICAL is 0, not 1");
}

#[test]
fn set_timing_accepts_only_statistical() {
    assert_eq!(classify(PR_SET_TIMING, PR_TIMING_STATISTICAL, 0, 0, 0), Ok(Op::SetTiming));
    einval(classify(PR_SET_TIMING, 1, 0, 0, 0));
}

// ---- PR_SET/GET_NO_NEW_PRIVS ------------------------------------------

#[test]
fn set_no_new_privs_requires_exactly_one_and_zero_tail() {
    assert_eq!(classify(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), Ok(Op::SetNoNewPrivs));
    einval(classify(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0));
    einval(classify(PR_SET_NO_NEW_PRIVS, 2, 0, 0, 0));
    einval(classify(PR_SET_NO_NEW_PRIVS, 1, 1, 0, 0));
    einval(classify(PR_SET_NO_NEW_PRIVS, 1, 0, 1, 0));
    einval(classify(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 1));
}

#[test]
fn get_no_new_privs_requires_all_zero_args() {
    assert_eq!(classify(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0), Ok(Op::GetNoNewPrivs));
    for i in 0..4 {
        let mut a = [0u64; 4];
        a[i] = 1;
        einval(classify(PR_GET_NO_NEW_PRIVS, a[0], a[1], a[2], a[3]));
    }
}

// ---- capability options -----------------------------------------------

#[test]
fn capbset_rejects_above_cap_last_cap_not_just_above_63() {
    assert_eq!(CAP_LAST_CAP, 40, "CAP_LAST_CAP == CAP_CHECKPOINT_RESTORE");
    assert_eq!(classify(PR_CAPBSET_READ, 0, 0, 0, 0), Ok(Op::CapbsetRead(0)));
    assert_eq!(classify(PR_CAPBSET_READ, CAP_LAST_CAP, 0, 0, 0),
               Ok(Op::CapbsetRead(CAP_LAST_CAP as u32)));
    // 41..63 are unassigned: Linux answers EINVAL, not "bit is clear".
    for cap in [CAP_LAST_CAP + 1, 50, 63, 64, u64::MAX] {
        einval(classify(PR_CAPBSET_READ, cap, 0, 0, 0));
        einval(classify(PR_CAPBSET_DROP, cap, 0, 0, 0));
    }
}

#[test]
fn cap_ambient_clear_all_requires_zero_tail() {
    assert_eq!(classify(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0),
               Ok(Op::CapAmbient(Ambient::ClearAll)));
    einval(classify(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 1, 0, 0));
    einval(classify(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 1, 0));
    einval(classify(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 1));
}

#[test]
fn cap_ambient_validates_the_cap_before_the_subcommand() {
    // Linux runs `if (((!cap_valid(arg3)) | arg4 | arg5)) return -EINVAL;`
    // BEFORE recognising arg2, so a bad cap beats an unknown sub-command.
    einval(classify(PR_CAP_AMBIENT, 99, CAP_LAST_CAP + 1, 0, 0));
    assert_eq!(classify(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, 21, 0, 0),
               Ok(Op::CapAmbient(Ambient::IsSet(21))));
    assert_eq!(classify(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, 0, 0, 0),
               Ok(Op::CapAmbient(Ambient::Raise(0))));
    assert_eq!(classify(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, CAP_LAST_CAP, 0, 0),
               Ok(Op::CapAmbient(Ambient::Lower(CAP_LAST_CAP as u32))));
    einval(classify(PR_CAP_AMBIENT, 99, 0, 0, 0));
}

#[test]
fn set_keepcaps_is_boolean() {
    assert_eq!(classify(PR_SET_KEEPCAPS, 0, 0, 0, 0), Ok(Op::SetKeepcaps(false)));
    assert_eq!(classify(PR_SET_KEEPCAPS, 1, 0, 0, 0), Ok(Op::SetKeepcaps(true)));
    einval(classify(PR_SET_KEEPCAPS, 2, 0, 0, 0));
}

// ---- PR_MCE_KILL -------------------------------------------------------

#[test]
fn mce_kill_argument_matrix() {
    assert_eq!(classify(PR_MCE_KILL, PR_MCE_KILL_CLEAR, 0, 0, 0), Ok(Op::MceKillClear));
    // CLEAR requires arg3 == 0.
    einval(classify(PR_MCE_KILL, PR_MCE_KILL_CLEAR, 1, 0, 0));
    for p in [PR_MCE_KILL_LATE, PR_MCE_KILL_EARLY, PR_MCE_KILL_DEFAULT] {
        assert_eq!(classify(PR_MCE_KILL, PR_MCE_KILL_SET, p, 0, 0), Ok(Op::MceKillSet(p)));
    }
    einval(classify(PR_MCE_KILL, PR_MCE_KILL_SET, 3, 0, 0));
    einval(classify(PR_MCE_KILL, 2, 0, 0, 0));
    // `if (arg4 | arg5) return -EINVAL;` runs before the sub-command switch.
    einval(classify(PR_MCE_KILL, PR_MCE_KILL_CLEAR, 0, 1, 0));
    einval(classify(PR_MCE_KILL, PR_MCE_KILL_CLEAR, 0, 0, 1));
}

#[test]
fn mce_kill_get_requires_all_zero_args_and_reports_the_policy() {
    assert_eq!(classify(PR_MCE_KILL_GET, 0, 0, 0, 0), Ok(Op::MceKillGet));
    einval(classify(PR_MCE_KILL_GET, 1, 0, 0, 0));
    assert_eq!(mce_kill_report(0), PR_MCE_KILL_DEFAULT as i64);
    assert_eq!(mce_kill_report(mce_kill_apply(PR_MCE_KILL_EARLY)), PR_MCE_KILL_EARLY as i64);
    assert_eq!(mce_kill_report(mce_kill_apply(PR_MCE_KILL_LATE)), PR_MCE_KILL_LATE as i64);
    // DEFAULT clears PF_MCE_PROCESS too, so it reads back as DEFAULT.
    assert_eq!(mce_kill_report(mce_kill_apply(PR_MCE_KILL_DEFAULT)), PR_MCE_KILL_DEFAULT as i64);
}

// ---- PR_SET/GET_THP_DISABLE -------------------------------------------

#[test]
fn thp_disable_flag_rules() {
    assert_eq!(classify(PR_SET_THP_DISABLE, 0, 0, 0, 0),
               Ok(Op::SetThpDisable { disable: false, except_advised: false }));
    assert_eq!(classify(PR_SET_THP_DISABLE, 1, 0, 0, 0),
               Ok(Op::SetThpDisable { disable: true, except_advised: false }));
    assert_eq!(classify(PR_SET_THP_DISABLE, 1, PR_THP_DISABLE_EXCEPT_ADVISED, 0, 0),
               Ok(Op::SetThpDisable { disable: true, except_advised: true }));
    // Flags only when disabling.
    einval(classify(PR_SET_THP_DISABLE, 0, PR_THP_DISABLE_EXCEPT_ADVISED, 0, 0));
    // Undefined flag bits.
    einval(classify(PR_SET_THP_DISABLE, 1, 1, 0, 0));
    einval(classify(PR_SET_THP_DISABLE, 1, 0, 1, 0));
    einval(classify(PR_SET_THP_DISABLE, 1, 0, 0, 1));
}

#[test]
fn thp_disable_report_encoding() {
    assert_eq!(thp_disable_report(crate::task::THP_DISABLE_OFF), 0);
    assert_eq!(thp_disable_report(crate::task::THP_DISABLE_COMPLETELY), 1);
    assert_eq!(thp_disable_report(crate::task::THP_DISABLE_EXCEPT_ADVISED),
               1 | PR_THP_DISABLE_EXCEPT_ADVISED as i64);
}

#[test]
fn get_thp_disable_requires_all_zero_args() {
    assert_eq!(classify(PR_GET_THP_DISABLE, 0, 0, 0, 0), Ok(Op::GetThpDisable));
    einval(classify(PR_GET_THP_DISABLE, 1, 0, 0, 0));
}

// ---- PR_SET/GET_TSC ----------------------------------------------------

#[test]
fn tsc_mode_rules() {
    // GET takes a user POINTER and writes the mode through it.
    assert_eq!(classify(PR_GET_TSC, 0xdead_beef, 0, 0, 0), Ok(Op::GetTsc(0xdead_beef)));
    assert_eq!(classify(PR_SET_TSC, PR_TSC_ENABLE as u64, 0, 0, 0),
               Ok(Op::SetTsc(PR_TSC_ENABLE)));
    assert_eq!(classify(PR_SET_TSC, PR_TSC_SIGSEGV as u64, 0, 0, 0),
               Ok(Op::SetTsc(PR_TSC_SIGSEGV)));
    einval(classify(PR_SET_TSC, 0, 0, 0, 0));
    einval(classify(PR_SET_TSC, 3, 0, 0, 0));
}

// ---- PR_SET_MM ---------------------------------------------------------

#[test]
fn set_mm_tail_argument_rule() {
    // `if (arg5 || (arg4 && opt is not AUXV/MAP/MAP_SIZE)) return -EINVAL;`
    assert_eq!(classify(PR_SET_MM, 1, 0x1000, 0, 0), Ok(Op::SetMm));
    einval(classify(PR_SET_MM, 1, 0x1000, 0, 1));
    einval(classify(PR_SET_MM, 1, 0x1000, 8, 0));
    for opt in [vmm::PR_SET_MM_AUXV as u64, vmm::PR_SET_MM_MAP as u64,
                vmm::PR_SET_MM_MAP_SIZE as u64] {
        assert_eq!(classify(PR_SET_MM, opt, 0x1000, 8, 0), Ok(Op::SetMm));
    }
}

// ---- speculation control ----------------------------------------------

#[test]
fn speculation_ctrl_argument_rules() {
    assert_eq!(classify(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0),
               Ok(Op::GetSpecCtrl(PR_SPEC_STORE_BYPASS)));
    einval(classify(PR_GET_SPECULATION_CTRL, 0, 1, 0, 0));
    assert_eq!(classify(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 1, 0, 0),
               Ok(Op::SetSpecCtrl { which: PR_SPEC_STORE_BYPASS, ctrl: 1 }));
    einval(classify(PR_SET_SPECULATION_CTRL, 0, 0, 1, 0));
    einval(classify(PR_SET_SPECULATION_CTRL, 0, 0, 0, 1));
}

#[test]
fn speculation_ctrl_unmitigated_kernel_answers() {
    assert_eq!(spec_ctrl_get(PR_SPEC_STORE_BYPASS), PR_SPEC_ENABLE);
    assert_eq!(spec_ctrl_get(PR_SPEC_INDIRECT_BRANCH), PR_SPEC_ENABLE);
    assert_eq!(spec_ctrl_get(PR_SPEC_L1D_FLUSH), PR_SPEC_FORCE_DISABLE);
    assert_eq!(spec_ctrl_get(99), -(Errno::Enodev.as_i32() as i64));
    // `ssb_prctl_set` answers ENXIO when ssb_mode is neither PRCTL nor SECCOMP.
    assert_eq!(spec_ctrl_set(PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE as u64),
               -(Errno::Enxio.as_i32() as i64));
    assert_eq!(spec_ctrl_set(PR_SPEC_INDIRECT_BRANCH, PR_SPEC_ENABLE as u64), 0);
    assert_eq!(spec_ctrl_set(PR_SPEC_INDIRECT_BRANCH, PR_SPEC_DISABLE as u64),
               -(Errno::Eperm.as_i32() as i64));
    assert_eq!(spec_ctrl_set(PR_SPEC_INDIRECT_BRANCH, 0),
               -(Errno::Erange.as_i32() as i64));
    assert_eq!(spec_ctrl_set(PR_SPEC_L1D_FLUSH, PR_SPEC_ENABLE as u64),
               -(Errno::Eperm.as_i32() as i64));
    assert_eq!(spec_ctrl_set(99, 0), -(Errno::Enodev.as_i32() as i64));
    // PR_SPEC_NOT_AFFECTED and PR_SPEC_PRCTL are part of the reported ABI even
    // though this configuration never emits them.
    assert_eq!(PR_SPEC_NOT_AFFECTED, 0);
    assert_eq!(PR_SPEC_PRCTL, 1);
    assert_eq!(PR_SPEC_DISABLE_NOEXEC, 1 << 4);
}

// ---- options that carry a raw user pointer ----------------------------

#[test]
fn pointer_carrying_options_pass_the_pointer_through_unchecked() {
    // Linux validates these with `put_user`, which is EFAULT at copy time —
    // there is no pre-check, and in particular no EINVAL for a null pointer.
    assert_eq!(classify(PR_GET_PDEATHSIG, 0, 0, 0, 0), Ok(Op::GetPdeathsig(0)));
    assert_eq!(classify(PR_GET_CHILD_SUBREAPER, 0x1234, 0, 0, 0),
               Ok(Op::GetChildSubreaper(0x1234)));
    assert_eq!(classify(PR_GET_TID_ADDRESS, 0x1234, 0, 0, 0), Ok(Op::GetTidAddress(0x1234)));
    assert_eq!(classify(PR_SET_NAME, 0x1234, 0, 0, 0), Ok(Op::SetName(0x1234)));
    assert_eq!(classify(PR_GET_NAME, 0x1234, 0, 0, 0), Ok(Op::GetName(0x1234)));
}

#[test]
fn child_subreaper_is_boolean_over_the_whole_word() {
    assert_eq!(classify(PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0), Ok(Op::SetChildSubreaper(false)));
    assert_eq!(classify(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0), Ok(Op::SetChildSubreaper(true)));
    // Linux stores `!!arg2`, so any non-zero arms it — including values whose
    // low 32 bits are zero.
    assert_eq!(classify(PR_SET_CHILD_SUBREAPER, 0x1_0000_0000, 0, 0, 0),
               Ok(Op::SetChildSubreaper(true)));
}

#[test]
fn mpx_management_is_an_explicit_einval_arm() {
    // Linux keeps these as named cases returning EINVAL ("No longer
    // implemented"), which is the same answer the default arm gives — pinned
    // so a future reshuffle cannot turn them into a success.
    einval(classify(PR_MPX_ENABLE_MANAGEMENT, 0, 0, 0, 0));
    einval(classify(PR_MPX_DISABLE_MANAGEMENT, 0, 0, 0, 0));
}

#[test]
fn seccomp_and_securebits_and_timerslack_pass_their_args_through() {
    assert_eq!(classify(PR_GET_SECCOMP, 0, 0, 0, 0), Ok(Op::GetSeccomp));
    assert_eq!(classify(PR_SET_SECCOMP, 2, 0x1234, 0, 0),
               Ok(Op::SetSeccomp { mode: 2, filter: 0x1234 }));
    assert_eq!(classify(PR_GET_SECUREBITS, 0, 0, 0, 0), Ok(Op::GetSecurebits));
    assert_eq!(classify(PR_SET_SECUREBITS, 0x20, 0, 0, 0), Ok(Op::SetSecurebits(0x20)));
    assert_eq!(classify(PR_SET_TIMERSLACK, 1234, 0, 0, 0), Ok(Op::SetTimerslack(1234)));
    assert_eq!(classify(PR_GET_TIMERSLACK, 0, 0, 0, 0), Ok(Op::GetTimerslack));
    assert_eq!(classify(PR_TASK_PERF_EVENTS_DISABLE, 0, 0, 0, 0), Ok(Op::PerfEventsDisable));
    assert_eq!(classify(PR_TASK_PERF_EVENTS_ENABLE, 0, 0, 0, 0), Ok(Op::PerfEventsEnable));
    assert_eq!(classify(PR_SET_VMA, 0, 0, 0, 0), Ok(Op::SetVma));
}
