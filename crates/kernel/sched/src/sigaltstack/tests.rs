use super::*;

const ALT_SP: u64 = 0x7000_0000;
const ALT_SZ: u64 = 64 * 1024;

fn armed() -> AltStack { AltStack { sp: ALT_SP, size: ALT_SZ, flags: 0 } }

#[test]
fn on_sig_stack_matches_linux_half_open_range() {
    let a = armed();
    assert!(!on_sig_stack(ALT_SP, a), "base itself is NOT on the stack (sp > sas_ss_sp)");
    assert!(on_sig_stack(ALT_SP + 1, a));
    assert!(on_sig_stack(ALT_SP + ALT_SZ, a), "top IS on the stack (delta <= size)");
    assert!(!on_sig_stack(ALT_SP + ALT_SZ + 1, a));
    assert!(!on_sig_stack(ALT_SP - 1, a));
}

#[test]
fn autodisarm_stack_is_never_reported_as_current() {
    let a = AltStack { sp: ALT_SP, size: ALT_SZ, flags: SS_AUTODISARM };
    assert!(!on_sig_stack(ALT_SP + 1, a));
    assert_eq!(sas_ss_flags(ALT_SP + 1, a), SS_AUTODISARM);
}

#[test]
fn sas_ss_flags_reports_live_mode_plus_stored_flag_bits() {
    assert_eq!(sas_ss_flags(0x1000, AltStack::default()), SS_DISABLE);
    assert_eq!(sas_ss_flags(0x1000, armed()), 0);
    assert_eq!(sas_ss_flags(ALT_SP + 8, armed()), SS_ONSTACK);
    let dis = AltStack { sp: 0, size: 0, flags: SS_DISABLE | SS_AUTODISARM };
    assert_eq!(sas_ss_flags(0x1000, dis), SS_DISABLE | SS_AUTODISARM);
}

#[test]
fn sigsp_switches_only_when_sa_onstack_and_stack_is_free() {
    let sp = 0x1000_0000;
    assert_eq!(sigsp(sp, armed(), false), sp, "no SA_ONSTACK ⇒ stay on the interrupted stack");
    assert_eq!(sigsp(sp, armed(), true), ALT_SP + ALT_SZ);
    assert_eq!(sigsp(sp, AltStack::default(), true), sp, "disabled alt stack ⇒ stay");
    let on = ALT_SP + 16;
    assert_eq!(sigsp(on, armed(), true), on, "already on it ⇒ no re-entry switch");
    let auto = AltStack { sp: ALT_SP, size: ALT_SZ, flags: SS_AUTODISARM };
    assert_eq!(sigsp(on, auto, true), ALT_SP + ALT_SZ, "AUTODISARM ⇒ never 'already on it'");
}

#[test]
fn apply_rejects_change_while_executing_on_the_stack() {
    let e = apply(ALT_SP + 8, armed(), AltStack { sp: 0, size: 0, flags: SS_DISABLE });
    assert_eq!(e, Err(AltStackError::Eperm));
}

#[test]
fn apply_rejects_unknown_mode_bits() {
    let bad = AltStack { sp: ALT_SP, size: ALT_SZ, flags: 4 };
    assert_eq!(apply(0x1000, AltStack::default(), bad), Err(AltStackError::Einval));
    let both = AltStack { sp: ALT_SP, size: ALT_SZ, flags: SS_ONSTACK | SS_DISABLE };
    assert_eq!(apply(0x1000, AltStack::default(), both), Err(AltStackError::Einval));
}

#[test]
fn apply_rejects_undersized_stack_with_enomem() {
    let small = AltStack { sp: ALT_SP, size: MINSIGSTKSZ - 1, flags: 0 };
    assert_eq!(apply(0x1000, AltStack::default(), small), Err(AltStackError::Enomem));
    let ok = AltStack { sp: ALT_SP, size: MINSIGSTKSZ, flags: 0 };
    assert_eq!(apply(0x1000, AltStack::default(), ok), Ok(Some(ok)));
}

#[test]
fn eperm_outranks_einval_and_enomem() {
    let bad = AltStack { sp: ALT_SP, size: 1, flags: 4 };
    assert_eq!(apply(ALT_SP + 8, armed(), bad), Err(AltStackError::Eperm));
}

#[test]
fn einval_outranks_enomem() {
    let bad = AltStack { sp: ALT_SP, size: 1, flags: 4 };
    assert_eq!(apply(0x1000, AltStack::default(), bad), Err(AltStackError::Einval));
}

#[test]
fn ss_disable_zeroes_sp_and_size_but_keeps_flag_bits() {
    let req = AltStack { sp: ALT_SP, size: 1, flags: SS_DISABLE | SS_AUTODISARM };
    assert_eq!(apply(0x1000, armed(), req),
               Ok(Some(AltStack { sp: 0, size: 0, flags: SS_DISABLE | SS_AUTODISARM })));
}

#[test]
fn ss_disable_ignores_undersized_size() {
    let req = AltStack { sp: ALT_SP, size: 1, flags: SS_DISABLE };
    assert!(matches!(apply(0x1000, armed(), req), Ok(Some(_))));
}

#[test]
fn identical_request_is_accepted_without_a_store() {
    assert_eq!(apply(0x1000, armed(), armed()), Ok(None));
    let tiny = AltStack { sp: ALT_SP, size: 1, flags: 0 };
    assert_eq!(apply(0x1000, tiny, tiny), Ok(None),
               "Linux returns before the size check when nothing changes");
}

#[test]
fn ss_onstack_mode_is_accepted_as_a_request_flag() {
    let req = AltStack { sp: ALT_SP, size: ALT_SZ, flags: SS_ONSTACK };
    assert_eq!(apply(0x1000, AltStack::default(), req), Ok(Some(req)));
}

#[test]
fn reset_matches_sas_ss_reset() {
    assert_eq!(reset(), AltStack { sp: 0, size: 0, flags: SS_DISABLE });
}
