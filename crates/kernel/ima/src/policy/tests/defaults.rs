// The built-in sets, pinned as exact sequences. A rule silently dropped here
// is a measurement that stops happening or a pseudo filesystem that starts
// filling the log, and nothing else in the tree would go red.

use alloc::vec::Vec;

use crate::flags::*;
use crate::fsmagic;
use crate::policy::defaults::*;
use crate::policy::matcher::{match_policy, match_rule, Request};
use crate::policy::rule::CmpOp;
use crate::uapi::Hook;

fn magics(rules: &[crate::policy::Rule], action: u32) -> Vec<u64> {
    rules.iter().filter(|r| r.action == action && r.has(C_FSMAGIC)).map(|r| r.fsmagic).collect()
}

#[test]
fn the_exclusion_set_is_exactly_these_filesystems_in_this_order() {
    let v = dont_measure_rules();
    assert_eq!(v.len(), 13);
    assert_eq!(magics(&v, DONT_MEASURE), alloc::vec![
        fsmagic::PROC, fsmagic::SYSFS, fsmagic::DEBUGFS, fsmagic::TMPFS,
        fsmagic::DEVPTS, fsmagic::BINFMTFS, fsmagic::SECURITYFS, fsmagic::SELINUXFS,
        fsmagic::SMACKFS, fsmagic::CGROUP, fsmagic::CGROUP2, fsmagic::NSFS,
        fsmagic::EFIVARFS,
    ]);
    // The temporary filesystem is excluded only for file opens; data read from
    // it by other hooks is still measured.
    let tmp = &v[3];
    assert_eq!(tmp.fsmagic, fsmagic::TMPFS);
    assert_eq!(tmp.func, Hook::FileCheck);
    assert!(tmp.has(C_FUNC));
    assert!(v.iter().all(|r| r.action == DONT_MEASURE));
}

#[test]
fn the_exclusions_actually_exclude() {
    // Not just present: a request on each excluded filesystem must come back
    // with no measurement.
    let policy = init_policy(&Selection { tcb: TcbPolicy::Default, ..Selection::default() },
                             &BuiltinConfig::default());
    for m in [fsmagic::PROC, fsmagic::SYSFS, fsmagic::DEBUGFS, fsmagic::DEVPTS,
              fsmagic::BINFMTFS, fsmagic::SECURITYFS, fsmagic::SELINUXFS, fsmagic::SMACKFS,
              fsmagic::CGROUP, fsmagic::CGROUP2, fsmagic::NSFS, fsmagic::EFIVARFS] {
        let mut req = Request::new(Hook::BprmCheck, MAY_EXEC);
        req.fsmagic = m;
        let d = match_policy(&policy, &req, IMA_MEASURE, false);
        assert_eq!(d.action & IMA_MEASURE, 0, "fsmagic {m:#x} must not be measured");
    }
    // And an ordinary filesystem still is.
    let mut req = Request::new(Hook::BprmCheck, MAY_EXEC);
    req.fsmagic = fsmagic::EXT4;
    assert_eq!(match_policy(&policy, &req, IMA_MEASURE, false).action & IMA_MEASURE, IMA_MEASURE);
}

#[test]
fn the_original_measurement_set_is_exact() {
    let v = original_measurement_rules();
    assert_eq!(v.len(), 5);
    assert!(v.iter().all(|r| r.action == MEASURE));

    assert_eq!((v[0].func, v[0].mask, v[0].flags), (Hook::MmapCheck, MAY_EXEC, C_FUNC | C_MASK));
    assert_eq!((v[1].func, v[1].mask, v[1].flags), (Hook::BprmCheck, MAY_EXEC, C_FUNC | C_MASK));
    assert_eq!((v[2].func, v[2].mask), (Hook::FileCheck, MAY_READ));
    assert_eq!((v[2].uid, v[2].uid_op), (Some(0), CmpOp::Eq));
    assert_eq!(v[2].flags, C_FUNC | C_MASK | C_UID);
    assert_eq!((v[3].func, v[3].flags), (Hook::ModuleCheck, C_FUNC));
    assert_eq!((v[4].func, v[4].flags), (Hook::FirmwareCheck, C_FUNC));
}

#[test]
fn the_default_measurement_set_is_exact() {
    let v = default_measurement_rules();
    assert_eq!(v.len(), 7);
    assert!(v.iter().all(|r| r.action == MEASURE));

    assert_eq!((v[0].func, v[0].mask, v[0].flags), (Hook::MmapCheck, MAY_EXEC, C_FUNC | C_MASK));
    assert_eq!((v[1].func, v[1].mask, v[1].flags), (Hook::BprmCheck, MAY_EXEC, C_FUNC | C_MASK));
    // Reads by root are measured, matched on the effective id and then on the
    // real one; both use the any-of mask so a read-write open still counts.
    assert_eq!((v[2].func, v[2].mask, v[2].flags),
               (Hook::FileCheck, MAY_READ, C_FUNC | C_INMASK | C_EUID));
    assert_eq!((v[3].func, v[3].mask, v[3].flags),
               (Hook::FileCheck, MAY_READ, C_FUNC | C_INMASK | C_UID));
    assert_eq!((v[2].uid, v[3].uid), (Some(0), Some(0)));
    assert_eq!((v[4].func, v[4].flags), (Hook::ModuleCheck, C_FUNC));
    assert_eq!((v[5].func, v[5].flags), (Hook::FirmwareCheck, C_FUNC));
    assert_eq!((v[6].func, v[6].flags), (Hook::PolicyCheck, C_FUNC));
}

#[test]
fn the_default_measurement_set_measures_what_it_names() {
    let policy = init_policy(&Selection { tcb: TcbPolicy::Default, ..Selection::default() },
                             &BuiltinConfig::default());
    let ext4 = |func, mask| {
        let mut q = Request::new(func, mask);
        q.fsmagic = fsmagic::EXT4;
        q
    };
    for (func, mask) in [(Hook::MmapCheck, MAY_EXEC), (Hook::BprmCheck, MAY_EXEC),
                         (Hook::FileCheck, MAY_READ)] {
        let d = match_policy(&policy, &ext4(func, mask), IMA_MEASURE, false);
        assert_eq!(d.action & IMA_MEASURE, IMA_MEASURE, "{}", func.token());
    }
    for func in [Hook::ModuleCheck, Hook::FirmwareCheck, Hook::PolicyCheck] {
        let d = match_policy(&policy, &ext4(func, 0), IMA_MEASURE, false);
        assert_eq!(d.action & IMA_MEASURE, IMA_MEASURE, "{}", func.token());
    }
    // A non-root read is not part of this set.
    let mut req = ext4(Hook::FileCheck, MAY_READ);
    req.uid = 1000; req.euid = 1000;
    assert_eq!(match_policy(&policy, &req, IMA_MEASURE, false).action & IMA_MEASURE, 0);
}

#[test]
fn the_default_appraisal_set_is_exact() {
    let cfg = BuiltinConfig::default();
    let v = default_appraise_rules(&cfg);
    assert_eq!(magics(&v, DONT_APPRAISE), alloc::vec![
        fsmagic::PROC, fsmagic::SYSFS, fsmagic::DEBUGFS, fsmagic::TMPFS, fsmagic::RAMFS,
        fsmagic::DEVPTS, fsmagic::BINFMTFS, fsmagic::SECURITYFS, fsmagic::SELINUXFS,
        fsmagic::SMACKFS, fsmagic::NSFS, fsmagic::EFIVARFS, fsmagic::CGROUP, fsmagic::CGROUP2,
    ]);
    // A runtime-replaceable policy must itself be signed.
    let policy_rule = v.iter().find(|r| r.func == Hook::PolicyCheck).expect("policy rule");
    assert_eq!(policy_rule.action, APPRAISE);
    assert!(policy_rule.flags & IMA_DIGSIG_REQUIRED != 0);
    // Everything owned by root is appraised.
    let last = v.last().unwrap();
    assert_eq!((last.action, last.fowner, last.fowner_op), (APPRAISE, Some(0), CmpOp::Eq));
    assert_eq!(last.flags & IMA_DIGSIG_REQUIRED, 0);
    assert_eq!(v.len(), 16);

    // With signed init selected, that last rule demands a signature.
    let signed = BuiltinConfig { appraise_signed_init: true, ..cfg };
    let v = default_appraise_rules(&signed);
    assert!(v.last().unwrap().flags & IMA_DIGSIG_REQUIRED != 0);
}

#[test]
fn the_secure_boot_set_is_exact_and_demands_signatures() {
    let v = secure_boot_rules();
    assert_eq!(v.len(), 4);
    assert!(v.iter().all(|r| r.action == APPRAISE && r.flags & IMA_DIGSIG_REQUIRED != 0));
    assert_eq!(v.iter().map(|r| r.func).collect::<Vec<_>>(),
               alloc::vec![Hook::ModuleCheck, Hook::FirmwareCheck, Hook::KexecKernelCheck,
                           Hook::PolicyCheck]);
    // Only a module may satisfy the requirement with an appended signature,
    // and only modules are checked against the blacklist alongside it.
    assert!(v[0].flags & IMA_MODSIG_ALLOWED != 0);
    assert!(v[0].flags & IMA_CHECK_BLACKLIST != 0);
    assert!(v[1..].iter().all(|r| r.flags & IMA_MODSIG_ALLOWED == 0));
}

#[test]
fn the_secure_boot_set_denies_an_unsigned_module() {
    let sel = Selection { secure_boot: true, ..Selection::default() };
    let policy = init_policy(&sel, &BuiltinConfig::default());
    let req = Request::new(Hook::ModuleCheck, 0);
    let d = match_policy(&policy, &req, IMA_APPRAISE, false);
    assert!(d.action & IMA_APPRAISE != 0);
    assert!(d.action & IMA_DIGSIG_REQUIRED != 0,
            "a secure-boot module load must require a signature");
}

#[test]
fn the_critical_data_set_is_one_rule() {
    let v = critical_data_rules();
    assert_eq!(v.len(), 1);
    assert_eq!((v[0].action, v[0].func, v[0].flags), (MEASURE, Hook::CriticalData, C_FUNC));
}

#[test]
fn build_time_requirements_appear_only_when_configured() {
    let none = build_appraise_rules(&BuiltinConfig::default());
    assert!(none.is_empty());
    let all = BuiltinConfig {
        require_module_sigs: true, require_firmware_sigs: true,
        require_kexec_sigs: true, require_policy_sigs: true,
        ..BuiltinConfig::default()
    };
    let v = build_appraise_rules(&all);
    assert_eq!(v.iter().map(|r| r.func).collect::<Vec<_>>(),
               alloc::vec![Hook::ModuleCheck, Hook::FirmwareCheck, Hook::KexecKernelCheck,
                           Hook::PolicyCheck]);
    assert!(v.iter().all(|r| r.flags & IMA_DIGSIG_REQUIRED != 0));
}

#[test]
fn no_selection_loads_no_rules() {
    let policy = init_policy(&Selection::default(), &BuiltinConfig::default());
    assert!(policy.is_empty());
}

#[test]
fn composition_order_puts_exclusions_first_and_signatures_before_appraisals() {
    let sel = Selection {
        tcb: TcbPolicy::Default, appraise_tcb: true, secure_boot: true, critical_data: true,
        fail_unverifiable_sigs: false,
    };
    let v = init_policy(&sel, &BuiltinConfig::default());
    let dont = v.iter().position(|r| r.action == DONT_MEASURE).unwrap();
    let meas = v.iter().position(|r| r.action == MEASURE && r.func == Hook::BprmCheck).unwrap();
    let sb = v.iter().position(|r| r.action == APPRAISE && r.func == Hook::ModuleCheck).unwrap();
    let tcb_appraise = v.iter().position(|r| r.action == DONT_APPRAISE).unwrap();
    assert!(dont < meas, "exclusions precede measurement rules");
    assert!(meas < sb, "measurement rules precede appraisal rules");
    assert!(sb < tcb_appraise, "signature requirements precede the appraisal set");
    // Selecting secure boot suppresses the build-time duplicates.
    let signed_modules = v.iter().filter(|r| r.action == APPRAISE && r.func == Hook::ModuleCheck)
        .count();
    assert_eq!(signed_modules, 1);
}

#[test]
fn command_line_selection() {
    assert_eq!(select_from_cmdline(false, false, None), Selection::default());

    let s = select_from_cmdline(true, false, None);
    assert_eq!(s.tcb, TcbPolicy::Original);

    let s = select_from_cmdline(false, false, Some("tcb"));
    assert_eq!(s.tcb, TcbPolicy::Default);

    // The first selection of a measurement policy wins.
    let s = select_from_cmdline(true, false, Some("tcb"));
    assert_eq!(s.tcb, TcbPolicy::Original);

    let s = select_from_cmdline(false, false,
                                Some("tcb|appraise_tcb|secure_boot|critical_data|fail_securely"));
    assert_eq!(s, Selection { tcb: TcbPolicy::Default, appraise_tcb: true, secure_boot: true,
                              critical_data: true, fail_unverifiable_sigs: true });

    // Space separated, and an unknown token is ignored rather than fatal.
    let s = select_from_cmdline(false, false, Some("secure_boot nonsense critical_data"));
    assert!(s.secure_boot && s.critical_data && s.tcb == TcbPolicy::None);

    let s = select_from_cmdline(false, true, None);
    assert!(s.appraise_tcb);
}

#[test]
fn every_builtin_rule_would_be_accepted_by_the_parser() {
    let sel = Selection { tcb: TcbPolicy::Default, appraise_tcb: true, secure_boot: true,
                          critical_data: true, fail_unverifiable_sigs: false };
    let cfg = BuiltinConfig {
        require_module_sigs: true, require_firmware_sigs: true, require_kexec_sigs: true,
        require_policy_sigs: true, ..BuiltinConfig::default()
    };
    for r in init_policy(&sel, &cfg).iter().chain(build_appraise_rules(&cfg).iter()) {
        assert!(crate::policy::validate_rule(r), "built-in rule is not valid: {:?}", r);
    }
    // And a rule with a condition its hook cannot honour is still refused, so
    // the check above is not vacuous.
    let mut bad = critical_data_rules().pop().unwrap();
    bad.flags |= C_FSMAGIC;
    bad.fsmagic = fsmagic::EXT4;
    assert!(!crate::policy::validate_rule(&bad));
}

#[test]
fn a_dropped_exclusion_would_be_visible() {
    // Positive control for the exclusion tests above: with the process
    // filesystem's rule removed, a request on it is measured.
    let mut policy = init_policy(&Selection { tcb: TcbPolicy::Default, ..Selection::default() },
                                 &BuiltinConfig::default());
    policy.retain(|r| !(r.action == DONT_MEASURE && r.fsmagic == fsmagic::PROC));
    let mut req = Request::new(Hook::BprmCheck, MAY_EXEC);
    req.fsmagic = fsmagic::PROC;
    assert_eq!(match_policy(&policy, &req, IMA_MEASURE, false).action & IMA_MEASURE, IMA_MEASURE);
}

#[test]
fn rendering_the_builtin_policy_produces_one_line_per_rule() {
    let sel = Selection { tcb: TcbPolicy::Default, ..Selection::default() };
    let v = init_policy(&sel, &BuiltinConfig::default());
    let text = render(&v);
    assert_eq!(text.lines().count(), v.len());
    assert!(text.starts_with("dont_measure fsmagic=0x9fa0"));
    assert!(match_rule(&v[0], &{
        let mut q = Request::new(Hook::FileCheck, MAY_READ);
        q.fsmagic = fsmagic::PROC;
        q
    }));
    assert_eq!(tcb_name(TcbPolicy::None), "none");
}
