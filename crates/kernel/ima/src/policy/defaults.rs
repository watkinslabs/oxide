// The built-in policies and the boot-time selection between them.
//
// These rule sets are what runs before any policy is loaded from userspace. A
// rule quietly dropped from the exclusion set is a pseudo filesystem that
// starts being measured — the log fills and the PCR churns; a rule dropped from
// a measurement set is a measurement that silently stops happening. The tests
// pin each set as an exact sequence for that reason.

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::flags::*;
use crate::fsmagic;
use crate::policy::rule::{CmpOp, Rule};
use crate::uapi::Hook;

/// Which measurement policy the boot selected.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TcbPolicy {
    /// No built-in measurement rules at all.
    #[default]
    None,
    /// The original minimum-TCB set.
    Original,
    /// The current default TCB set.
    Default,
}

/// Boot-time selection of built-in policies.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Selection {
    pub tcb: TcbPolicy,
    pub appraise_tcb: bool,
    pub secure_boot: bool,
    pub critical_data: bool,
    /// Fail, rather than accept, a signature that cannot be verified on the
    /// filesystem holding the file.
    pub fail_unverifiable_sigs: bool,
}

/// Build-time choices the built-in appraisal sets depend on.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct BuiltinConfig {
    /// Policy may be replaced at runtime, which the default appraisal set
    /// answers by requiring a signature on the replacement.
    pub write_policy: bool,
    /// The default appraisal set requires signatures, not bare digests.
    pub appraise_signed_init: bool,
    pub require_module_sigs: bool,
    pub require_firmware_sigs: bool,
    pub require_kexec_sigs: bool,
    pub require_policy_sigs: bool,
}

impl Default for BuiltinConfig {
    fn default() -> Self {
        Self {
            write_policy: true,
            appraise_signed_init: false,
            require_module_sigs: false,
            require_firmware_sigs: false,
            require_kexec_sigs: false,
            require_policy_sigs: false,
        }
    }
}

/// The root user id, which the built-in rules name.
const ROOT: u32 = 0;

fn r(action: u32, flags: u32) -> Rule {
    let mut e = Rule::new();
    e.action = action;
    e.flags = flags;
    e
}

fn magic(action: u32, m: u64) -> Rule {
    let mut e = r(action, C_FSMAGIC);
    e.fsmagic = m;
    e
}

fn func_rule(action: u32, f: Hook, extra: u32) -> Rule {
    let mut e = r(action, C_FUNC | extra);
    e.func = f;
    e
}

/// Pseudo filesystems excluded from measurement. # C: O(1)
pub fn dont_measure_rules() -> Vec<Rule> {
    let mut v = Vec::new();
    for m in [fsmagic::PROC, fsmagic::SYSFS, fsmagic::DEBUGFS] { v.push(magic(DONT_MEASURE, m)); }
    let mut tmp = magic(DONT_MEASURE, fsmagic::TMPFS);
    tmp.flags |= C_FUNC;
    tmp.func = Hook::FileCheck;
    v.push(tmp);
    for m in [fsmagic::DEVPTS, fsmagic::BINFMTFS, fsmagic::SECURITYFS, fsmagic::SELINUXFS,
              fsmagic::SMACKFS, fsmagic::CGROUP, fsmagic::CGROUP2, fsmagic::NSFS,
              fsmagic::EFIVARFS] {
        v.push(magic(DONT_MEASURE, m));
    }
    v
}

/// The original minimum-TCB measurement set. # C: O(1)
pub fn original_measurement_rules() -> Vec<Rule> {
    let mut v = Vec::new();
    v.push(mask_rule(MEASURE, Hook::MmapCheck, MAY_EXEC, C_MASK));
    v.push(mask_rule(MEASURE, Hook::BprmCheck, MAY_EXEC, C_MASK));
    let mut read_by_root = mask_rule(MEASURE, Hook::FileCheck, MAY_READ, C_MASK);
    read_by_root.flags |= C_UID;
    read_by_root.uid = Some(ROOT);
    read_by_root.uid_op = CmpOp::Eq;
    v.push(read_by_root);
    v.push(func_rule(MEASURE, Hook::ModuleCheck, 0));
    v.push(func_rule(MEASURE, Hook::FirmwareCheck, 0));
    v
}

/// The current default TCB measurement set. # C: O(1)
pub fn default_measurement_rules() -> Vec<Rule> {
    let mut v = Vec::new();
    v.push(mask_rule(MEASURE, Hook::MmapCheck, MAY_EXEC, C_MASK));
    v.push(mask_rule(MEASURE, Hook::BprmCheck, MAY_EXEC, C_MASK));
    for cond in [C_EUID, C_UID] {
        let mut e = mask_rule(MEASURE, Hook::FileCheck, MAY_READ, C_INMASK);
        e.flags |= cond;
        e.uid = Some(ROOT);
        e.uid_op = CmpOp::Eq;
        v.push(e);
    }
    v.push(func_rule(MEASURE, Hook::ModuleCheck, 0));
    v.push(func_rule(MEASURE, Hook::FirmwareCheck, 0));
    v.push(func_rule(MEASURE, Hook::PolicyCheck, 0));
    v
}

fn mask_rule(action: u32, f: Hook, mask: u32, mask_cond: u32) -> Rule {
    let mut e = func_rule(action, f, mask_cond);
    e.mask = mask;
    e
}

/// The default appraisal set: pseudo filesystems excluded, then everything
/// owned by root appraised. # C: O(1)
pub fn default_appraise_rules(cfg: &BuiltinConfig) -> Vec<Rule> {
    let mut v = Vec::new();
    for m in [fsmagic::PROC, fsmagic::SYSFS, fsmagic::DEBUGFS, fsmagic::TMPFS, fsmagic::RAMFS,
              fsmagic::DEVPTS, fsmagic::BINFMTFS, fsmagic::SECURITYFS, fsmagic::SELINUXFS,
              fsmagic::SMACKFS, fsmagic::NSFS, fsmagic::EFIVARFS, fsmagic::CGROUP,
              fsmagic::CGROUP2] {
        v.push(magic(DONT_APPRAISE, m));
    }
    if cfg.write_policy {
        v.push(func_rule(APPRAISE, Hook::PolicyCheck, IMA_DIGSIG_REQUIRED));
    }
    let mut owner = r(APPRAISE, C_FOWNER);
    owner.fowner = Some(ROOT);
    owner.fowner_op = CmpOp::Eq;
    if cfg.appraise_signed_init { owner.flags |= IMA_DIGSIG_REQUIRED; }
    v.push(owner);
    v
}

/// Build-time appraisal requirements, folded in ahead of other appraise rules.
/// # C: O(1)
pub fn build_appraise_rules(cfg: &BuiltinConfig) -> Vec<Rule> {
    let mut v = Vec::new();
    if cfg.require_module_sigs {
        v.push(func_rule(APPRAISE, Hook::ModuleCheck, IMA_DIGSIG_REQUIRED));
    }
    if cfg.require_firmware_sigs {
        v.push(func_rule(APPRAISE, Hook::FirmwareCheck, IMA_DIGSIG_REQUIRED));
    }
    if cfg.require_kexec_sigs {
        v.push(func_rule(APPRAISE, Hook::KexecKernelCheck, IMA_DIGSIG_REQUIRED));
    }
    if cfg.require_policy_sigs {
        v.push(func_rule(APPRAISE, Hook::PolicyCheck, IMA_DIGSIG_REQUIRED));
    }
    v
}

/// The secure-boot set: signatures required on everything the kernel loads.
/// # C: O(1)
pub fn secure_boot_rules() -> Vec<Rule> {
    let mut v = Vec::new();
    v.push(func_rule(APPRAISE, Hook::ModuleCheck,
                     IMA_DIGSIG_REQUIRED | IMA_MODSIG_ALLOWED | IMA_CHECK_BLACKLIST));
    v.push(func_rule(APPRAISE, Hook::FirmwareCheck, IMA_DIGSIG_REQUIRED));
    v.push(func_rule(APPRAISE, Hook::KexecKernelCheck, IMA_DIGSIG_REQUIRED));
    v.push(func_rule(APPRAISE, Hook::PolicyCheck, IMA_DIGSIG_REQUIRED));
    v
}

/// Measure kernel-internal critical data. # C: O(1)
pub fn critical_data_rules() -> Vec<Rule> {
    let mut v = Vec::new();
    v.push(func_rule(MEASURE, Hook::CriticalData, 0));
    v
}

/// Compose the initial rule list from a boot selection. # C: O(1)
pub fn init_policy(sel: &Selection, cfg: &BuiltinConfig) -> Vec<Rule> {
    let mut v = Vec::new();
    // With no measurement policy selected, no exclusions are needed either.
    if sel.tcb != TcbPolicy::None { v.extend(dont_measure_rules()); }
    match sel.tcb {
        TcbPolicy::Original => v.extend(original_measurement_rules()),
        TcbPolicy::Default => v.extend(default_measurement_rules()),
        TcbPolicy::None => {}
    }
    // Signature requirements come before any other appraisal rule so that a
    // later, looser rule cannot decide the appraisal first.
    if sel.secure_boot { v.extend(secure_boot_rules()); }
    // The secure-boot set already covers every build-time requirement, so the
    // build-time rules are only added when it is absent.
    if !sel.secure_boot { v.extend(build_appraise_rules(cfg)); }
    if sel.appraise_tcb { v.extend(default_appraise_rules(cfg)); }
    if sel.critical_data { v.extend(critical_data_rules()); }
    v
}

/// Apply the boot parameters that select built-in policies. `ima_tcb` and
/// `ima_appraise_tcb` are passed as their own booleans; `ima_policy=` is passed
/// as its value. The first selection of a measurement policy wins. # C: O(n)
pub fn select_from_cmdline(ima_tcb: bool, ima_appraise_tcb: bool, ima_policy: Option<&str>)
    -> Selection
{
    let mut s = Selection::default();
    if ima_tcb { s.tcb = TcbPolicy::Original; }
    if ima_appraise_tcb { s.appraise_tcb = true; }
    if let Some(v) = ima_policy {
        for tok in v.split([' ', '|', '\n']) {
            match tok {
                "" => {}
                "tcb" => if s.tcb == TcbPolicy::None { s.tcb = TcbPolicy::Default },
                "appraise_tcb" => s.appraise_tcb = true,
                "secure_boot" => s.secure_boot = true,
                "critical_data" => s.critical_data = true,
                "fail_securely" => s.fail_unverifiable_sigs = true,
                _ => {}
            }
        }
    }
    s
}

/// Render a rule set as policy text, one rule per line. # C: O(n)
pub fn render(rules: &[Rule]) -> alloc::string::String {
    let mut s = alloc::string::String::new();
    for e in rules { s.push_str(&crate::policy::show::show_rule(e)); }
    s
}

/// Name of the measurement policy a selection chose. # C: O(1)
pub fn tcb_name(t: TcbPolicy) -> alloc::string::String {
    match t { TcbPolicy::None => "none", TcbPolicy::Original => "tcb", TcbPolicy::Default => "tcb" }
        .to_string()
}
