// Rule matching and the policy walk.
//
// A rule matches when every condition it carries holds for the request. The
// walk visits rules in order and, for each action it is still looking for, the
// FIRST matching rule decides that action; later rules can only decide actions
// no earlier rule has decided. The walk stops once every action it was asked
// about has been decided.

use crate::flags::*;
use crate::policy::rule::{LsmSlot, Rule};
use crate::uapi::Hook;

/// LSM labels of the object and the subject, as the matcher compares them.
#[derive(Copy, Clone, Default, Debug)]
pub struct LsmProps<'a> {
    pub obj_user: Option<&'a str>,
    pub obj_role: Option<&'a str>,
    pub obj_type: Option<&'a str>,
    pub subj_user: Option<&'a str>,
    pub subj_role: Option<&'a str>,
    pub subj_type: Option<&'a str>,
}

impl<'a> LsmProps<'a> {
    /// Label held in one slot. # C: O(1)
    pub fn at(&self, slot: LsmSlot) -> Option<&'a str> {
        match slot {
            LsmSlot::ObjUser => self.obj_user, LsmSlot::ObjRole => self.obj_role,
            LsmSlot::ObjType => self.obj_type, LsmSlot::SubjUser => self.subj_user,
            LsmSlot::SubjRole => self.subj_role, LsmSlot::SubjType => self.subj_type,
        }
    }
}

/// The request a rule is matched against.
#[derive(Copy, Clone, Debug)]
pub struct Request<'a> {
    pub func: Hook,
    pub mask: u32,
    pub fsmagic: u64,
    pub fsname: &'a str,
    pub fs_subtype: Option<&'a str>,
    pub fsuuid: [u8; 16],
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    /// The acting task may change its user id, which widens the effective-uid
    /// condition to any of its three user ids.
    pub cap_setuid: bool,
    /// As above for group ids.
    pub cap_setgid: bool,
    pub inode_uid: u32,
    pub inode_gid: u32,
    /// Hook-specific name: the keyring for a key event, the label for a
    /// critical-data event.
    pub func_data: Option<&'a str>,
    pub lsm: LsmProps<'a>,
}

impl<'a> Request<'a> {
    /// A request with the given hook and access mask and nothing else set.
    /// # C: O(1)
    pub fn new(func: Hook, mask: u32) -> Self {
        Self {
            func, mask, fsmagic: 0, fsname: "", fs_subtype: None, fsuuid: [0u8; 16],
            uid: 0, euid: 0, suid: 0, gid: 0, egid: 0, sgid: 0,
            cap_setuid: false, cap_setgid: false, inode_uid: 0, inode_gid: 0,
            func_data: None, lsm: LsmProps::default(),
        }
    }
}

/// What the walk decided.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Decision {
    /// Action bits plus the non-action bits contributed by matching rules.
    pub action: u32,
    /// PCR a measurement extends, when a matching measure rule named one.
    pub pcr: Option<u32>,
    /// Template a measurement uses, when a matching measure rule named one.
    pub template: Option<alloc::string::String>,
    /// Digest allowlist, when a matching appraise rule named one.
    pub allowed_algos: Option<u32>,
}

/// Does a keyring or label list carry `want`? A hook-data rule with no list
/// matches every name for that hook. # C: O(n)
fn match_rule_data(rule: &Rule, req: &Request<'_>) -> bool {
    if rule.flags & C_UID != 0 && !rule.uid_op.apply(req.uid, rule.uid.unwrap_or(0)) {
        return false;
    }
    let list = match rule.func {
        Hook::KeyCheck => match &rule.keyrings { None => return true, Some(l) => l },
        Hook::CriticalData => match &rule.label { None => return true, Some(l) => l },
        _ => return false,
    };
    match req.func_data {
        None => false,
        Some(d) => list.iter().any(|i| i == d),
    }
}

/// True when every condition the rule carries holds for the request. # C: O(1)
pub fn match_rule(rule: &Rule, req: &Request<'_>) -> bool {
    let post_setattr = req.func == Hook::PostSetattr;

    if rule.flags & C_FUNC != 0 && rule.func != req.func && !post_setattr { return false; }

    // The key and critical-data hooks match on their own name list and on
    // nothing else, so they never reach the inode conditions below.
    if matches!(req.func, Hook::KeyCheck | Hook::CriticalData) {
        return rule.func == req.func && match_rule_data(rule, req);
    }

    if rule.flags & C_MASK != 0 && rule.mask != req.mask && !post_setattr { return false; }
    if rule.flags & C_INMASK != 0 && rule.mask & req.mask == 0 && !post_setattr { return false; }
    if rule.flags & C_FSMAGIC != 0 && rule.fsmagic != req.fsmagic { return false; }
    if rule.flags & C_FSNAME != 0 && rule.fsname.as_deref() != Some(req.fsname) { return false; }
    if rule.flags & C_FS_SUBTYPE != 0 {
        match (req.fs_subtype, rule.fs_subtype.as_deref()) {
            (Some(have), Some(want)) if have == want => {}
            _ => return false,
        }
    }
    if rule.flags & C_FSUUID != 0 && rule.fsuuid != req.fsuuid { return false; }

    if rule.flags & C_UID != 0 && !rule.uid_op.apply(req.uid, rule.uid.unwrap_or(0)) {
        return false;
    }
    if rule.flags & C_EUID != 0 {
        let want = rule.uid.unwrap_or(0);
        let ok = if req.cap_setuid {
            rule.uid_op.apply(req.euid, want) || rule.uid_op.apply(req.suid, want)
                || rule.uid_op.apply(req.uid, want)
        } else {
            rule.uid_op.apply(req.euid, want)
        };
        if !ok { return false; }
    }
    if rule.flags & C_GID != 0 && !rule.gid_op.apply(req.gid, rule.gid.unwrap_or(0)) {
        return false;
    }
    if rule.flags & C_EGID != 0 {
        let want = rule.gid.unwrap_or(0);
        let ok = if req.cap_setgid {
            rule.gid_op.apply(req.egid, want) || rule.gid_op.apply(req.sgid, want)
                || rule.gid_op.apply(req.gid, want)
        } else {
            rule.gid_op.apply(req.egid, want)
        };
        if !ok { return false; }
    }
    if rule.flags & C_FOWNER != 0
        && !rule.fowner_op.apply(req.inode_uid, rule.fowner.unwrap_or(0)) { return false; }
    if rule.flags & C_FGROUP != 0
        && !rule.fgroup_op.apply(req.inode_gid, rule.fgroup.unwrap_or(0)) { return false; }

    for slot in LsmSlot::all() {
        let want = match rule.lsm_at(slot) { None => continue, Some(w) => w };
        // A rule naming a label the running system cannot resolve must not
        // match; it would otherwise grant the action it was written to
        // restrict.
        match req.lsm.at(slot) {
            Some(have) if have == want => {}
            _ => return false,
        }
    }
    true
}

/// Appraisal subaction a matching rule contributes for this hook. # C: O(1)
pub fn subaction(rule: &Rule, func: Hook) -> u32 {
    if rule.flags & C_FUNC == 0 { return IMA_FILE_APPRAISE; }
    match func {
        Hook::MmapCheck | Hook::MmapCheckReqprot => IMA_MMAP_APPRAISE,
        Hook::BprmCheck => IMA_BPRM_APPRAISE,
        Hook::CredsCheck => IMA_CREDS_APPRAISE,
        Hook::FileCheck | Hook::PostSetattr => IMA_FILE_APPRAISE,
        _ => IMA_READ_APPRAISE,
    }
}

/// Walk `rules` and decide the actions named in `want` (a mask of `IMA_MEASURE`
/// / `IMA_APPRAISE` / `IMA_AUDIT` / `IMA_HASH`). For each action the first
/// matching rule decides it, whether that rule says to do it or not to.
/// `fail_unverifiable_sigs` reflects the boot-time choice to fail signatures
/// that cannot be verified on the filesystem holding the file. # C: O(rules)
pub fn match_policy(rules: &[Rule], req: &Request<'_>, want: u32, fail_unverifiable_sigs: bool)
    -> Decision
{
    let mut out = Decision::default();
    // Each action bit is paired with its "dont" bit one position higher; the
    // walk looks for both and clears both once either is decided.
    let mut actmask = want | (want << 1);

    for rule in rules {
        if actmask == 0 { break; }
        if rule.action & actmask == 0 { continue; }
        if !match_rule(rule, req) { continue; }

        out.action |= rule.flags & IMA_NONACTION_FLAGS;
        out.action |= rule.action & IMA_DO_MASK;

        if rule.action & IMA_APPRAISE != 0 {
            out.action |= subaction(rule, req.func);
            out.action &= !IMA_HASH;
            if fail_unverifiable_sigs { out.action |= IMA_FAIL_UNVERIFIABLE_SIGS; }
            if rule.flags & C_VALIDATE_ALGOS != 0 { out.allowed_algos = Some(rule.allowed_algos); }
        }

        if rule.action & IMA_DO_MASK != 0 {
            actmask &= !(rule.action | (rule.action << 1));
        } else {
            actmask &= !(rule.action | (rule.action >> 1));
        }

        if rule.flags & C_PCR != 0 { out.pcr = Some(rule.pcr); }
        if let Some(t) = &rule.template { out.template = Some(t.clone()); }
    }
    out
}
