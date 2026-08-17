// Rendering a rule back as policy text, in the order and spelling the policy
// file uses. What is rendered must parse back to the same rule, which is what
// makes the policy file a usable record of what is enforced.

use alloc::format;
use alloc::string::{String, ToString};

use crate::flags::*;
use crate::hash::HashAlgo;
use crate::policy::parse::algos_of;
use crate::policy::rule::{CmpOp, LsmSlot, Rule};

fn action_word(action: u32) -> &'static str {
    match action {
        MEASURE => "measure", DONT_MEASURE => "dont_measure",
        APPRAISE => "appraise", DONT_APPRAISE => "dont_appraise",
        AUDIT => "audit", DONT_AUDIT => "dont_audit",
        HASH => "hash", DONT_HASH => "dont_hash",
        _ => "",
    }
}

fn mask_word(bit: u32) -> &'static str {
    match bit {
        MAY_EXEC => "MAY_EXEC", MAY_WRITE => "MAY_WRITE",
        MAY_READ => "MAY_READ", MAY_APPEND => "MAY_APPEND",
        _ => "",
    }
}

/// Hyphenated lowercase rendering of a filesystem UUID. # C: O(1)
pub fn uuid_str(u: &[u8; 16]) -> String {
    let h = crate::hash::hex(u);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

fn id_cond(out: &mut String, key: &str, op: CmpOp, v: u32) {
    out.push_str(key);
    out.push(op.sep());
    out.push_str(&v.to_string());
    out.push(' ');
}

/// One rule as a policy-file line, terminated by a newline. # C: O(n)
pub fn show_rule(e: &Rule) -> String {
    let mut s = String::new();
    s.push_str(action_word(e.action));
    s.push(' ');

    if e.flags & C_FUNC != 0 { s.push_str(&format!("func={} ", e.func.token())); }

    if e.flags & (C_MASK | C_INMASK) != 0 {
        // An exact-match condition renders the bare name; an any-of condition
        // keeps the '^' that asked for it.
        let caret = if e.flags & C_MASK != 0 { "" } else { "^" };
        for bit in [MAY_EXEC, MAY_WRITE, MAY_READ, MAY_APPEND] {
            if e.mask & bit != 0 { s.push_str(&format!("mask={}{} ", caret, mask_word(bit))); }
        }
        s.push(' ');
    }
    if e.flags & C_FSMAGIC != 0 { s.push_str(&format!("fsmagic=0x{:x} ", e.fsmagic)); }
    if e.flags & C_FSNAME != 0 {
        s.push_str(&format!("fsname={} ", e.fsname.as_deref().unwrap_or("")));
    }
    if e.flags & C_FS_SUBTYPE != 0 {
        s.push_str(&format!("fs_subtype={} ", e.fs_subtype.as_deref().unwrap_or("")));
    }
    if e.flags & C_KEYRINGS != 0 {
        s.push_str("keyrings=");
        s.push_str(&join_list(e.keyrings.as_deref().unwrap_or(&[])));
        s.push(' ');
    }
    if e.flags & C_LABEL != 0 {
        s.push_str("label=");
        s.push_str(&join_list(e.label.as_deref().unwrap_or(&[])));
        s.push(' ');
    }
    if e.flags & C_PCR != 0 { s.push_str(&format!("pcr={} ", e.pcr)); }
    if e.flags & C_FSUUID != 0 { s.push_str(&format!("fsuuid={} ", uuid_str(&e.fsuuid))); }
    if e.flags & C_UID != 0 { id_cond(&mut s, "uid", e.uid_op, e.uid.unwrap_or(0)); }
    if e.flags & C_EUID != 0 { id_cond(&mut s, "euid", e.uid_op, e.uid.unwrap_or(0)); }
    if e.flags & C_GID != 0 { id_cond(&mut s, "gid", e.gid_op, e.gid.unwrap_or(0)); }
    if e.flags & C_EGID != 0 { id_cond(&mut s, "egid", e.gid_op, e.gid.unwrap_or(0)); }
    if e.flags & C_FOWNER != 0 { id_cond(&mut s, "fowner", e.fowner_op, e.fowner.unwrap_or(0)); }
    if e.flags & C_FGROUP != 0 { id_cond(&mut s, "fgroup", e.fgroup_op, e.fgroup.unwrap_or(0)); }
    if e.flags & C_VALIDATE_ALGOS != 0 {
        s.push_str("appraise_algos=");
        let names: alloc::vec::Vec<&str> = algos_of(e.allowed_algos).iter()
            .map(|a: &HashAlgo| a.name()).collect();
        s.push_str(&names.join(","));
        s.push(' ');
    }
    for slot in LsmSlot::all() {
        if let Some(v) = e.lsm_at(slot) { s.push_str(&format!("{}={} ", slot.key(), v)); }
    }
    if let Some(t) = &e.template { s.push_str(&format!("template={} ", t)); }
    if e.flags & IMA_DIGSIG_REQUIRED != 0 {
        if e.flags & IMA_SIGV3_REQUIRED != 0 { s.push_str("appraise_type=sigv3 "); }
        else if e.flags & IMA_MODSIG_ALLOWED != 0 { s.push_str("appraise_type=imasig|modsig "); }
        else { s.push_str("appraise_type=imasig "); }
    }
    if e.flags & IMA_VERITY_REQUIRED != 0 { s.push_str("digest_type=verity "); }
    if e.flags & IMA_PERMIT_DIRECTIO != 0 { s.push_str("permit_directio "); }
    s.push('\n');
    s
}

fn join_list(items: &[String]) -> String {
    let mut s = String::new();
    for (i, it) in items.iter().enumerate() {
        if i > 0 { s.push('|'); }
        s.push_str(it);
    }
    s
}
