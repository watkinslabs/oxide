// The policy rule parser: one line of policy text to one rule.
//
// A line is a whitespace-separated list of an action and its conditions. The
// parse rejects an unknown keyword, a second action, a repeated condition, an
// unparsable value, and — through validation — a condition the named hook
// cannot honour. A `#` starts a comment that ends the line.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::flags::*;
use crate::hash::{HashAlgo, HASH_ALGO_LAST};
use crate::limits::invalid_pcr;
use crate::policy::rule::{CmpOp, LsmSlot, Rule};
use crate::policy::validate::validate_rule;
use crate::template::desc::lookup_desc;
use crate::uapi::Hook;

/// Why a policy line was refused. Every variant is reported to userspace as
/// an invalid-argument error; the distinction exists for diagnosis and tests.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ParseError {
    /// Keyword is not part of the policy language.
    UnknownKeyword,
    /// A second action on one line.
    DuplicateAction,
    /// A condition given twice.
    DuplicateCondition,
    /// A condition's value could not be parsed or is out of range.
    BadValue,
    /// The rule parsed but the combination is not one this hook accepts.
    InvalidRule,
}

/// Parse one policy line into a rule. # C: O(n)
pub fn parse_rule(line: &str) -> Result<Rule, ParseError> {
    let mut e = Rule::new();
    for tok in line.split([' ', '\t']) {
        if tok.is_empty() { continue; }
        if tok.starts_with('#') { break; }
        apply_token(&mut e, tok)?;
    }
    if !validate_rule(&e) { return Err(ParseError::InvalidRule); }
    Ok(e)
}

fn set_action(e: &mut Rule, a: u32) -> Result<(), ParseError> {
    if e.action != UNKNOWN { return Err(ParseError::DuplicateAction); }
    e.action = a;
    Ok(())
}

fn split_kv(tok: &str) -> Option<(&str, CmpOp, &str)> {
    let i = tok.find(['=', '>', '<'])?;
    let op = match &tok[i..i + 1] {
        "=" => CmpOp::Eq, ">" => CmpOp::Gt, _ => CmpOp::Lt,
    };
    Some((&tok[..i], op, &tok[i + 1..]))
}

fn apply_token(e: &mut Rule, tok: &str) -> Result<(), ParseError> {
    match tok {
        "measure" => return set_action(e, MEASURE),
        "dont_measure" => return set_action(e, DONT_MEASURE),
        "appraise" => return set_action(e, APPRAISE),
        "dont_appraise" => return set_action(e, DONT_APPRAISE),
        "audit" => return set_action(e, AUDIT),
        "dont_audit" => return set_action(e, DONT_AUDIT),
        "hash" => return set_action(e, HASH),
        "dont_hash" => return set_action(e, DONT_HASH),
        "permit_directio" => { e.flags |= IMA_PERMIT_DIRECTIO; return Ok(()); }
        _ => {}
    }
    let (key, op, val) = split_kv(tok).ok_or(ParseError::UnknownKeyword)?;
    match (key, op) {
        ("func", CmpOp::Eq) => func(e, val),
        ("mask", CmpOp::Eq) => mask(e, val),
        ("fsmagic", CmpOp::Eq) => fsmagic(e, val),
        ("fsname", CmpOp::Eq) => { e.fsname = Some(val.to_string()); e.flags |= C_FSNAME; Ok(()) }
        ("fs_subtype", CmpOp::Eq) => {
            if e.fs_subtype.is_some() { return Err(ParseError::DuplicateCondition); }
            e.fs_subtype = Some(val.to_string()); e.flags |= C_FS_SUBTYPE; Ok(())
        }
        ("fsuuid", CmpOp::Eq) => fsuuid(e, val),
        ("uid", _) => id_cond(e, val, op, false, false),
        ("euid", _) => id_cond(e, val, op, false, true),
        ("gid", _) => id_cond(e, val, op, true, false),
        ("egid", _) => id_cond(e, val, op, true, true),
        ("fowner", _) => fown(e, val, op, false),
        ("fgroup", _) => fown(e, val, op, true),
        ("obj_user", CmpOp::Eq) => lsm(e, LsmSlot::ObjUser, val),
        ("obj_role", CmpOp::Eq) => lsm(e, LsmSlot::ObjRole, val),
        ("obj_type", CmpOp::Eq) => lsm(e, LsmSlot::ObjType, val),
        ("subj_user", CmpOp::Eq) => lsm(e, LsmSlot::SubjUser, val),
        ("subj_role", CmpOp::Eq) => lsm(e, LsmSlot::SubjRole, val),
        ("subj_type", CmpOp::Eq) => lsm(e, LsmSlot::SubjType, val),
        ("digest_type", CmpOp::Eq) => {
            if val != "verity" { return Err(ParseError::BadValue); }
            e.flags |= IMA_VERITY_REQUIRED; Ok(())
        }
        ("appraise_type", CmpOp::Eq) => appraise_type(e, val),
        ("appraise_flag", CmpOp::Eq) => Ok(()),
        ("appraise_algos", CmpOp::Eq) => appraise_algos(e, val),
        ("pcr", CmpOp::Eq) => pcr(e, val),
        ("template", CmpOp::Eq) => template(e, val),
        ("keyrings", CmpOp::Eq) => {
            if e.keyrings.is_some() { return Err(ParseError::DuplicateCondition); }
            e.keyrings = Some(opt_list(val)); e.flags |= C_KEYRINGS; Ok(())
        }
        ("label", CmpOp::Eq) => {
            if e.label.is_some() { return Err(ParseError::DuplicateCondition); }
            e.label = Some(opt_list(val)); e.flags |= C_LABEL; Ok(())
        }
        _ => Err(ParseError::UnknownKeyword),
    }
}

fn func(e: &mut Rule, val: &str) -> Result<(), ParseError> {
    if e.func != Hook::None { return Err(ParseError::DuplicateCondition); }
    e.func = Hook::by_token(val).ok_or(ParseError::BadValue)?;
    e.flags |= C_FUNC;
    Ok(())
}

fn mask(e: &mut Rule, val: &str) -> Result<(), ParseError> {
    if e.mask != 0 { return Err(ParseError::DuplicateCondition); }
    // A leading '^' asks for "any of these bits" instead of an exact match.
    let exact = !val.starts_with('^');
    let name = if exact { val } else { &val[1..] };
    e.mask = match name {
        "MAY_EXEC" => MAY_EXEC,
        "MAY_WRITE" => MAY_WRITE,
        "MAY_READ" => MAY_READ,
        "MAY_APPEND" => MAY_APPEND,
        _ => return Err(ParseError::BadValue),
    };
    e.flags |= if exact { C_MASK } else { C_INMASK };
    Ok(())
}

fn fsmagic(e: &mut Rule, val: &str) -> Result<(), ParseError> {
    if e.fsmagic != 0 { return Err(ParseError::DuplicateCondition); }
    let s = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X")).unwrap_or(val);
    if s.is_empty() { return Err(ParseError::BadValue); }
    let mut v: u64 = 0;
    for c in s.chars() {
        let d = c.to_digit(16).ok_or(ParseError::BadValue)?;
        v = v.checked_mul(16).and_then(|v| v.checked_add(d as u64)).ok_or(ParseError::BadValue)?;
    }
    e.fsmagic = v;
    e.flags |= C_FSMAGIC;
    Ok(())
}

fn fsuuid(e: &mut Rule, val: &str) -> Result<(), ParseError> {
    if e.fsuuid != [0u8; 16] { return Err(ParseError::DuplicateCondition); }
    e.fsuuid = parse_uuid(val).ok_or(ParseError::BadValue)?;
    e.flags |= C_FSUUID;
    Ok(())
}

/// Parse the hyphenated 36-character UUID form. # C: O(1)
pub fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 36 { return None; }
    for i in [8usize, 13, 18, 23] { if b[i] != b'-' { return None; } }
    let mut out = [0u8; 16];
    let mut oi = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'-' { i += 1; continue; }
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out[oi] = ((hi << 4) | lo) as u8;
        oi += 1;
        i += 2;
    }
    if oi != 16 { return None; }
    Some(out)
}

fn dec_u32(val: &str) -> Result<u32, ParseError> {
    if val.is_empty() { return Err(ParseError::BadValue); }
    let mut v: u64 = 0;
    for c in val.chars() {
        let d = c.to_digit(10).ok_or(ParseError::BadValue)?;
        v = v * 10 + d as u64;
        if v > u32::MAX as u64 { return Err(ParseError::BadValue); }
    }
    // The all-ones value is the "no such id" marker and is never a valid
    // subject or owner id.
    if v == u32::MAX as u64 { return Err(ParseError::BadValue); }
    Ok(v as u32)
}

fn id_cond(e: &mut Rule, val: &str, op: CmpOp, group: bool, effective: bool)
    -> Result<(), ParseError>
{
    // The uid and euid conditions share one stored value, as do gid and egid,
    // so naming either twice is a duplicate.
    let slot = if group { &mut e.gid } else { &mut e.uid };
    if slot.is_some() { return Err(ParseError::DuplicateCondition); }
    let v = dec_u32(val)?;
    *slot = Some(v);
    if group { e.gid_op = op } else { e.uid_op = op }
    e.flags |= match (group, effective) {
        (false, false) => C_UID, (false, true) => C_EUID,
        (true, false) => C_GID, (true, true) => C_EGID,
    };
    Ok(())
}

fn fown(e: &mut Rule, val: &str, op: CmpOp, group: bool) -> Result<(), ParseError> {
    let slot = if group { &mut e.fgroup } else { &mut e.fowner };
    if slot.is_some() { return Err(ParseError::DuplicateCondition); }
    let v = dec_u32(val)?;
    *slot = Some(v);
    if group { e.fgroup_op = op; e.flags |= C_FGROUP } else { e.fowner_op = op; e.flags |= C_FOWNER }
    Ok(())
}

fn lsm(e: &mut Rule, slot: LsmSlot, val: &str) -> Result<(), ParseError> {
    if e.lsm[slot as usize].is_some() { return Err(ParseError::DuplicateCondition); }
    e.lsm[slot as usize] = Some(val.to_string());
    Ok(())
}

fn appraise_type(e: &mut Rule, val: &str) -> Result<(), ParseError> {
    match val {
        "imasig" => {
            if e.flags & IMA_VERITY_REQUIRED != 0 { return Err(ParseError::BadValue); }
            e.flags |= IMA_DIGSIG_REQUIRED | IMA_CHECK_BLACKLIST;
        }
        "sigv3" => e.flags |= IMA_SIGV3_REQUIRED | IMA_DIGSIG_REQUIRED | IMA_CHECK_BLACKLIST,
        "imasig|modsig" => {
            if e.flags & (IMA_VERITY_REQUIRED | IMA_SIGV3_REQUIRED) != 0 {
                return Err(ParseError::BadValue);
            }
            e.flags |= IMA_DIGSIG_REQUIRED | IMA_MODSIG_ALLOWED | IMA_CHECK_BLACKLIST;
        }
        _ => return Err(ParseError::BadValue),
    }
    Ok(())
}

fn appraise_algos(e: &mut Rule, val: &str) -> Result<(), ParseError> {
    if e.allowed_algos != 0 { return Err(ParseError::DuplicateCondition); }
    let mut bits: u32 = 0;
    for name in val.split(',') {
        let a = HashAlgo::by_name(name).ok_or(ParseError::BadValue)?;
        // An algorithm this kernel cannot compute must not be accepted into an
        // allowlist; the rule would permit a digest nothing can verify.
        if a.engine().is_none() { return Err(ParseError::BadValue); }
        bits |= 1u32 << a.id();
    }
    if bits == 0 { return Err(ParseError::BadValue); }
    e.allowed_algos = bits;
    e.flags |= C_VALIDATE_ALGOS;
    Ok(())
}

fn pcr(e: &mut Rule, val: &str) -> Result<(), ParseError> {
    let mut v: i64 = 0;
    let neg = val.starts_with('-');
    let digits = if neg { &val[1..] } else { val };
    if digits.is_empty() { return Err(ParseError::BadValue); }
    for c in digits.chars() {
        let d = c.to_digit(10).ok_or(ParseError::BadValue)?;
        v = v * 10 + d as i64;
        if v > u32::MAX as i64 { return Err(ParseError::BadValue); }
    }
    if neg { v = -v; }
    if invalid_pcr(v) { return Err(ParseError::BadValue); }
    e.pcr = v as u32;
    e.flags |= C_PCR;
    Ok(())
}

fn template(e: &mut Rule, val: &str) -> Result<(), ParseError> {
    if e.action != MEASURE { return Err(ParseError::BadValue); }
    if e.template.is_some() { return Err(ParseError::DuplicateCondition); }
    let d = lookup_desc(val).ok_or(ParseError::BadValue)?;
    e.template = Some(d.name.to_string());
    Ok(())
}

fn opt_list(val: &str) -> Vec<String> {
    val.split('|').map(|s| s.to_string()).collect()
}

/// Bit position of an algorithm within an `appraise_algos` allowlist. # C: O(1)
pub fn algo_bit(a: HashAlgo) -> u32 { 1u32 << a.id() }

/// Algorithms named by an allowlist bitfield, in ABI id order. # C: O(1)
pub fn algos_of(bits: u32) -> Vec<HashAlgo> {
    (0..HASH_ALGO_LAST)
        .filter(|i| bits & (1u32 << i) != 0)
        .filter_map(HashAlgo::from_id)
        .collect()
}
