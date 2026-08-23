// Permission-check entry points.
//
// Every kernel subsystem that mediates an operation calls one of these with
// the two SIDs, the class and the permissions it wants. The decision, the
// permissive handling and the audit record all happen here, in one place, so
// no caller can accidentally act on a verdict without reporting it.

use alloc::string::String;
use alloc::vec::Vec;

use selinux::sidtab::Sid;
use selinux::uapi::classmap::{class_def, perm_names};
use selinux::Verdict;

/// Refusal returned to a caller whose operation the policy denies.
pub const EACCES: i64 = -13;

/// Ask whether a subject may exercise permissions on an object. # C: O(1) cached
///
/// Returns `Ok(())` when the operation proceeds. A denial in a permissive
/// domain also returns `Ok(())` — and is still reported, because a permissive
/// denial that is not reported is invisible, and reporting is the only thing
/// permissive mode is for.
pub fn has_perm(ssid: Sid, tsid: Sid, class: u16, requested: u32) -> Result<(), i64> {
    let Some(verdict) = crate::with(|s| s.has_perm(ssid, tsid, class, requested)) else {
        return Ok(());
    };
    if verdict.audit { report(ssid, tsid, class, &verdict); }
    if verdict.allowed { Ok(()) } else { Err(EACCES) }
}

/// Ask without reporting, for a caller that will report the denial itself
/// with more context than this layer has. # C: O(1) cached
pub fn has_perm_noaudit(ssid: Sid, tsid: Sid, class: u16, requested: u32) -> Verdict {
    crate::with(|s| s.has_perm(ssid, tsid, class, requested)).unwrap_or(Verdict::allow())
}

/// Whether a subject may act on the security server itself. # C: O(1) cached
pub fn security_perm(ssid: Sid, permission: &str) -> Result<(), i64> {
    let Some(class) = selinux::uapi::classmap::class_by_name("security") else {
        return Ok(());
    };
    let Some(bit) = selinux::uapi::classmap::perm_bit(class, permission) else {
        return Err(EACCES);
    };
    has_perm(ssid, crate::label::security_sid(), class, bit)
}

/// SELinux's `cred_has_capability` check for the LSM `capable` hook. The
/// kernel capability set has two 32-bit access-vector classes: capability for
/// CAP_0..CAP_31 and capability2 for CAP_32 onward. User-namespace checks use
/// the corresponding cap_*_userns classes.
pub fn capability(ssid: Sid, cap: u32, init_namespace: bool) -> Result<(), i64> {
    let (class_name, bit) = if cap < 32 {
        (if init_namespace { "capability" } else { "cap_userns" }, 1u32 << cap)
    } else if cap < 64 {
        (if init_namespace { "capability2" } else { "cap2_userns" }, 1u32 << (cap - 32))
    } else {
        return Err(EACCES);
    };
    let class = selinux::uapi::classmap::class_by_name(class_name).ok_or(EACCES)?;
    has_perm(ssid, ssid, class, bit)
}

/// Label a newly-created kernel IPC object using the policy transition for its
/// concrete object class. # C: O(1)
pub fn create_sid(class_name: &'static str) -> Sid {
    let sid = crate::task::current_sid();
    let Some(class) = selinux::uapi::classmap::class_by_name(class_name) else { return sid };
    crate::with(|s| s.transition_sid(sid, sid, class, None).unwrap_or(sid)).unwrap_or(sid)
}

/// Check SysV IPC read/write access against the object label. # C: O(1) cached
pub fn ipc_permission(ssid: Sid, tsid: Sid, class_name: &'static str, requested: i32)
    -> Result<(), i64>
{
    let class = selinux::uapi::classmap::class_by_name(class_name).ok_or(EACCES)?;
    let mut av = 0;
    if requested & 0o444 != 0 {
        av |= selinux::uapi::classmap::perm_bit(class, "unix_read").unwrap_or(0);
    }
    if requested & 0o222 != 0 {
        av |= selinux::uapi::classmap::perm_bit(class, "unix_write").unwrap_or(0);
    }
    if av == 0 { return Ok(()) }
    has_perm(ssid, tsid, class, av)
}

/// Emit the record describing one denial or audited grant.
///
/// The record names the permissions, the class and both contexts. Naming the
/// SIDs alone would be useless: a SID is meaningful only against the policy
/// that issued it, and the record outlives that policy.
fn report(ssid: Sid, tsid: Sid, class: u16, verdict: &Verdict) {
    let body = record_body(ssid, tsid, class, verdict);
    let _ = audit::log_if_enabled(audit::uapi::AUDIT_AVC, body.as_bytes());
}

/// Build the text of one access-vector record. # C: O(permissions)
pub fn record_body(ssid: Sid, tsid: Sid, class: u16, verdict: &Verdict) -> String {
    let mut out = String::new();
    out.push_str("avc:  ");
    out.push_str(if verdict.allowed { "granted  { " } else { "denied  { " });
    out.push_str(&permission_names(class, verdict.denied).join(" "));
    out.push_str(" } for ");
    push_context(&mut out, "scontext=", ssid);
    out.push(' ');
    push_context(&mut out, "tcontext=", tsid);
    out.push_str(" tclass=");
    out.push_str(class_def(class).map_or("?", |d| d.name));
    if verdict.permissive { out.push_str(" permissive=1"); }
    out
}

/// Names of the permissions a mask selects, in bit order. # C: O(permissions)
pub fn permission_names(class: u16, mask: u32) -> Vec<&'static str> {
    let Some(def) = class_def(class) else { return Vec::new() };
    perm_names(def).enumerate()
        .filter(|(i, _)| *i < u32::BITS as usize && mask & (1u32 << i) != 0)
        .map(|(_, name)| name)
        .collect()
}

fn push_context(out: &mut String, prefix: &str, sid: Sid) {
    out.push_str(prefix);
    match crate::with(|s| s.sid_to_context(sid)) {
        Some(Ok(text)) => out.push_str(&text),
        _ => out.push_str("unknown"),
    }
}

#[cfg(test)]
#[path = "tests/check.rs"]
mod tests;
