// SELinux's inode-attribute gate, and the label attribute's VALUE.

extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

use selinux_runtime::check::{has_perm, EACCES};
use selinux_runtime::inode::{answers_getsecurity, getsecurity_value, relabel_decision,
                             selinux_xattr_gate, RelabelRequest, XattrGate, XattrOp};
use selinux_runtime::label::inode_class;

use vfs::InodeRef;

/// `-EOPNOTSUPP`: this module does not answer for the attribute, so the
/// filesystem's own store does.
const EOPNOTSUPP: i64 = -(Errno::Eopnotsupp.as_i32() as i64);

/// Access vector asking for nothing; a permission this kernel does not know
/// is never granted rather than silently skipped.
const NO_PERMISSION: u32 = 0;

/// Gate one attribute operation on an inode. # C: O(1) cached
///
/// `value` is the label being written, and is required for a write: the
/// relabel is priced against the label the caller is asking for, so deciding
/// without it would price a different move than the one being made.
pub fn xattr_gate(inode: &InodeRef, name: &str, op: XattrOp, value: Option<&[u8]>)
    -> Result<(), i64>
{
    let gate = selinux_xattr_gate(name, op);
    if !selinux_runtime::active() { return Ok(()); }
    let Some(class) = inode_class(inode.i_mode() as u32) else { return Ok(()) };
    let Some(isid) = super::label::inode_sid(inode) else { return Ok(()) };
    let ssid = selinux_runtime::task::current_sid();
    match gate {
        XattrGate::Refuse => Err(EACCES),
        XattrGate::Perm(perm) => {
            let av = selinux::uapi::classmap::perm_bit(class, perm).unwrap_or(NO_PERMISSION);
            has_perm(ssid, isid, class, av)
        }
        XattrGate::Relabel => relabel(inode, ssid, isid, class, value),
    }
}

/// `selinux_inode_getsecurity` — the label attribute's value, read from the
/// object's IN-CORE label rather than from any attribute store. # C: O(1) cached
///
/// This is what makes the label readable on every filesystem, not only the ones
/// that can store an attribute: the label of a device node, a pipe or a socket
/// lives in the kernel's own inode state, and a mount with no attribute store
/// still has one. Answering such a read from the store instead reports "this
/// filesystem cannot do attributes" for an object that is labelled, and the
/// callers that ask — the login stack among them — treat that as "no label" and
/// carry a null onwards.
///
/// `EOPNOTSUPP` means "not this module's attribute", and is the one answer that
/// sends the read on to the store. A label the loaded policy cannot render is
/// `EINVAL` and stands: falling back there would answer a live label read with
/// whatever stale text the disk happens to hold.
pub fn inode_getsecurity(inode: &InodeRef, suffix: &str) -> Result<Vec<u8>, i64> {
    if !answers_getsecurity(suffix) || !selinux_runtime::active() { return Err(EOPNOTSUPP); }
    // No label to report while the object has no filesystem type or no class
    // the policy names: nothing has been decided for it, so the store answers.
    let Some(sid) = super::label::inode_sid(inode) else { return Err(EOPNOTSUPP) };
    let force = sched::current().is_some_and(|t| t.has_cap(sched::cap::MAC_ADMIN));
    let text = selinux_runtime::with(|s| render_context(force,
        || s.sid_to_context(sid), || s.sid_to_context_force(sid)))
        .ok_or(EOPNOTSUPP)?
        .map_err(|_| -(Errno::Einval.as_i32() as i64))?;
    Ok(getsecurity_value(&text))
}

/// Choose ordinary or raw retained-context rendering at the capability boundary. # C: O(renderer)
fn render_context<T>(force: bool, ordinary: impl FnOnce() -> T, raw: impl FnOnce() -> T) -> T {
    if force { raw() } else { ordinary() }
}

/// Price a label write against the label being written. # C: O(rules)
///
/// A context the policy cannot interpret is `EINVAL` here, unlike one already
/// written on an object: refusing to WRITE a meaningless label costs the
/// caller nothing, while refusing to read an object that already carries one
/// would make the object unreachable.
fn relabel(inode: &InodeRef, ssid: u32, isid: u32, class: u16, value: Option<&[u8]>)
    -> Result<(), i64>
{
    let value = value.ok_or(-(Errno::Einval.as_i32() as i64))?;
    let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
    let written = core::str::from_utf8(&value[..end])
        .map_err(|_| -(Errno::Einval.as_i32() as i64))?;
    let fstype = inode.i_sb().map(|sb| alloc::string::ToString::to_string(sb.s_type.name()));
    let Some(fstype) = fstype else { return Ok(()) };
    let resolved = selinux_runtime::with(|s| {
        let new_sid = s.context_to_sid(written).ok()?;
        Some((new_sid, super::label::superblock_security(s, &fstype).sb_sid))
    }).flatten();
    let Some((new_sid, sb_sid)) = resolved else { return Err(-(Errno::Einval.as_i32() as i64)) };
    let req = RelabelRequest { ssid, old_sid: isid, new_sid, sb_sid, class };
    if !relabel_decision(&req, |c| has_perm(c.ssid, c.tsid, c.class, c.av()).is_ok()) {
        return Err(EACCES);
    }
    // The object's label is about to change, so the cached one is stale.
    // Dropped rather than replaced: the write can still fail below this, and a
    // re-read answers correctly either way.
    inode.clear_security_sid();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::render_context;

    #[test]
    fn cap_mac_admin_alone_selects_the_retained_raw_context() {
        assert_eq!(render_context(false, || "policy", || "raw"), "policy");
        assert_eq!(render_context(true, || "policy", || "raw"), "raw");
    }
}
