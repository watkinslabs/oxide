// The `security.*` attribute gate.

extern crate alloc;

use syscall::errno::Errno;

use selinux_runtime::check::{has_perm, EACCES};
use selinux_runtime::inode::{relabel_decision, selinux_xattr_gate, RelabelRequest, XattrGate,
                             XattrOp};
use selinux_runtime::label::inode_class;

use vfs::InodeRef;

/// Access vector asking for nothing; a permission this kernel does not know
/// is never granted rather than silently skipped.
const NO_PERMISSION: u32 = 0;

/// Gate one operation on an inode's `security.*` attribute. # C: O(1) cached
///
/// `value` is the label being written, and is required for a write: the
/// relabel is priced against the label the caller is asking for, so deciding
/// without it would price a different move than the one being made.
pub fn xattr_gate(inode: &InodeRef, name: &str, op: XattrOp, value: Option<&[u8]>)
    -> Result<(), i64>
{
    let gate = selinux_xattr_gate(name, op);
    if matches!(gate, XattrGate::NotOurs) || !selinux_runtime::active() { return Ok(()); }
    let Some(class) = inode_class(inode.i_mode() as u32) else { return Ok(()) };
    let Some(isid) = super::label::inode_sid(inode) else { return Ok(()) };
    let ssid = selinux_runtime::task::current_sid();
    match gate {
        XattrGate::NotOurs => Ok(()),
        XattrGate::Refuse => Err(EACCES),
        XattrGate::Perm(perm) => {
            let av = selinux::uapi::classmap::perm_bit(class, perm).unwrap_or(NO_PERMISSION);
            has_perm(ssid, isid, class, av)
        }
        XattrGate::Relabel => relabel(inode, ssid, isid, class, value),
    }
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
