// Namespace resolution of the `quotactl` id argument.
//
// The `qid_t` a caller passes is expressed in the CALLER's user namespace and
// must be resolved before any of it is used:
//
//   * the permission ladder's "you may query the dquot you own" exemption
//     compares the resolved identity against the caller's own effective
//     credentials, so it has to run in the same id space;
//   * the command itself additionally requires that identity to be nameable by
//     the TARGET filesystem, whose ids live in its own `s_user_ns` — an id
//     that filesystem cannot express is `EINVAL`.
//
// Ordering matters and is fixed: permission FIRST, mapping SECOND. An
// unprivileged caller naming an unmappable id gets `EPERM`, not a disclosure
// that the id is out of range.

use syscall::errno::Errno;

use super::eno;

/// One resolved `quotactl` id argument. # C: O(extents)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct QuotaIdArg {
    resolved: Option<vfs::Kqid>,
}

impl QuotaIdArg {
    /// Resolve a raw `qid_t` through the caller's user namespace. # C: O(extents)
    pub(super) fn resolve<H: core::ops::Deref<Target = namespace_identity::Namespace>>(
        caller_ns: &H, kind: vfs::QuotaType, id: u64) -> Self
    {
        Self { resolved: vfs::make_kqid(caller_ns, kind, id as u32) }
    }

    /// Identity for the permission ladder. An argument the caller's namespace
    /// cannot name yields the invalid id, which equals no credential and so
    /// falls through to the capability rung. # C: O(1)
    pub(super) fn auth_id(&self) -> u32 {
        self.resolved.map_or(vfs::INVALID_QUOTA_ID, |qid| qid.id)
    }

    /// Identity to operate on, or the errno for an argument neither the caller
    /// nor the target filesystem can name. # C: O(extents)
    pub(super) fn kqid(&self, sb: &vfs::SuperBlock) -> Result<vfs::Kqid, i64> {
        let qid = self.resolved.ok_or_else(|| eno(Errno::Einval))?;
        if !vfs::qid_has_mapping(&sb.s_user_ns, qid) { return Err(eno(Errno::Einval)); }
        Ok(qid)
    }
}

/// Report an internal identity back through the caller's namespace
/// (`from_kqid`). An identity the caller cannot name is reported as the
/// invalid id rather than as whatever account the overflow id happens to
/// name. # C: O(extents)
pub(super) fn report_id<H: core::ops::Deref<Target = namespace_identity::Namespace>>(
    caller_ns: &H, qid: vfs::Kqid) -> u32
{
    vfs::from_kqid(caller_ns, qid).unwrap_or(vfs::INVALID_QUOTA_ID)
}

/// The caller's namespace plus the identity its `qid_t` argument resolved to.
/// The two always travel together: an id means nothing without the namespace
/// that named it, and the report path needs the same namespace to name it
/// back. # C: O(1)
pub(super) struct QuotaIdCtx {
    caller_ns: namespace_identity::NamespacePin,
    arg: QuotaIdArg,
}

impl QuotaIdCtx {
    /// Resolve `id` in `caller_ns`. # C: O(extents)
    pub(super) fn new(caller_ns: namespace_identity::NamespacePin, kind: vfs::QuotaType, id: u64)
        -> Self
    {
        let arg = QuotaIdArg::resolve(&caller_ns, kind, id);
        Self { caller_ns, arg }
    }

    /// Resolve `id` in the INITIAL user namespace, whose maps are the
    /// identity — the id space of a caller that is not in any container.
    /// Only the hosted harnesses build a context this way; the kernel always
    /// has a calling task and reads ITS namespace. # C: O(1)
    #[cfg(not(target_os = "oxide-kernel"))]
    pub(super) fn initial(kind: vfs::QuotaType, id: u64) -> Self {
        Self::new(namespace_identity::initial(namespace_identity::NamespaceKind::User).pin(), kind, id)
    }

    /// Identity for the permission ladder. # C: O(1)
    pub(super) fn auth_id(&self) -> u32 { self.arg.auth_id() }

    /// Identity to operate on, or the errno for an unnameable argument.
    /// # C: O(extents)
    pub(super) fn kqid(&self, sb: &vfs::SuperBlock) -> Result<vfs::Kqid, i64> {
        self.arg.kqid(sb)
    }

    /// Name an internal identity back in the caller's namespace. # C: O(extents)
    pub(super) fn report(&self, qid: vfs::Kqid) -> u32 { report_id(&self.caller_ns, qid) }
}

/// User namespace the calling task's ids are expressed in
/// (`current_user_ns()`). A task with no user namespace recorded falls back to
/// the initial one, whose maps are the identity. # C: O(1)
pub(super) fn caller_user_ns(cur: &sched::Task) -> namespace_identity::NamespacePin {
    cur.namespace_owner(namespace_identity::NamespaceKind::User)
        .map(|ns| ns.pin())
        .unwrap_or_else(|| namespace_identity::initial(namespace_identity::NamespaceKind::User).pin())
}
