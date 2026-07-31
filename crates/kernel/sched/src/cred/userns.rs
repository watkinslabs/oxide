// The user-namespace id boundary for the credential syscalls (Linux
// `make_kuid`/`make_kgid` on every uid/gid ARGUMENT, `from_kuid_munged`/
// `from_kgid_munged` on every uid/gid RESULT).
//
// `Task::creds` stores INTERNAL ids — Linux `kuid_t`/`kgid_t`. That is what
// the VFS compares against an inode owner, what the signal permission check
// compares between tasks, and what `/proc` renders through each reader's own
// namespace. The numbers userspace passes and receives are namespace-relative
// and only equal the internal ones inside the initial namespace, whose map is
// the identity. Translating anywhere but this boundary would give a task in a
// user namespace two disagreeing identities.
//
// A task with no namespace set (kthreads, hosted fixtures) is treated as the
// initial namespace: identity in both directions.
//
// The capability gate of this family is `ns_capable_setid(cred->user_ns, …)`
// — the TARGET namespace is the caller's OWN, so Linux's ancestry walk exits
// on its first iteration and the check reduces exactly to "is this bit raised
// in the effective set". `Task::has_cap` is therefore the complete check
// here, not an approximation of one; only a gate naming a FOREIGN namespace
// (mount, network, `setns`) needs the walk.

use namespace_identity::NamespaceKind;
use user_namespace::IdMapKind;

use crate::Task;

/// Map a uid/gid argument to its internal id. `None` is Linux's
/// `INVALID_UID` — the caller turns that into `EINVAL` (or, for the
/// `set*id` family's `-1`, into "leave unchanged" BEFORE calling here).
/// # C: O(extents); # Lk: Namespace
pub(crate) fn to_host(cur: &Task, kind: IdMapKind, ns_id: u32) -> Option<u32> {
    let Some(owner) = cur.namespace_owner(NamespaceKind::User) else {
        return identity_to_host(ns_id);
    };
    match user_namespace::resolve_to_host(&owner, kind, ns_id) {
        Ok(host) => host,
        Err(_) => identity_to_host(ns_id),
    }
}

/// Map an internal id to the number this task's userspace can name.
/// Unmapped munges to the overflow id, exactly as `from_kuid_munged` does.
/// # C: O(extents); # Lk: Namespace
pub(crate) fn to_ns(cur: &Task, kind: IdMapKind, host_id: u32) -> u32 {
    let Some(owner) = cur.namespace_owner(NamespaceKind::User) else { return host_id; };
    user_namespace::resolve_to_ns(&owner, kind, host_id).unwrap_or(host_id)
}

/// Linux `make_kuid(ns, 0)` — the internal id of the SUPERUSER inside this
/// task's user namespace, which is what `cap_emulate_setxuid` compares the
/// uid triple against. `None` when the namespace maps no id 0 at all, in
/// which case no uid can be its root and the juggle never fires.
/// # C: O(extents); # Lk: Namespace
pub(crate) fn root_uid(cur: &Task) -> Option<u32> { to_host(cur, IdMapKind::Uid, ROOT_NS_ID) }

/// Namespace-relative id of the superuser. # C: O(1)
const ROOT_NS_ID: u32 = 0;

/// Identity translation for a task outside the namespace model. The
/// `(uid_t)-1` sentinel is unmapped even under the identity map, so it stays
/// `None` here too. # C: O(1)
fn identity_to_host(ns_id: u32) -> Option<u32> {
    if ns_id == user_namespace::INVALID_ID { None } else { Some(ns_id) }
}

/// Linux `make_kuid(current_user_ns(), id)` for a uid ARGUMENT that names a
/// FILESYSTEM owner (the `chown(2)` family) rather than a process credential.
/// `None` is `INVALID_UID`, which `setattr_vfsuid` reports as `EINVAL` — an id
/// the caller's user namespace does not map has no internal identity and must
/// never be stored as an owner. The `(uid_t)-1` "leave unchanged" sentinel is
/// resolved by the caller BEFORE this point.
/// # C: O(extents); # Lk: Namespace
pub fn make_kuid(ns_id: u32) -> Option<u32> {
    match crate::current() { Some(cur) => to_host(cur, IdMapKind::Uid, ns_id), None => identity_to_host(ns_id) }
}

/// `make_kgid(current_user_ns(), id)` — the gid half of [`make_kuid`].
/// # C: O(extents); # Lk: Namespace
pub fn make_kgid(ns_id: u32) -> Option<u32> {
    match crate::current() { Some(cur) => to_host(cur, IdMapKind::Gid, ns_id), None => identity_to_host(ns_id) }
}
