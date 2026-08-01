// Namespace translation for quota identities (Linux `make_kqid`,
// `qid_valid`, `qid_has_mapping`, `from_kqid`, `from_kqid_munged`).
//
// A [`Kqid`] holds an INTERNAL id — the same space `Inode::uid`/`gid` and the
// on-disk quota files use — never a namespace-relative one. The two edges of
// the quota ABI are therefore:
//
//   IN  — a `qid_t` argument arrives expressed in the CALLER's user namespace.
//         [`make_kqid`] resolves it; an id no extent covers is `INVALID` and
//         its command fails with `EINVAL`, never falling through to the
//         overflow id (which would charge or report an unrelated account).
//   OUT — an id leaves through [`from_kqid_munged`], expressed in the caller's
//         namespace, unmapped ids munged to the overflow id.
//
// A command is additionally refused when the resolved identity has no mapping
// in the TARGET filesystem's `s_user_ns` ([`qid_has_mapping`]): that
// filesystem cannot name the account at all, so neither reading nor writing
// its limits is meaningful.

use namespace_identity::Namespace;
use user_namespace::{is_mapped, resolve_to_host, resolve_to_ns, IdMapKind};

use super::ids::{Kqid, QuotaType};

/// Id-map this quota class translates through. Project ids have their own map,
/// independent of uid and gid. # C: O(1)
pub const fn id_map_kind(kind: QuotaType) -> IdMapKind {
    match kind {
        QuotaType::User => IdMapKind::Uid,
        QuotaType::Group => IdMapKind::Gid,
        QuotaType::Project => IdMapKind::Projid,
    }
}

/// Linux `make_kqid(from, type, id)` with `qid_valid` folded in: resolve a
/// namespace-relative quota id to its internal identity, or `None` when the
/// namespace has no mapping for it (Linux's INVALID kqid). A handle that does
/// not name a user namespace at all also yields `None`. # C: O(extents)
pub fn make_kqid<H: core::ops::Deref<Target = Namespace>>(from: &H, kind: QuotaType, id: u32)
    -> Option<Kqid>
{
    let host = resolve_to_host(from, id_map_kind(kind), id).ok()??;
    Some(Kqid { kind, id: host })
}

/// Linux `from_kqid_munged(to, qid)`: the number `to`'s userspace can name for
/// this identity, unmapped ids munged to the overflow id. # C: O(extents)
pub fn from_kqid_munged<H: core::ops::Deref<Target = Namespace>>(to: &H, qid: Kqid) -> u32 {
    resolve_to_ns(to, id_map_kind(qid.kind), qid.id)
        .unwrap_or_else(|_| id_map_kind(qid.kind).overflow().value())
}

/// Linux `from_kqid(to, qid)`: the number `to`'s userspace can name for this
/// identity, or `None` for Linux's `(qid_t)-1` miss. The report path that
/// echoes an id the FILESYSTEM chose (`Q_GETNEXTQUOTA`) uses this rather than
/// the munged form, so an id the caller's namespace cannot name is reported as
/// the sentinel instead of as account 65534. # C: O(extents)
pub fn from_kqid<H: core::ops::Deref<Target = Namespace>>(to: &H, qid: Kqid) -> Option<u32> {
    if !qid_has_mapping(to, qid) { return None; }
    resolve_to_ns(to, id_map_kind(qid.kind), qid.id).ok()
}

/// Linux `qid_has_mapping(ns, qid)` — `from_kqid(ns, qid) != (qid_t)-1`.
/// Distinct from [`from_kqid_munged`], which cannot tell an unmapped identity
/// from one genuinely mapped to the overflow id. # C: O(extents)
pub fn qid_has_mapping<H: core::ops::Deref<Target = Namespace>>(ns: &H, qid: Kqid) -> bool {
    is_mapped(ns, id_map_kind(qid.kind), qid.id).unwrap_or(false)
}

#[cfg(test)]
mod tests;
