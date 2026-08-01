// `open_by_handle_at(2)`'s `acceptable` callback — the reach test the relaxed
// (non-global-capability) decode path substitutes for the path walk it skipped.
//
// Two questions, one walk: could the caller EXPRESS the owner of every inode on
// the way to the decoded object (so the object is not hidden behind an id its
// user namespace has no name for), and — on the bind-mount leg — does that way
// actually pass through the anchor.
//
// The owner compared is the one the MOUNT reports, not the one the filesystem
// stores. An idmapped mount presents `i_uid`/`i_gid` translated through its
// map, so comparing the raw on-disk ids answers a question about a different
// filesystem than the caller is looking at: on a mount that shifts ownership
// into the caller's range, the raw compare rejects a file the caller plainly
// owns, and on one that shifts ownership OUT of it the raw compare accepts a
// file whose owner the caller cannot even name.
//
// Ungated so the hosted suite drives the DECISION (CLAUDE.md phantom-test
// rule); slot 304 supplies the dentries, the mount's idmap and the caller's
// user-namespace membership test.

extern crate alloc;

use alloc::sync::Arc;

use vfs::dentry::Dentry;
use vfs::idmap::{INVALID_ID, Idmap};

use super::DecodeCtx;

/// `privileged_wrt_inode_uidgid` — is this inode's owner, AS THE MOUNT REPORTS
/// IT, an id the caller's user namespace can express?
///
/// `id_mapped` answers the namespace half for an already-translated
/// `(vfsuid, vfsgid)` pair. An inode with no owner to report, and an owner the
/// mount's idmap cannot translate (Linux's `INVALID_VFSUID`), both fail: an
/// owner that cannot be named is not an owner the caller can be shown to
/// out-rank.
/// # C: O(extents)
pub fn inode_owner_reachable<M>(idmap: &Idmap, uid: Option<u32>, gid: Option<u32>, id_mapped: M)
    -> bool
where M: Fn(u32, u32) -> bool
{
    let (Some(uid), Some(gid)) = (uid, gid) else { return false };
    let (vfsuid, vfsgid) = (idmap.map_out_uid(uid), idmap.map_out_gid(gid));
    if vfsuid == INVALID_ID || vfsgid == INVALID_ID { return false; }
    id_mapped(vfsuid, vfsgid)
}

/// The whole `vfs_dentry_acceptable` walk: from `d` up to `anchor`, testing
/// each level's owner when `check_perms` is set, and requiring the anchor to be
/// reached when `check_subtree` is.
///
/// An empty [`DecodeCtx`] (the global-capability holder) accepts everything —
/// that caller could have walked to the object regardless. Reaching a
/// filesystem root without meeting the anchor is acceptable only when
/// containment was not demanded.
/// # C: O(depth * extents)
pub fn dentry_acceptable<M>(ctx: &DecodeCtx, idmap: &Idmap, anchor: &Arc<Dentry>,
                            d: &Arc<Dentry>, id_mapped: M) -> bool
where M: Fn(u32, u32) -> bool
{
    if !ctx.check_perms && !ctx.check_subtree { return true; }
    let mut cur = d.clone();
    loop {
        // The ownership leg is skipped for a caller holding the global
        // capability; the containment leg still runs, because a CONNECTABLE
        // handle is confined to the anchor's subtree whoever presents it.
        if ctx.check_perms {
            let (uid, gid) = match cur.inode() {
                Some(i) => (i.uid(), i.gid()),
                None    => return false,
            };
            if !inode_owner_reachable(idmap, uid, gid, &id_mapped) { return false; }
        }
        if Arc::ptr_eq(&cur, anchor) { return true; }
        match cur.parent() {
            Some(p) => cur = p.clone(),
            None    => return !ctx.check_subtree,
        }
    }
}
