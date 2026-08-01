// `mount_setattr(2)` / `open_tree_attr(2)` kernel-attribute flags and the
// idmap REQUEST decision (Linux `struct mount_kattr.kflags` +
// `build_mount_idmapped`).
//
// Two syscalls share one attribute block but not one policy. `mount_setattr(2)`
// may only INSTALL a first idmap; `open_tree_attr(2)` on a freshly cloned tree
// may also REMOVE or REPLACE one, because that clone has never been reachable
// from any userspace-visible mount namespace. The distinction is a kernel-side
// flag the uapi struct never carries, so it cannot be derived from the
// attribute block alone — it comes from the CALLER.
//
// The removal form is what makes the flag observable: `attr_clr` naming
// MOUNT_ATTR_IDMAP is EINVAL from `mount_setattr(2)` and legal from
// `open_tree_attr(OPEN_TREE_CLONE)`, and when `attr_set` does NOT also name it
// the request resolves to the identity map WITHOUT the `userns_fd` field being
// read at all — so a closed or out-of-range fd in that field is NOT an error.
//
// Deliberately NOT `target_os`-gated: `442_mount_setattr.rs` and
// `467_open_tree_attr.rs` are kernel-only, so a `#[cfg(test)]` block inside
// them never compiles. The per-mount admission ORDER that follows this decision
// belongs to `vfs::mount::can_idmap_mount`, which owns it for both the attached
// and the detached path — this module owns only the request-shaping half that
// runs before any mount is looked at.

use syscall::errno::Errno;
use vfs::mount::MOUNT_ATTR_IDMAP;

/// `AT_RECURSIVE` was requested: the attribute change applies to the whole
/// selected subtree rather than its root mount alone.
pub const MOUNT_KATTR_RECURSE: u32 = 1 << 0;
/// The caller may remove or replace an existing idmap, not merely install a
/// first one. Set only by `open_tree_attr(2)` with `OPEN_TREE_CLONE`.
pub const MOUNT_KATTR_IDMAP_REPLACE: u32 = 1 << 1;

/// Largest `userns_fd` value the attribute block may carry; anything above is
/// EINVAL before the descriptor table is consulted.
const USERNS_FD_MAX: u64 = i32::MAX as u64;

/// `mount_setattr(2)`'s kernel flags: recursion only. The idmap-replace mode is
/// never available to a call that names a path in a live namespace. # C: O(1)
pub fn kflags_for_mount_setattr(at_recursive: bool) -> u32 {
    if at_recursive { MOUNT_KATTR_RECURSE } else { 0 }
}

/// `open_tree_attr(2)`'s kernel flags. `OPEN_TREE_CLONE` produces a mount tree
/// in an anonymous namespace that no other task can reach, which is exactly the
/// precondition idmap replacement requires. `AT_RECURSIVE` carries through to
/// the attribute application exactly as it carried through to the clone.
/// # C: O(1)
pub fn kflags_for_open_tree_attr(clone_tree: bool, at_recursive: bool) -> u32 {
    let mut kflags = 0;
    if clone_tree { kflags |= MOUNT_KATTR_IDMAP_REPLACE; }
    if at_recursive { kflags |= MOUNT_KATTR_RECURSE; }
    kflags
}

/// True when the caller may remove or replace an existing idmap. # C: O(1)
pub fn idmap_replace(kflags: u32) -> bool { kflags & MOUNT_KATTR_IDMAP_REPLACE != 0 }

/// True when the attribute change applies to the whole subtree. # C: O(1)
pub fn recurse(kflags: u32) -> bool { kflags & MOUNT_KATTR_RECURSE != 0 }

/// What the attribute block asks the idmap property to become.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IdmapPlan {
    /// Neither `attr_set` nor `attr_clr` names MOUNT_ATTR_IDMAP: the mount's
    /// idmap is not part of this request.
    Leave,
    /// Removal: the identity map. `userns_fd` is never read.
    Identity,
    /// Install/replace with the map derived from this user-namespace fd.
    FromUserNsFd(i32),
}

/// Shape the idmap request from the attribute block plus the caller's kernel
/// flags, ahead of any descriptor or mount lookup.
///
/// A request naming no idmap bit short-circuits first, so a nonsense
/// `userns_fd` in an otherwise idmap-free block is ignored rather than
/// rejected. `attr_clr` naming the bit is refused outright without the replace
/// mode; with it, `attr_clr` alone resolves to [`IdmapPlan::Identity`] and the
/// fd field stays unread, while `attr_set` alongside it resolves to a normal
/// fd-derived install that overwrites whatever map is already there. # C: O(1)
pub fn build_mount_idmapped(attr_set: u64, attr_clr: u64, userns_fd: u64, kflags: u32)
                            -> Result<IdmapPlan, Errno> {
    if (attr_set | attr_clr) & MOUNT_ATTR_IDMAP == 0 { return Ok(IdmapPlan::Leave); }

    if attr_clr & MOUNT_ATTR_IDMAP != 0 {
        if !idmap_replace(kflags) { return Err(Errno::Einval); }
        if attr_set & MOUNT_ATTR_IDMAP == 0 { return Ok(IdmapPlan::Identity); }
    }

    if userns_fd > USERNS_FD_MAX { return Err(Errno::Einval); }
    Ok(IdmapPlan::FromUserNsFd(userns_fd as i32))
}

#[cfg(test)]
mod tests;
