// The ordinary file and directory permission question.

use crate::label::{inode_class, mask_to_av, MAY_MASK};

/// Class and access vector one permission check asks for, or `None` when there
/// is nothing to ask. # C: O(perms)
///
/// An EMPTY mask is an existence test, not an access: `stat` and every
/// resolution step that only needs the object to be there request no
/// permission at all. Asking the policy for zero permissions and treating the
/// answer as a refusal breaks every one of them.
pub fn inode_permission_av(mode: u32, mask: u32) -> Option<(u16, u32)> {
    if mask & MAY_MASK == 0 { return None; }
    let class = inode_class(mode)?;
    Some((class, mask_to_av(mode, mask)))
}
