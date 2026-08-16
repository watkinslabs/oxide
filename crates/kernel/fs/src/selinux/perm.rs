// The inode permission check the VFS calls, and its installation.

use selinux_runtime::inode::inode_permission_av;

use vfs::{InodeRef, KResult, VfsError};

/// Label-based permission over one inode. # C: O(1) cached
///
/// Allows when the module has no policy, when the request asks for no
/// permission at all, and when the object has no resolvable label — none of
/// those is a decision the policy has made, and turning any of them into a
/// refusal would refuse work the policy permits.
pub fn inode_permission(inode: &InodeRef, mask: u32) -> KResult<()> {
    if !selinux_runtime::active() { return Ok(()); }
    let Some((class, av)) = inode_permission_av(inode.i_mode() as u32, mask) else { return Ok(()) };
    let Some(isid) = super::label::inode_sid(inode) else { return Ok(()) };
    let ssid = selinux_runtime::task::current_sid();
    selinux_runtime::check::has_perm(ssid, isid, class, av).map_err(|_| VfsError::Eacces)
}

/// Install the check into the VFS permission path. # C: O(1)
pub fn install() { vfs::set_inode_mac_hook(inode_permission); }
