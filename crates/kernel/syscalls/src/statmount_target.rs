// Request plumbing shared by `statmount(2)` and `listmount(2)`: reading the
// `struct mnt_id_req`, deciding which mount namespace it names, and finding the
// root its paths are rendered against.
//
// UNGATED so the hosted harness can drive both slots against a real mount tree.
// The pieces that genuinely need scheduler / nsfs / fd-table state sit behind
// one cfg-selected child module rather than `#[cfg]` scattered through the
// logic (`docs/07§5`): `kernel` on the kernel target, `hosted` under
// `cargo test`, where there is no current task and a descriptor names nothing.

use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::statmount_abi::{ns_admission, ns_pick, decode_mnt_id_req, req_copy_plan,
    req_size_check, MntIdReq, NsPick, MNT_ID_REQ_SIZE_VER1};

#[cfg(target_os = "oxide-kernel")]
#[path = "statmount_target/kernel.rs"]
mod imp;
#[cfg(not(target_os = "oxide-kernel"))]
#[path = "statmount_target/hosted.rs"]
mod imp;

pub(crate) use imp::{caller_fs_root, current_user_ns, may_admin_ns, mount_of_fd, ns_from_fd,
    user_readable, user_writable};

fn neg(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Read the caller's `struct mnt_id_req` in Linux's order: the size prefix
/// first (so a malformed size is reported before any field is looked at), then
/// the struct, then its argument admission. # C: O(1)
pub(crate) fn read_req(req: u64, by_fd: bool) -> Result<MntIdReq, i64> {
    user_readable(req, 4)?;
    // SAFETY: `req` validated readable for the `struct mnt_id_req` size prefix.
    let size = unsafe { core::ptr::read_unaligned(req as *const u32) };
    req_size_check(size).map_err(neg)?;
    user_readable(req, size as u64)?;
    let (known, tail) = req_copy_plan(size);
    let mut head = [0u8; MNT_ID_REQ_SIZE_VER1 as usize];
    // SAFETY: `req` validated readable for `size` bytes and `known <= size`; a
    // byte copy into a local array needs no alignment.
    unsafe { core::ptr::copy_nonoverlapping(req as *const u8, head.as_mut_ptr(), known); }
    let mut tail_nonzero = false;
    if tail != 0 {
        let mut rest = alloc::vec![0u8; tail];
        // SAFETY: `req` validated readable for `size` bytes; this reads the
        // remainder past the struct this kernel knows, inside that range.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (req + MNT_ID_REQ_SIZE_VER1 as u64) as *const u8, rest.as_mut_ptr(), tail);
        }
        tail_nonzero = rest.iter().any(|b| *b != 0);
    }
    decode_mnt_id_req(&head, tail_nonzero, by_fd).map_err(neg)
}

/// Resolve the mount namespace a request names, applying the admission for a
/// namespace the caller does not live in. # C: O(userns depth)
pub(crate) fn resolve_ns(r: &MntIdReq, listmount: bool) -> Result<u64, i64> {
    let current = vfs::mount::current_ns();
    let pick = ns_pick(r);
    let ns = match pick {
        NsPick::Current => current,
        NsPick::ById => {
            if vfs::mntns::ns_by_id(r.mnt_ns_id).is_none() { return Err(neg(Errno::Enoent)); }
            r.mnt_ns_id
        }
        NsPick::ByFd => ns_from_fd(r.fd)?,
    };
    ns_admission(pick, ns == current, may_admin_ns(ns), listmount).map_err(neg)?;
    Ok(ns)
}

/// Linux `grab_requested_root`: the root the reply's mount points are rendered
/// against. For the caller's OWN namespace that is its `fs_struct` root, so a
/// chrooted caller sees paths in its own frame; for a FOREIGN namespace the
/// caller's root says nothing about a tree it does not live in, so the root is
/// the first mount below that namespace's own root. # C: O(N_ns)
pub(crate) fn requested_root(ns: u64) -> Option<(u64, Arc<vfs::dentry::Dentry>)> {
    if ns == vfs::mount::current_ns() {
        if let Some(p) = caller_fs_root() { return Some(p); }
        let id = vfs::mount::root_mount_id(ns)?;
        return Some((id, vfs::mount::root_dentry_for_mount_id(id)?));
    }
    let root = vfs::mount::root_mount_id(ns)?;
    let child = vfs::mount::mounts_in_ns_snapshot(ns).into_iter()
        .find(|m| m.mnt_id != root && vfs::mount::parent_mnt_id(m) == root)?;
    Some((child.mnt_id, child.mnt_root()?))
}
