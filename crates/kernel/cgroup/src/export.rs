// cgroup2's `s_export_op` — the file handle `name_to_handle_at(2)` mints for a
// cgroup and `open_by_handle_at(2)` decodes back.
//
// cgroupfs is kernfs-backed, so its handle is the kernfs one: the 64-bit node
// id, 8 payload bytes, `FILEID_KERNFS`. The width is a userspace contract, not
// an internal choice — the service manager reads a unit's cgroup id with a
// `handle_bytes` of exactly `sizeof(uint64_t)` and does NOT run the
// grow-and-retry protocol, so the VFS-generic 12-byte `(ino, generation)` FID
// answered every one of those calls with EOVERFLOW and made the cgroup id
// unreadable for every unit.
//
// The id is the DIRECTORY's inode number, which is also what `stat(2)` reports,
// so a caller can cross-check the two. Decode inverts cgroupfs's inode-number
// derivation and then verifies the cgroup is still in the hierarchy: an id that
// is gone is ESTALE, never a synthesized inode for a removed cgroup.
//
// A CONNECTABLE handle for a control file is the one shape the 8-byte payload
// cannot carry (it has no room for the parent identity `open_by_handle_at`
// needs to re-derive the file's name), so that case falls back to the generic
// FID, which does. `handle_type` distinguishes the two, so decode is never
// ambiguous. The payload is opaque to userspace and only ever decoded by the
// kernel that minted it.

use alloc::string::String;
use alloc::sync::Arc;

use vfs::export::fid::{Fid, decode_fid, encode_fid_into, encoded_fid_len, fid_len_for_type};
use vfs::export::kernfs_fid::{HANDLE_TYPE_KERNFS, KERNFS_FID_LEN, decode_kernfs_fid,
    encode_kernfs_fid};
use vfs::{Ino, InodeRef, KResult, SbStatFs, SuperBlock};

use crate::fs::CGROUP2_SUPER_MAGIC;
use crate::{ids, inode, tree};

/// `s_op` for the unified cgroup2 hierarchy: `simple_statfs` plus the kernfs
/// handle export.
pub struct CgroupSuperOps;

/// `f_bsize` cgroupfs reports — the VFS default block size, as kernfs sets
/// `s_blocksize = PAGE_SIZE`.
const CG_BLOCK_SIZE: u32 = hal::PAGE_SIZE_BYTES as u32;

impl vfs::SuperOps for CgroupSuperOps {
    /// `simple_statfs`: the cgroup2 magic and a page block size, no block or
    /// inode counts (there is no backing store). # C: O(1)
    fn statfs(&self) -> KResult<SbStatFs> {
        Ok(SbStatFs { f_type: CGROUP2_SUPER_MAGIC, f_bsize: CG_BLOCK_SIZE, ..Default::default() })
    }

    /// Eight bytes for every handle the kernfs codec can carry; the generic
    /// width only for a connectable control file, which needs a parent.
    /// # C: O(1)
    fn export_fid_len(&self, connectable: bool, is_dir: bool) -> u32 {
        if connectable && !is_dir { encoded_fid_len(connectable, is_dir) } else { KERNFS_FID_LEN }
    }

    /// # C: O(1)
    fn export_encode_fh(&self, inode: &InodeRef, parent: Option<(Ino, u32)>, buf: &mut [u8])
        -> (u32, i32)
    {
        match parent {
            Some(p) => encode_fid_into(
                &Fid { ino: inode.ino(), generation: inode.i_generation(), parent: Some(p) }, buf),
            None => encode_kernfs_fid(inode.ino(), buf),
        }
    }

    /// # C: O(1)
    fn export_fid_len_for_type(&self, handle_type: i32) -> Option<u32> {
        if handle_type == HANDLE_TYPE_KERNFS { Some(KERNFS_FID_LEN) }
        else { fid_len_for_type(handle_type) }
    }

    /// # C: O(1)
    fn export_decode_fh(&self, bytes: &[u8], handle_type: i32)
        -> Result<Fid, syscall::errno::Errno>
    {
        if handle_type == HANDLE_TYPE_KERNFS { decode_kernfs_fid(bytes) }
        else { decode_fid(bytes, handle_type) }
    }

    /// Resolve a decoded inode number back to a live cgroup inode.
    ///
    /// cgroupfs synthesizes its inodes on lookup and never keeps them in the
    /// inode cache, so the generic cache-only decode would report ESTALE for
    /// every handle. The number itself is the identity: it folds the cgroup id
    /// (and, for a control file, the file slot) into cgroupfs's own regions,
    /// and the hierarchy says whether that id is still live.
    /// # C: O(log n) + O(controllers) for a control file
    fn fh_to_dentry(&self, _sb: &SuperBlock, ino: Ino, _generation: u32) -> Option<InodeRef> {
        resolve_ino(ino)
    }

    /// The containing cgroup of a decoded directory, for the reconnect walk.
    /// Read from the hierarchy rather than by a `..` readdir, because a cgroup
    /// directory's entries are its control files and children — it emits no
    /// `..` of its own. # C: O(log n)
    fn get_parent(&self, _sb: &SuperBlock, dir: &InodeRef) -> Option<InodeRef> {
        let cgid = crate::cgid_from_dir_inode(dir)?;
        let parent = crate::node_parent(cgid)?;
        Some(inode::make_cg_dir(parent))
    }

    /// cgroupfs decodes what it encodes: the handle carries a cgroup id the
    /// hierarchy can resolve. # C: O(1)
    fn export_can_decode_fh(&self) -> bool { true }

    /// # C: O(1)
    fn show_options(&self) -> String { String::new() }
}

/// Inode number → the cgroup inode it names, or `None` when the number is not
/// cgroupfs's or names a cgroup that is gone.
/// # C: O(log n) + O(controllers) for a control file
fn resolve_ino(ino: Ino) -> Option<InodeRef> {
    if let Some(cgid) = ids::cgid_of_dir_ino(ino) {
        if !crate::node_exists(cgid) { return None; }
        return Some(inode::make_cg_dir(cgid));
    }
    let (cgid, slot) = ids::cgid_slot_of_file_ino(ino)?;
    if !crate::node_exists(cgid) { return None; }
    // The slot is the file's fixed table index, so the name is the one control
    // file of this cgroup whose slot matches. A cgroup that lost the controller
    // owning that file since the handle was minted has no such name — stale.
    let name = crate::node_file_names(cgid).into_iter().find(|f| tree::file_slot(f) == slot)?;
    Some(inode::make_cg_file(cgid, name))
}

#[cfg(test)]
#[path = "export/tests.rs"] mod tests;

/// Build the cgroup2 `s_op`. # C: O(1)
pub fn super_ops() -> Arc<dyn vfs::SuperOps> { Arc::new(CgroupSuperOps) }
