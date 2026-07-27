// ext4 `i_op->rename` — Linux `fs/ext4/namei.c` `ext4_rename2` →
// `ext4_rename` / `ext4_cross_rename`. Split out of `special.rs` per `08§7`.
//
// What lives here that did not exist before: the ENOTEMPTY gate on a
// directory destination (without it a rename over a populated directory ran
// `Mount::rmdir`, whose contract is "caller-verified-empty", and freed the
// destination's blocks with its children still linked), the cross-parent `..`
// repoint + parent `i_links_count` fixups for a moved directory, the EMLINK
// ceiling, and the four Linux timestamp stamps.

use alloc::sync::Arc;

use vfs::{FileType, Inode, KResult, VfsError};
use vfs::namei::{RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT};

use super::data::Ext4StatData;
use super::ids::ext4_wrap_ino;
use super::super::ops::{dirent_dt, project_inherit_allows_child};
use super::super::state::RootfsState;
use crate::mount::Mount;

/// `EXT4_LINK_MAX` (`fs/ext4/ext4.h`): the `i_links_count` ceiling a directory
/// may reach by gaining child `..` back-references.
const EXT4_LINK_MAX: u16 = 65000;

/// ext4 whiteout inode: `S_IFCHR` with `WHITEOUT_MODE` (0) permission bits and
/// `WHITEOUT_DEV` (0) — Linux `ext4_whiteout_for_rename`.
const WHITEOUT_MODE: u16 = crate::inode::S_IFCHR;

/// `ext4_empty_dir`: true when `dir` holds nothing but `.` and `..`.
/// # C: O(dir blocks)
pub(crate) fn ext4_empty_dir(mount: &Mount, dir: &crate::inode::Inode) -> bool {
    let bs = mount.sb.block_size as u64;
    let nblocks = ((dir.size + bs - 1) / bs) as u32;
    for blk_idx in 0..nblocks {
        let Ok(blk) = mount.read_file_block(dir, blk_idx) else { break };
        let mut nonempty = false;
        let _ = crate::iter_active(&blk, |e| {
            if e.name.is_empty() || e.name == b"." || e.name == b".." { return true; }
            nonempty = true;
            false
        });
        if nonempty { return false; }
    }
    true
}

/// Resolved sides of one ext4 rename: both parents live on the same mount
/// (the VFS layer already enforced EXDEV) so a single `Mount` serves both.
/// Built by the `i_op->rename` entry AND by the path-based
/// `RootfsState::rename_at`, so both reach the same `..`/nlink/ENOTEMPTY
/// handling instead of maintaining two divergent copies.
pub(crate) struct RenameSides<'a> {
    pub(crate) st: &'a RootfsState,
    pub(crate) from_p: u32,
    pub(crate) to_p: u32,
    pub(crate) target: u32,
    pub(crate) dest_victim: Option<u32>,
}

impl RenameSides<'_> {
    fn mount(&self) -> &Mount { &self.st.mount }
}

/// `ext4_rename2` entry: validate the flag set this filesystem implements,
/// then split plain / EXCHANGE. `RENAME_NOREPLACE` and `RENAME_WHITEOUT` are
/// genuinely supported (the VFS layer resolved NOREPLACE before reaching a
/// backend; WHITEOUT materialises the char-dev marker below).
/// # C: O(dir entries)
pub(crate) fn ext4_rename2(
    inode: &Inode, old_name: &str, new_dir: &Inode, new_name: &str, flags: u32,
) -> KResult<()> {
    if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) != 0 {
        return Err(VfsError::Einval);
    }
    let d = inode.private::<Ext4StatData>().ok_or(VfsError::Eio)?;
    if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
    let nd = new_dir.private::<Ext4StatData>().ok_or(VfsError::Eio)?;
    if !matches!(nd.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
    if !Arc::ptr_eq(&d.st, &nd.st) { return Err(VfsError::Exdev); }

    let (from_p, to_p) = (d.ino, nd.ino);
    let target = d.st.lookup_child_ino(from_p, old_name).ok_or(VfsError::Enoent)?;
    let dest_victim = d.st.lookup_child_ino(to_p, new_name);
    let moved_is_dir = d.st.mount.read_inode(target).map(|i| i.is_dir()).unwrap_or(false);
    let s = RenameSides { st: &d.st, from_p, to_p, target, dest_victim };
    rename_sides(&s, old_name.as_bytes(), new_name.as_bytes(), flags)?;
    // Mirror the on-disk `..` accounting into the two cached VFS directory
    // inodes so `stat(2)`'s `st_nlink` agrees with the image without a
    // re-read (Linux `ext4_dec_count`/`ext4_inc_count` act on the live
    // inodes). EXCHANGE of a mixed pair moves one link the other way.
    if flags & RENAME_EXCHANGE != 0 {
        if from_p != to_p {
            let swapped_is_dir = dest_victim
                .and_then(|v| d.st.mount.read_inode(v).ok()).map(|i| i.is_dir()).unwrap_or(false);
            if moved_is_dir && !swapped_is_dir { inode.drop_nlink(); new_dir.inc_nlink(); }
            if !moved_is_dir && swapped_is_dir { new_dir.drop_nlink(); inode.inc_nlink(); }
        }
    } else if moved_is_dir {
        // A replaced directory victim surrendered the destination's incoming
        // link inside `Mount::rmdir`, so the destination's count already
        // balances the arriving `..` and only the source parent drops one
        // (Linux `simple_rename`'s `drop_nlink(old_dir)` in both branches).
        if dest_victim.is_some() { inode.drop_nlink(); }
        else if from_p != to_p { inode.drop_nlink(); new_dir.inc_nlink(); }
    }
    Ok(())
}

/// Flag-dispatched body shared by `i_op->rename` and the path-based
/// `rename_at`. # C: O(dir entries)
pub(crate) fn rename_sides(s: &RenameSides<'_>, old_name: &[u8], new_name: &[u8], flags: u32) -> KResult<()> {
    // `vfs_rename`: renaming a name onto itself is a no-op success.
    if s.from_p == s.to_p && old_name == new_name { return Ok(()); }
    project_inherit_allows_child(s.mount(), s.to_p, s.target)?;
    if flags & RENAME_EXCHANGE != 0 { cross_rename(s, old_name, new_name) }
    else { plain_rename(s, old_name, new_name, flags & RENAME_WHITEOUT != 0) }
}

/// `ext4_rename`: move `old_name` onto `new_name`, replacing whatever is
/// there. # C: O(dir entries)
fn plain_rename(s: &RenameSides<'_>, from_name: &[u8], to_name: &[u8], whiteout: bool) -> KResult<()> {
    let mount = s.mount();
    let src = mount.read_inode(s.target).map_err(|_| VfsError::Eio)?;
    let ftype = dirent_dt(&src);
    let src_is_dir = src.is_dir();
    let dest_raw = s.dest_victim.and_then(|v| mount.read_inode(v).ok());
    let dest_is_dir = dest_raw.as_ref().map(|i| i.is_dir()).unwrap_or(false);

    // Linux `ext4_rename`: `if (!ext4_empty_dir(new.inode)) return -ENOTEMPTY`.
    // Linux reaches that test only for a directory SOURCE because `may_delete`
    // already answered EISDIR for a non-directory source onto a directory
    // victim; the emptiness test is keyed on the VICTIM here so the path-based
    // `rename_at` API — which has no VFS layer above it — cannot hand a
    // populated directory to `Mount::rmdir`, whose contract is
    // "caller-verified-empty" and which would otherwise free the victim's
    // blocks and inode with its children still linked.
    if dest_is_dir {
        if let Some(dst) = dest_raw.as_ref() {
            if !ext4_empty_dir(mount, dst) { return Err(VfsError::Enotempty); }
        }
    } else if src_is_dir && dest_raw.is_none() && s.to_p != s.from_p {
        // A directory gaining a new parent adds a `..` back-reference to it.
        let to_dir = mount.read_inode(s.to_p).map_err(|_| VfsError::Eio)?;
        if to_dir.links_count >= EXT4_LINK_MAX { return Err(VfsError::Emlink); }
    }

    let dest_quota_released = dest_raw.as_ref().map_or(Ok(false),
        |raw| super::super::quota::pre_release_existing_inode_if_final(s.st, raw))?;
    if whiteout {
        if let Err(e) = super::super::quota::charge_new_inode(s.st, s.from_p, WHITEOUT_MODE, 0, 0) {
            rollback_dest(s, dest_quota_released, dest_raw.as_ref());
            return Err(e);
        }
    }
    let now = vfs::inode_times::realtime_now_ns();
    let cross_dir_move = src_is_dir && s.from_p != s.to_p;
    let rename = mount.run_journaled(|m| {
        if s.dest_victim.is_some() {
            // `Mount::rmdir` also drops `to_p`'s link count for the victim's
            // departing `..`, which is why the moved directory's arrival is
            // accounted separately below.
            if dest_is_dir { m.rmdir(s.to_p, to_name)?; } else { m.unlink(s.to_p, to_name)?; }
        }
        m.dir_link(s.to_p, to_name, s.target, ftype)?;
        m.dir_unlink(s.from_p, from_name)?;
        if whiteout { m.create_mknod(s.from_p, from_name, WHITEOUT_MODE, 0, 0, 0)?; }
        if cross_dir_move {
            // `ext4_rename_dir_prepare`/`_finish` + `ext4_dec_count(old.dir)` /
            // `ext4_inc_count(new.dir)`: the moved directory's `..` follows it.
            m.set_dotdot(s.target, s.to_p)?;
            m.adjust_nlink(s.from_p, -1)?;
            m.adjust_nlink(s.to_p, 1)?;
        }
        m.touch_inode_ctime(s.target, now)?;
        m.touch_inode_mtime_ctime(s.from_p, now)?;
        if s.from_p != s.to_p { m.touch_inode_mtime_ctime(s.to_p, now)?; }
        Ok(())
    });
    if let Err(e) = rename {
        mount.refresh_cached_meta();
        if whiteout {
            let _ = super::super::quota::rollback_new_inode_charge(s.st, s.from_p, WHITEOUT_MODE, 0, 0);
        }
        rollback_dest(s, dest_quota_released, dest_raw.as_ref());
        return Err(super::regular::vfs_error_from_mount(e));
    }
    if let Some(victim_ino) = s.dest_victim {
        if let Some(sb) = s.st.i_sb() {
            if let Some(victim) = sb.ilookup(ext4_wrap_ino(victim_ino)) {
                if dest_is_dir { victim.set_nlink(0); } else { victim.drop_link(); }
            }
        }
        if dest_quota_released { super::super::quota::drop_existing_inode_dquots(s.st, victim_ino); }
    }
    Ok(())
}

/// # C: O(1)
fn rollback_dest(s: &RenameSides<'_>, released: bool, dest_raw: Option<&crate::inode::Inode>) {
    if !released { return; }
    if let Some(raw) = dest_raw {
        let _ = super::super::quota::rollback_existing_inode_release(s.st, raw);
    }
}

/// `ext4_cross_rename` (`RENAME_EXCHANGE`): swap the two existing entries in
/// ONE journaled transaction. Neither inode's link count changes; only the
/// PARENTS' counts move, and only when exactly one of the pair is a directory
/// crossing between different parents (Linux `dir_nlink_delta`).
/// # C: O(dir entries)
fn cross_rename(s: &RenameSides<'_>, from_name: &[u8], to_name: &[u8]) -> KResult<()> {
    let mount = s.mount();
    let bino = s.dest_victim.ok_or(VfsError::Enoent)?;
    project_inherit_allows_child(mount, s.from_p, bino)?;
    let src = mount.read_inode(s.target).map_err(|_| VfsError::Eio)?;
    let dst = mount.read_inode(bino).map_err(|_| VfsError::Eio)?;
    let (src_is_dir, dst_is_dir) = (src.is_dir(), dst.is_dir());
    let now = vfs::inode_times::realtime_now_ns();
    let cross = s.from_p != s.to_p;
    mount.run_journaled(|m| {
        m.dir_unlink(s.from_p, from_name)?;
        m.dir_unlink(s.to_p, to_name)?;
        m.dir_link(s.from_p, from_name, bino, dirent_dt(&dst))?;
        m.dir_link(s.to_p, to_name, s.target, dirent_dt(&src))?;
        if cross {
            if src_is_dir { m.set_dotdot(s.target, s.to_p)?; }
            if dst_is_dir { m.set_dotdot(bino, s.from_p)?; }
            // `ext4_update_dir_count`: a delta only exists when the pair is
            // mixed — swapping two directories leaves both counts intact.
            if src_is_dir && !dst_is_dir { m.adjust_nlink(s.from_p, -1)?; m.adjust_nlink(s.to_p, 1)?; }
            if !src_is_dir && dst_is_dir { m.adjust_nlink(s.from_p, 1)?; m.adjust_nlink(s.to_p, -1)?; }
        }
        m.touch_inode_ctime(s.target, now)?;
        m.touch_inode_ctime(bino, now)?;
        m.touch_inode_mtime_ctime(s.from_p, now)?;
        if cross { m.touch_inode_mtime_ctime(s.to_p, now)?; }
        Ok(())
    }).map_err(|_| VfsError::Eio)
}
