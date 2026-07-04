use alloc::string::String;
use alloc::sync::{Arc, Weak};

use sync::{Spinlock, Inode as InodeClass};
use vfs::{CreateCtx, FileType, InodeRef, KResult, VfsError};
use vfs::superblock::SuperBlock;

use super::accounting::TmpfsSb;
use super::dir::{as_dir, dir_parent_of, dir_resolve, make_tmpfs_dir_inode};
use super::file::make_tmpfs_file_inode;
use super::limits::{PG, ROOT_INO};
use super::uapi::TMPFS_MAGIC;

/// # C: O(1)
pub fn init() {}

/// Boot-time round-trip smoke for the tmpfs body: build a fresh instance,
/// create a file in its tree, write/read-back/partial-overwrite.
/// # SAFETY: caller is the boot path; PMM up; pre-userspace.
/// # C: O(1)
pub fn smoke_test() {
    use hal::kassert;
    let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), TmpfsSb::unlimited());
    let inode = root.create_child(".smoke", 0o644, &CreateCtx::root()).expect("tmpfs.create");
    let n = inode.write(0, b"shell-test").expect("tmpfs.write");
    kassert!(n == 10, "tmpfs write len");
    let mut buf = [0u8; 16];
    let n = inode.read(0, &mut buf).expect("tmpfs.read");
    kassert!(n == 10, "tmpfs read len");
    kassert!(&buf[..10] == b"shell-test", "tmpfs round-trip body");
    // Re-write at offset 5 to validate partial overwrite.
    let _ = inode.write(5, b"WORK").expect("tmpfs.write part");
    let n = inode.read(0, &mut buf).expect("tmpfs.read 2");
    kassert!(&buf[..n] == b"shellWORKt", "tmpfs partial overwrite");
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[INFO]  tmpfs-smoke: ok\n");
    }
}

/// One mounted tmpfs instance. Owns its OWN inode tree (`root: TmpfsDir`)
/// under its SuperBlock — there is no shared global registry. TARGET-INDEPENDENT
/// (no baked mount path): every write op is mount-relative — the per-component
/// i_op path (`create_child`/`unlink_child`/`link_child`/`rename_child` via the
/// resolved parent inode) needs no path, and the whole-path `FileSystem`
/// fallbacks address the tree from the SB root with the leading `/` stripped.
/// Built fresh per mount by [`TmpfsFs::new`]; identical at `/` and `/run`.
pub struct TmpfsFs {
    root:       InodeRef,
    sb:         Spinlock<Weak<SuperBlock>, InodeClass>,
    /// Per-instance space accounting (block/inode limits + usage). # D33
    acct:       Arc<TmpfsSb>,
}

impl TmpfsFs {
    /// A fresh empty tmpfs instance with Linux-default limits (half of RAM).
    /// `name` is informational only (no mount path is baked into the SB — the
    /// tree is target-independent); `set_sb` stamps `s_dev` at `fill_super`,
    /// after which children derive `fsid` from it. # C: O(1)
    pub fn new(name: String) -> Arc<Self> {
        Self::with_limits(name, TmpfsSb::default_limits())
    }
    /// As [`TmpfsFs::new`] but with explicit accounting (the hook a future
    /// `mount -o size=,nr_inodes=` parser fills — the syscall layer that parses
    /// the option string is the only remaining piece, cross-lane). `_name` is
    /// ignored for SB identity (target-independent). # C: O(1)
    pub fn with_limits(_name: String, acct: Arc<TmpfsSb>) -> Arc<Self> {
        acct.charge_inode(); // the root inode itself counts (Linux shmem)
        let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), acct.clone());
        Arc::new(Self { root, sb: Spinlock::new(Weak::new()), acct })
    }
    /// This instance's root inode (`sb->s_root->d_inode`), handed to
    /// `register_bind` so the path walk crosses into the tree. # C: O(1)
    pub fn root_inode(&self) -> InodeRef { self.root.clone() }
}

impl vfs::fs::FileSystem for TmpfsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "tmpfs" }
    /// TMPFS_MAGIC (linux/magic.h). # C: O(1)
    fn magic(&self) -> u64 { TMPFS_MAGIC }
    /// tmpfs block size = page size (statfs `f_bsize`). # C: O(1)
    fn block_size(&self) -> u32 { PG as u32 }
    /// This instance's root inode (mount table per-mount root). # C: O(1)
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
    /// Install live tmpfs space accounting as this SB's `s_op` so `statfs(2)`/
    /// `df` report real `f_blocks`/`f_bfree`/`f_files`/`f_ffree` (D33/D6). # C: O(1)
    fn super_ops(&self) -> Option<Arc<dyn vfs::SuperOps>> {
        Some(Arc::new(TmpfsSuperOps { acct: self.acct.clone() }))
    }

    /// `fill_super` back-stamp: record the SB so the root + every child
    /// derives `fsid` from `s_dev` (per-instance, not a constant). # C: O(1)
    fn set_sb(&self, sb: Weak<SuperBlock>) {
        *self.sb.lock() = sb.clone();
        if let Some(d) = as_dir(&self.root) { d.set_sb(sb); }
    }

    /// `open(O_CREAT)`: return the existing inode or create a regular file in
    /// the tree (lookup-or-create). `path` is mount-absolute. # C: O(components)
    fn create(&self, path: &str, mode: u32) -> vfs::fs::KResult<vfs::InodeRef> {
        let rel = path.trim_start_matches('/');
        if let Some(i) = dir_resolve(&self.root, rel) { return Ok(i); }
        let (p, name) = dir_parent_of(&self.root, rel).ok_or(VfsError::Enoent)?;
        p.create_child(name, mode, &CreateCtx::root())
    }

    /// `O_TMPFILE`: a fresh in-memory inode with no directory entry — reclaimed
    /// when its last fd closes (Linux shmem anonymous inode). It carries this
    /// instance's SB so `fsid` is the mount's `s_dev`. # C: O(1)
    fn create_anonymous(&self, _dir: &str, mode: u32) -> vfs::fs::KResult<vfs::InodeRef> {
        // Blocks the anon inode writes count against this mount (freed on the
        // file's Drop); it has no directory entry so it is not inode-charged.
        Ok(make_tmpfs_file_inode(false, (mode & 0o7777) as u16, 0, 0, self.sb.lock().clone(), self.acct.clone()))
    }

    /// `unlink(2)` by whole path (atomic-rename idiom). # C: O(components)
    fn unlink(&self, path: &str) -> vfs::fs::KResult<()> {
        let (p, name) = dir_parent_of(&self.root, path.trim_start_matches('/')).ok_or(VfsError::Enoent)?;
        p.unlink_child(name)
    }

    /// Hardlink: add another name in the tree for `target`'s inode. # C: O(components)
    fn link(&self, target: &str, link: &str) -> vfs::fs::KResult<()> {
        let inode = dir_resolve(&self.root, target.trim_start_matches('/')).ok_or(VfsError::Enoent)?;
        self.link_inode(inode, link)
    }

    /// Materialize `inode` at `link` (linkat AT_EMPTY_PATH). # C: O(components)
    fn link_inode(&self, inode: vfs::InodeRef, link: &str) -> vfs::fs::KResult<()> {
        let (p, name) = dir_parent_of(&self.root, link.trim_start_matches('/')).ok_or(VfsError::Enoent)?;
        let dir = as_dir(&p).ok_or(VfsError::Enotdir)?;
        if dir.kids.lock().contains_key(name) { return Err(VfsError::Eexist); }
        inode.inc_nlink(); // a new name for the same inode (Linux inc_nlink)
        dir.insert(name, inode);
        Ok(())
    }

    /// `rename(from, to)` — the editor/package-manager atomic-write idiom:
    /// detach the source from its parent dir, attach it under the dest name.
    /// # C: O(components)
    fn rename(&self, from: &str, to: &str) -> vfs::fs::KResult<()> {
        let (sp, sname) = dir_parent_of(&self.root, from.trim_start_matches('/')).ok_or(VfsError::Enoent)?;
        let (dp, dname) = dir_parent_of(&self.root, to.trim_start_matches('/')).ok_or(VfsError::Enoent)?;
        let sdir = as_dir(&sp).ok_or(VfsError::Enotdir)?;
        let ddir = as_dir(&dp).ok_or(VfsError::Enotdir)?;
        let inode = sdir.remove(sname).ok_or(VfsError::Enoent)?;
        // Replaced destination (plain rename = non-EXCHANGE; RENAME_EXCHANGE
        // routes through `exchange`, which only renames into a vacated temp name
        // and never overwrites a live target). The victim loses its link (Linux
        // `vfs_rename`): drop its in-memory nlink — a directory target is cleared
        // to 0 (loses both its `.` self-link and the parent's reference) — and
        // reclaim its inode charge once no name remains. Mirrors `unlink`.
        if let Some(victim) = ddir.remove(dname) {
            if victim.file_type() == FileType::Directory { victim.set_nlink(0); }
            else { victim.drop_nlink(); }
            if victim.nlink() == 0 { ddir.acct.free_inode(); }
        }
        ddir.insert(dname, inode);
        Ok(())
    }
}

/// `super_operations` for a tmpfs mount: `statfs` reports live per-instance
/// block/inode accounting (Linux `shmem_statfs`), replacing the generic
/// `FsBackedSuperOps` that reported only `f_type`/`f_bsize` (D33/D6). # C: O(1)
pub struct TmpfsSuperOps { acct: Arc<TmpfsSb> }
impl vfs::SuperOps for TmpfsSuperOps {
    /// # C: O(1)
    fn statfs(&self) -> KResult<vfs::SbStatFs> { Ok(self.acct.statfs()) }
}
