// VFS bridge for cgroup v2 per `26§4` + `16§2`. cgroupfs SYNTHESIZES
// its inodes on lookup from the hierarchy in `tree.rs` — it owns no
// registry and has ZERO dependency on devfs. A cgroup directory inode is
// identified by its node id (`cgid`) held in `i_private` (`CgDirData`);
// `lookup`/`iterate` resolve its control files + child cgroups straight
// from the tree, and mkdir/rmdir mutate the tree. Control files are
// `CgFileData` inodes whose read/write route to the tree keyed by
// `(cgid, file)`.
//
// Post-KEYSTONE shape (`16§2`): per-inode state → `i_private`; the
// namespace ops (lookup/mkdir/rmdir) → `impl InodeOps`; the data ops
// (iterate/read/write) → `impl FileOps`; construction via `InodeBuilder`.

use alloc::string::{String, ToString};
use alloc::sync::Arc;

use vfs::inode::{Inode, InodeBuilder, OwnerPersist};
use vfs::inode_ops::{mk_mode, InodeOps};
use vfs::file_ops::FileOps;
use vfs::{DirContext, FileType, Ino, InodeRef, KResult, VfsError};

/// Permission bits of a cgroup DIRECTORY inode. `0o755` (Linux cgroup2 dirs are
/// `drwxr-xr-x`): the owner may create sub-cgroups (`mkdir`) — required for a
/// delegated subtree whose directory was chowned to the target uid.
const CG_DIR_MODE: u16 = 0o755;

/// cgroup2 superblock magic (`linux/magic.h` CGROUP2_SUPER_MAGIC) — the
/// distinct `fsid` for the unified hierarchy so mount-point detection sees
/// the `/sys/fs/cgroup` boundary.
/// Backend-private state (`i_private`) for a cgroup directory: the node id
/// (`cgid`). lookup/iterate resolve against the live hierarchy (`tree.rs`)
/// via the accessors in `lib.rs`.
pub struct CgDirData {
    pub cgid: u64,
}

/// Backend-private state (`i_private`) for a cgroup control file
/// (`cgroup.procs`, `memory.max`, …) bound to `(cgid, file)`. Synthesized
/// on lookup — never registered.
pub struct CgFileData {
    pub cgid: u64,
    pub file: String,
}

/// Stable inode number for a control file — derived from `(cgid, file)` so
/// the same control file keeps one identity across lookups. cgid in the
/// high bits, a hash of the file name in the low bits. # C: O(name)
fn file_ino(cgid: u64, file: &str) -> Ino {
    let mut h: u64 = 0;
    for b in file.bytes() { h = h.wrapping_mul(31).wrapping_add(b as u64); }
    (crate::ids::FILE_INO_BASE + ((cgid << 8) ^ (h & 0xff))) as Ino
}

/// Permission bits for a control file — read-only interface files vs
/// writable knobs (mirrors Linux kernfs cftype `.mode`). # C: O(1)
fn file_perm(file: &str) -> u16 {
    match file {
        "cgroup.controllers" | "cgroup.events" | "cgroup.stat"
        | "cgroup.type" | "pids.current" | "pids.peak" | "pids.events"
        | "memory.current" | "memory.swap.current" | "memory.events"
        | "memory.stat" | "memory.pressure_level" | "cpu.stat" | "io.stat"
        | "cpuset.cpus.effective" | "cpuset.mems.effective" => 0o444,
        _ => 0o644,
    }
}

/// Recover the `cgid` from a cgroup directory inode's `i_private`. # C: O(1)
fn dir_data(inode: &Inode) -> KResult<&CgDirData> {
    inode.private::<CgDirData>().ok_or(VfsError::Einval)
}

/// `inode_operations` for a cgroup directory — lookup/mkdir/rmdir resolve
/// against the live hierarchy (`tree.rs`).
struct CgDirOps;
impl InodeOps for CgDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let cgid = dir_data(inode)?.cgid;
        // A control file of this cgroup → CgFile inode.
        if crate::node_has_file(cgid, name) {
            return Ok(make_cg_file(cgid, name));
        }
        // A child cgroup → CgDir inode.
        if let Some(child) = crate::node_child_id(cgid, name) {
            return Ok(make_cg_dir(child));
        }
        Err(VfsError::Enoent)
    }

    fn mkdir(&self, inode: &Inode, name: &str, _mode: u32, ctx: &vfs::CreateCtx) -> KResult<InodeRef> {
        let cgid = dir_data(inode)?.cgid;
        #[cfg(feature = "debug-cgroup")]
        {
            klog::write_raw(b"[cg] mkdir parent=");
            klog::write_dec_u64(cgid);
            klog::write_raw(b" name=");
            klog::write_raw(name.as_bytes());
            klog::write_raw(b"\n");
        }
        // Stamp the creating task's fsuid/fsgid on the new cgroup (Linux
        // `cgroup_create` uses `current_fsuid`/`current_fsgid`), mapped DOWN
        // through the mount idmap — so a delegated user's sub-cgroups are
        // user-owned and their cgroup.procs is writable without a further chown.
        let id = crate::mkdir_child(cgid, name, ctx.fsuid(), ctx.fsgid())?;
        Ok(make_cg_dir(id))
    }

    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        crate::rmdir_child(dir_data(inode)?.cgid, name)
    }
}

/// `file_operations` for a cgroup directory — `iterate` (readdir) emits the
/// control files then the child cgroups.
struct CgDirFileOps;
impl FileOps for CgDirFileOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let cgid = dir_data(inode)?.cgid;
        // Stable order: control files first, then child cgroups. The
        // offset is an index into that concatenated sequence. The child's real
        // ino (resolved via `lookup` — no lock held here) feeds getdents `d_ino`.
        let files = crate::node_file_names(cgid);
        let kids = crate::node_child_names(cgid);
        let total = files.len() + kids.len();
        let mut idx = ctx.pos as usize;
        while idx < total {
            let next = idx as u64 + 1;
            if idx < files.len() {
                let ino = inode.lookup(files[idx]).map(|i| i.ino()).unwrap_or(0);
                if !ctx.emit(files[idx], ino, FileType::Regular, next) { return Ok(()); }
            } else {
                let name = &kids[idx - files.len()];
                let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
                if !ctx.emit(name, ino, FileType::Directory, next) { return Ok(()); }
            }
            idx += 1;
        }
        Ok(())
    }
}

/// `file_operations` for a cgroup control file — read/write route to the
/// hierarchy keyed by `(cgid, file)`.
struct CgFileFileOps;
impl FileOps for CgFileFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<CgFileData>().ok_or(VfsError::Einval)?;
        let data = crate::read_file(d.cgid, &d.file)?;
        if off as usize >= data.len() { return Ok(0); }
        let n = core::cmp::min(buf.len(), data.len() - off as usize);
        buf[..n].copy_from_slice(&data[off as usize..off as usize + n]);
        Ok(n)
    }

    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let d = inode.private::<CgFileData>().ok_or(VfsError::Einval)?;
        let s = core::str::from_utf8(buf).map_err(|_| VfsError::Einval)?;
        // A cgroup control file takes ONE value per write. Userspace
        // (bash `echo`, GNU `printf`) emits the trailing
        // newline as a SEPARATE write() at a non-zero offset, so the
        // kernel sees `7` then `\n` as two calls. Linux kernfs buffers
        // the whole write and parses once; we parse per-write, so a
        // bare-whitespace chunk would re-parse as an empty value and
        // wrongly EINVAL. A whitespace-only chunk carries no value →
        // no-op success, leaving the preceding value write in effect.
        if s.trim().is_empty() {
            return Ok(buf.len());
        }
        crate::write_file(d.cgid, &d.file, s)?;
        Ok(buf.len())
    }
}

/// `inode_operations` for cgroup control files. Linux cgroupfs is kernfs-backed:
/// O_TRUNC/ftruncate(0) on a writable control file is admitted by VFS readonly
/// gates and does not mean "mutate persistent file length". # C: O(1)
struct CgFileInodeOps;
impl InodeOps for CgFileInodeOps {
    /// # C: O(1)
    fn truncate(&self, _inode: &Inode, _len: u64) -> KResult<()> { Ok(()) }
}

/// `chown(2)` write-through for a cgroup DIRECTORY inode — persists the owner to
/// the hierarchy so it survives the inode being re-synthesized on the next
/// lookup (systemd cgroup delegation). Bound into the inode via
/// [`InodeBuilder::owner_persist`].
struct CgDirOwner {
    cgid: u64,
}
impl OwnerPersist for CgDirOwner {
    /// # C: O(log n)
    fn persist_owner(&self, uid: u32, gid: u32) { let _ = crate::chown_dir(self.cgid, uid, gid); }
}

/// `chown(2)` write-through for a cgroup CONTROL-FILE inode — records a per-file
/// owner override (systemd delegates cgroup.procs/threads/subtree_control this
/// way).
struct CgFileOwner {
    cgid: u64,
    file: String,
}
impl OwnerPersist for CgFileOwner {
    /// # C: O(log n)
    fn persist_owner(&self, uid: u32, gid: u32) { let _ = crate::chown_file(self.cgid, &self.file, uid, gid); }
}

/// Build a cgroup DIRECTORY inode for `cgid`. lookup/iterate resolve against
/// the live hierarchy (`tree.rs`); the owner is read back from the hierarchy so
/// a delegated (chowned) subtree keeps its uid across re-synthesis. # C: O(log n)
pub fn make_cg_dir(cgid: u64) -> InodeRef {
    let ino = (crate::ids::DIR_INO_BASE + cgid) as Ino;
    let (uid, gid) = crate::node_dir_owner(cgid);
    InodeBuilder::new(ino, mk_mode(FileType::Directory, CG_DIR_MODE), Arc::new(CgDirOps), Arc::new(CgDirFileOps))
        .fsid(crate::CGROUP2_SUPER_MAGIC)
        .owner(uid, gid)
        .owner_persist(Arc::new(CgDirOwner { cgid }))
        .private(Arc::new(CgDirData { cgid }))
        .build()
}

/// Build a cgroup CONTROL-FILE inode bound to `(cgid, file)`. read/write route
/// to the hierarchy. The owner is read back from the hierarchy (per-file chown
/// override, else the node's frozen creation owner) so a delegated file stays
/// user-owned. `i_size` is a snapshot of the current content length (the inode
/// is synthesized fresh on every lookup, so the snapshot is live at resolution
/// time); the read path bounds on EOF, not `i_size`. # C: O(content)
pub fn make_cg_file(cgid: u64, file: &str) -> InodeRef {
    let size = crate::read_file(cgid, file).map(|d| d.len()).unwrap_or(0) as u64;
    let (uid, gid) = crate::node_file_owner(cgid, file);
    InodeBuilder::new(file_ino(cgid, file), mk_mode(FileType::Regular, file_perm(file)),
                      Arc::new(CgFileInodeOps), Arc::new(CgFileFileOps))
        .fsid(crate::CGROUP2_SUPER_MAGIC)
        .owner(uid, gid)
        .owner_persist(Arc::new(CgFileOwner { cgid, file: file.to_string() }))
        .size(size)
        .private(Arc::new(CgFileData { cgid, file: file.to_string() }))
        .build()
}
