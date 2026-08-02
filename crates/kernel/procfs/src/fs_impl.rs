//! `vfs::fs::FileSystem` impl for kernel-side procfs.
//!
//! procfs is fully per-component: its mount root is the `ProcRootInode`
//! singleton (`static_files::proc_root`), and resolution proceeds via
//! `ProcRootInode::lookup` → `ProcPidDirInode::lookup` (`d_lookup →
//! i_op->lookup → d_add`). No whole-path `FileSystem::lookup`.

use alloc::sync::Arc;

/// PROC_SUPER_MAGIC (linux/magic.h) — procfs `f_type`/`s_magic`.
const PROC_SUPER_MAGIC: u64 = 0x9fa0;
/// `PAGE_SIZE` — procfs statfs `f_bsize` (Linux `proc_fill_super` → `s_blocksize
/// = PAGE_SIZE`). # C: O(1)
const PAGE_SIZE: u32 = 4096;

/// FileSystem trait impl. Read-only. The mount table crosses into procfs
/// at `root()` and the namei walker resolves every component below it
/// through the procfs inode tree.
pub struct ProcfsFs {
    /// THIS mount's root inode and identity. One per mount: two `mount -t proc`
    /// calls with different options must give different answers, which is
    /// impossible while they share a root.
    root: vfs::InodeRef,
    info: Arc<crate::fs_info::ProcFsInfo>,
}

impl ProcfsFs {
    /// Build a procfs instance for one mount. # C: O(N static files)
    pub fn new(info: crate::fs_info::ProcFsInfo) -> Self {
        let info = Arc::new(info);
        ProcfsFs { root: crate::static_files::build_root(Arc::clone(&info)), info }
    }

    /// # C: O(1)
    pub fn info(&self) -> &Arc<crate::fs_info::ProcFsInfo> { &self.info }
}

impl Default for ProcfsFs {
    /// An option-less `mount -t proc`, which is every mount the kernel itself
    /// performs. # C: O(N static files)
    fn default() -> Self { ProcfsFs::new(crate::fs_info::ProcFsInfo::default()) }
}

/// `super_operations` for procfs. procfs is a zero-sized pseudo filesystem:
/// `statfs(2)` reports the magic + `PAGE_SIZE` block size and zero block/inode
/// counts (Linux `simple_statfs`, fs/libfs.c, used by `proc_fill_super`).
struct ProcfsSuperOps;
impl vfs::SuperOps for ProcfsSuperOps {
    /// `simple_statfs`: f_type=PROC_SUPER_MAGIC, f_bsize=PAGE_SIZE, all
    /// block/inode counts 0 (f_namelen=NAME_MAX is filled by the syscall layer).
    /// # C: O(1)
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> {
        Ok(vfs::SbStatFs {
            f_type:  PROC_SUPER_MAGIC,
            f_bsize: PAGE_SIZE,
            ..Default::default()
        })
    }

    /// procfs installs no handle-export backend: a procfs inode number is
    /// synthesized from the live object it reflects (a pid, a per-task file)
    /// and is neither stable across that object's lifetime nor resolvable back
    /// to it by number. `name_to_handle_at(2)` therefore reports `EOPNOTSUPP`
    /// here instead of minting a handle whose every `open_by_handle_at(2)`
    /// would be `ESTALE`. # C: O(1)
    fn export_can_decode_fh(&self) -> bool { false }
}

impl vfs::fs::FileSystem for ProcfsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "procfs" }
    /// PROC_SUPER_MAGIC (linux/magic.h).
    /// # C: O(1)
    fn magic(&self) -> u64 { PROC_SUPER_MAGIC }
    /// Linux `fs/proc/root.c` `proc_fill_super`: "User space would break if
    /// executables or devices appear on proc" — `s->s_iflags |= SB_I_NOEXEC |
    /// SB_I_NODEV`. These are also the `required_iflags` `mount_too_revealing`
    /// demands of every `FS_USERNS_MOUNT_RESTRICTED` filesystem; without them a
    /// user-namespace `mount -t proc` is refused outright. # C: O(1)
    fn s_iflags(&self) -> u64 { vfs::superblock::SB_I_USERNS_REQUIRED }
    /// Install zero-sized pseudo-fs statfs (`simple_statfs`) as this SB's `s_op`
    /// so `statfs(2)`/`df` report PROC_SUPER_MAGIC + PAGE_SIZE, not the generic
    /// synthetic figures. # C: O(1)
    fn super_ops(&self) -> Option<Arc<dyn vfs::SuperOps>> { Some(Arc::new(ProcfsSuperOps)) }
    /// `/proc/mounts` shows the options this mount actually carries, in the
    /// reference's spelling, so what is displayed round-trips as input.
    /// # C: O(1)
    fn show_options(&self) -> alloc::string::String {
        crate::fs_info::show_options(&self.info)
    }
    /// Mount root = the `ProcRootInode` singleton. The path walk crosses
    /// into the procfs mount and resolves `/proc/<name>`, `/proc/self`,
    /// `/proc/<pid>/<leaf>`, `/proc/net`, `/proc/sys` per-component via
    /// `ProcRootInode::lookup` + `ProcPidDirInode::lookup` — no whole-path
    /// synthesis.
    /// # C: O(1)
    fn root(&self) -> Option<vfs::InodeRef> { Some(self.root.clone()) }

    /// Publish this mount's identity where the reference keeps it — the
    /// superblock's private slot (`sb->s_fs_info`, read back through
    /// `proc_sb_info`). The root inode carries the same `Arc`, so a lookup that
    /// already has an inode needs no superblock round-trip; this is what lets
    /// code holding only a `SuperBlock` (statfs, show_options, a future
    /// remount) reach the same answers. # C: O(1)
    fn set_sb(&self, sb: alloc::sync::Weak<vfs::SuperBlock>) -> vfs::KResult<()> {
        if let Some(sb) = sb.upgrade() { sb.set_fs_info(Arc::clone(&self.info)); }
        Ok(())
    }
}
