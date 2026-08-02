// DevptsFs — first-class devpts filesystem (D36/D37).
//
// Linux mounts devpts as its OWN filesystem at `/dev/pts` with its own
// `super_block` (DEVPTS_SUPER_MAGIC) whose root directory holds `ptmx` plus
// the per-pty slave nodes `/dev/pts/<n>`. This backend gives oxide that
// first-class object: a singleton `DevptsFs` (matching the current single
// global pty namespace — the pair table is global; multi-instance pts
// namespaces are a noted residual) whose `kernfs::PseudoDir` root exposes the
// ptmx node + slaves from THIS fs's root rather than the devfs path registry.
// `mount -t devpts` / `fsopen("devpts")` materialise the real SB via the
// fsmount_common registry. The devfs registry mirror is kept as a fallback so
// the boot /dev/pts setup is non-fatal even when no devpts is mounted.

use alloc::sync::{Arc, Weak};

use kernfs::PseudoDir;
use sync::{Spinlock, TaskList};
use vfs::{InodeRef, SuperBlock};

use crate::ids::{DEVPTS_FSID, DEVPTS_MAGIC};

/// A first-class devpts filesystem instance: its own `kernfs::PseudoDir` root
/// holding `ptmx` + the per-pty slave nodes, surfaced under `DEVPTS_MAGIC` /
/// `DEVPTS_FSID` once the mount engine builds its `SuperBlock`.
pub struct DevptsFs {
    root: Arc<PseudoDir>,
    /// This devpts instance's mount options (Linux `pts_fs_info.mount_opts`).
    /// The pty namespace is global here — one instance backs every devpts mount
    /// — so these are the options of the mount that last supplied any, and a
    /// second mount with different options is a residual recorded in the ledger
    /// rather than a second namespace.
    opts: Spinlock<crate::mount_opts::PtsMountOpts, TaskList>,
}

impl DevptsFs {
    /// Build a fresh instance: an empty `PseudoDir` root seeded with the
    /// per-instance `ptmx` node. Slaves are inserted lazily by
    /// `crate::allocate_pair`. # C: O(1)
    fn new() -> Arc<Self> {
        let root = PseudoDir::new_root(kernfs::dir_ino("/dev/pts"), DEVPTS_FSID);
        root.insert_path("ptmx", crate::inodes::make_pts_ptmx_inode());
        Arc::new(Self { root, opts: Spinlock::new(crate::mount_opts::PtsMountOpts::default()) })
    }

    /// The instance root directory (tree-population entry point). # C: O(1)
    pub fn root_dir(&self) -> &Arc<PseudoDir> { &self.root }

    /// This instance's mount options. # C: O(1)
    pub fn opts(&self) -> crate::mount_opts::PtsMountOpts { *self.opts.lock() }

    /// Install the options a `mount -t devpts` supplied, and re-stamp the
    /// instance `ptmx` node's mode from them — Linux `devpts_fill_super` builds
    /// the node from `opts->ptmxmode`, and `devpts_reconfigure` re-applies it
    /// through `update_ptmx_mode`. # C: O(1)
    pub fn set_opts(&self, opts: crate::mount_opts::PtsMountOpts) {
        *self.opts.lock() = opts;
        if let Some(ptmx) = self.root.lookup_path("ptmx") {
            let _ = ptmx.set_perm(opts.ptmxmode);
        }
    }
}

impl vfs::fs::FileSystem for DevptsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "devpts" }
    /// `DEVPTS_SUPER_MAGIC` — `statfs`/`fstatfs` `f_type`. # C: O(1)
    fn magic(&self) -> u64 { DEVPTS_MAGIC }
    /// Non-`None` directory root: the path walk crosses into the mount and the
    /// post-mount verify accepts it. # C: O(1)
    fn root(&self) -> Option<InodeRef> { Some(self.root.as_inode()) }
    /// Back-stamp the SB (`fill_super`) so the root dir's inodes report the
    /// instance `s_dev`. The slave nodes carry an explicit `DEVPTS_FSID`
    /// override (set at build), so their `st_dev` is the devpts fs id either
    /// way. # C: O(tree)
    fn set_sb(&self, sb: Weak<SuperBlock>) -> vfs::KResult<()> { self.root.set_sb(sb); Ok(()) }
    /// `/proc/mounts` shows the options this mount carries (Linux
    /// `devpts_show_options`), so what is displayed parses back as input.
    /// # C: O(1)
    fn show_options(&self) -> alloc::string::String {
        crate::mount_opts::show_options(&self.opts())
    }
}

/// Process-wide singleton devpts instance. The current pty namespace is global
/// so one `DevptsFs` backs every devpts mount; this keeps the SB's slave set
/// identical to the global pair table.
static DEVPTS_FS: Spinlock<Option<Arc<DevptsFs>>, TaskList> = Spinlock::new(None);

/// The singleton [`DevptsFs`] (lazily created). The fsmount_common registry
/// constructor and `crate::allocate_pair`'s slave mirror both resolve through
/// this, so a mounted devpts SB and the devfs fallback observe the same
/// slaves. # C: O(1) after first.
pub fn devpts_fs() -> Arc<DevptsFs> {
    let mut g = DEVPTS_FS.lock();
    if let Some(fs) = g.as_ref() { return Arc::clone(fs); }
    let fs = DevptsFs::new();
    *g = Some(Arc::clone(&fs));
    fs
}
