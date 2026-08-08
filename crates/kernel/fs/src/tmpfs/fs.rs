use alloc::string::String;
use alloc::sync::{Arc, Weak};

use sync::{Spinlock, Inode as InodeClass};
use vfs::{CreateCtx, InodeRef, KResult};
use vfs::superblock::SuperBlock;

use super::accounting::TmpfsSb;
use super::dir::{as_dir, make_tmpfs_dir_inode};
use super::limits::{PG, ROOT_INO};
use super::uapi::TMPFS_MAGIC;

/// Root-inode defaults of a mount that names no `mode=`/`uid=`/`gid=`
/// (`shmem_fill_super`).
const DEFAULT_ROOT_MODE: u16 = 0o755;
const DEFAULT_ROOT_UID: u32 = 0;
const DEFAULT_ROOT_GID: u32 = 0;

/// The privilege facts the option parser judges `noswap` and the quota family
/// against, sampled once per mount so the parse itself stays a pure function.
///
/// A mount with no calling task is the boot path building an in-kernel
/// instance: it has no user namespace to be outside of and no capability set
/// to lack, and it is the most privileged context there is.
/// # C: O(userns depth)
fn current_mount_cred() -> super::mount_opts::MountCred {
    let Some(cur) = sched::current() else { return super::mount_opts::MountCred::KERNEL; };
    let init = namespace_identity::initial(namespace_identity::NamespaceKind::User).pin();
    let in_init_userns = cur.namespace_owner(namespace_identity::NamespaceKind::User)
        .is_some_and(|ns| namespace_identity::NamespacePin::ptr_eq(&ns.pin(), &init));
    super::mount_opts::MountCred {
        in_init_userns,
        sys_admin: nscg::proc_ns::has_cap_for(&cur, &init, sched::cap::SYS_ADMIN),
    }
}

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
    /// Filesystem TYPE identity this instance presents to userspace: the
    /// `/proc/mounts` name and the statfs `f_type`. tmpfs and ramfs share this
    /// in-memory tree but are separate Linux filesystems, and a probe that
    /// keys on `f_type` must be able to tell them apart.
    fsname:     &'static str,
    magic:      u64,
    /// `casefold=` / `strict_encoding`: the name encoding this instance
    /// declares, applied to the superblock at fill-super. A directory folds
    /// case only once it also carries the casefold attribute.
    encoding:   Option<(String, bool)>,
}

impl TmpfsFs {
    /// A fresh empty tmpfs instance with Linux-default limits (half of RAM).
    /// `name` is informational only (no mount path is baked into the SB — the
    /// tree is target-independent); `set_sb` stamps `s_dev` at `fill_super`,
    /// after which children derive `fsid` from it. # C: O(1)
    pub fn new(name: String) -> Arc<Self> {
        Self::with_limits(name, TmpfsSb::default_limits())
    }
    /// As [`TmpfsFs::new`] but with explicit accounting. The root inode keeps
    /// the Linux tmpfs default (mode 0755, owned by 0:0); callers wanting the
    /// `-o mode=/uid=/gid=` root ownership use [`TmpfsFs::from_mount_data`].
    /// `_name` is ignored for SB identity (target-independent). # C: O(1)
    pub fn with_limits(_name: String, acct: Arc<TmpfsSb>) -> Arc<Self> {
        Self::with_root(0o755, 0, 0, acct, "tmpfs", TMPFS_MAGIC)
    }
    /// Build an instance whose ROOT inode has the given `perm`/`uid`/`gid` and
    /// the given accounting, presenting `fsname`/`magic` as its filesystem type.
    /// # C: O(1)
    fn with_root(perm: u16, uid: u32, gid: u32, acct: Arc<TmpfsSb>,
                 fsname: &'static str, magic: u64) -> Arc<Self> {
        Self::with_root_encoding(perm, uid, gid, acct, fsname, magic, None)
    }
    /// As [`TmpfsFs::with_root`], also declaring a name encoding. # C: O(1)
    fn with_root_encoding(perm: u16, uid: u32, gid: u32, acct: Arc<TmpfsSb>,
                          fsname: &'static str, magic: u64,
                          encoding: Option<(String, bool)>) -> Arc<Self> {
        acct.charge_inode(); // the root inode itself counts (Linux shmem)
        let root = make_tmpfs_dir_inode(ROOT_INO, perm, uid, gid, Weak::new(), acct.clone());
        Arc::new(Self { root, sb: Spinlock::new(Weak::new()), acct, fsname, magic, encoding })
    }
    /// Build a tmpfs instance honouring a `mount(2)` `-o` option string
    /// (`data`) — `mode=`/`uid=`/`gid=` set the ROOT inode's permission bits
    /// and owner, `size=`/`nr_blocks=`/`nr_inodes=` set the accounting caps.
    /// This is what the mount-syscall tmpfs constructor calls so, e.g.,
    /// `/run/user/979` mounts mode 0700 owned by 979:979 as pam_systemd and
    /// `systemd --user` require (Linux `shmem_fill_super`). Unspecified options
    /// take the Linux defaults (0755, 0:0, half-RAM). `_name` is informational.
    /// An option this mount cannot be given fails the mount with the option's
    /// own error, rather than mounting a filesystem that quietly ignores it.
    /// # C: O(len(data))
    pub fn from_mount_data(_name: String, data: &str) -> KResult<Arc<Self>> {
        Self::typed_from_mount_data(data, "tmpfs", TMPFS_MAGIC)
    }
    /// `ramfs_fill_super`: the same in-memory tree, but reporting `ramfs` /
    /// `RAMFS_MAGIC` and — like Linux ramfs — no block or inode ceiling, so
    /// `statfs(2)` reports the zero accounting a limit-less fs has.
    ///
    /// ramfs takes `mode=` and nothing else (`ramfs_fs_parameters`), so any
    /// other key here is a key the caller was told does not exist.
    /// # C: O(len(data))
    pub fn ramfs_from_mount_data(data: &str) -> KResult<Arc<Self>> {
        let opts = Self::parse_data(data)?;
        Ok(Self::with_root(
            opts.mode.unwrap_or(DEFAULT_ROOT_MODE),
            opts.uid.unwrap_or(DEFAULT_ROOT_UID),
            opts.gid.unwrap_or(DEFAULT_ROOT_GID),
            TmpfsSb::unlimited(),
            "ramfs", super::uapi::RAMFS_MAGIC,
        ))
    }
    /// # C: O(len(data))
    fn typed_from_mount_data(data: &str, fsname: &'static str, magic: u64) -> KResult<Arc<Self>> {
        let opts = Self::parse_data(data)?;
        let acct = TmpfsSb::from_opts(&opts);
        let encoding = opts.casefold.clone().map(|c| (c, opts.strict_encoding));
        Ok(Self::with_root_encoding(
            opts.mode.unwrap_or(DEFAULT_ROOT_MODE),
            opts.uid.unwrap_or(DEFAULT_ROOT_UID),
            opts.gid.unwrap_or(DEFAULT_ROOT_GID),
            acct, fsname, magic, encoding,
        ))
    }
    /// Parse an option string against the CALLER's privilege. # C: O(len(data))
    fn parse_data(data: &str) -> KResult<super::mount_opts::TmpfsOpts> {
        super::mount_opts::parse_opts(data, TmpfsSb::total_ram_pages(), current_mount_cred())
    }
    /// This instance's root inode (`sb->s_root->d_inode`), handed to
    /// `register_bind` so the path walk crosses into the tree. # C: O(1)
    pub fn root_inode(&self) -> InodeRef { self.root.clone() }
    /// This instance's space accounting, the object every charge point takes.
    /// # C: O(1)
    #[cfg(test)]
    pub(super) fn accounting(&self) -> Arc<TmpfsSb> { self.acct.clone() }
}

impl vfs::fs::FileSystem for TmpfsFs {
    /// # C: O(1)
    fn name(&self) -> &str { self.fsname }
    /// TMPFS_MAGIC / RAMFS_MAGIC (the statfs f_type value), per instance type. # C: O(1)
    fn magic(&self) -> u64 { self.magic }
    /// Both tmpfs and ramfs are user-namespace mountable; Linux shmem/tmpfs,
    /// unlike ramfs, also advertises `FS_ALLOW_IDMAP`. # C: O(1)
    fn fs_flags(&self) -> vfs::fs::FsFlags {
        let mut flags = vfs::fs::FsFlags::FS_USERNS_MOUNT;
        if self.magic == vfs::uapi::TMPFS_SUPER_MAGIC {
            flags |= vfs::fs::FsFlags::FS_ALLOW_IDMAP;
        }
        flags
    }
    /// tmpfs block size = page size (statfs `f_bsize`). # C: O(1)
    fn block_size(&self) -> u32 { PG as u32 }
    /// This instance's root inode (mount table per-mount root). # C: O(1)
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
    /// Install live tmpfs space accounting as this SB's `s_op` so `statfs(2)`/
    /// `df` report real `f_blocks`/`f_bfree`/`f_files`/`f_ffree` (D33/D6). # C: O(1)
    fn super_ops(&self) -> Option<Arc<dyn vfs::SuperOps>> {
        Some(Arc::new(TmpfsSuperOps { acct: self.acct.clone(), magic: self.magic }))
    }

    /// `fill_super` back-stamp: record the SB so the root + every child
    /// derives `fsid` from `s_dev` (per-instance, not a constant). # C: O(1)
    fn set_sb(&self, sb: Weak<SuperBlock>) -> vfs::KResult<()> {
        *self.sb.lock() = sb.clone();
        self.acct.bind_sb(&sb);
        if let Some(d) = as_dir(&self.root) { d.set_sb(sb.clone()); }
        // The quota classes come up before the root inode is charged, so the
        // root counts against its owner exactly as every later inode does.
        if let Some(s) = sb.upgrade() {
            // The encoding is declared before anything can be looked up in the
            // instance, so no dentry is ever hashed by a rule the instance
            // later changes.
            if let Some((charset, strict)) = self.encoding.as_ref() {
                vfs::dentry::casefold::sb_enable_casefold(&s, charset, *strict)?;
            }
            super::quota::enable(&s, &self.acct.quota())?;
            super::quota::charge_existing_inode(&self.acct, &self.root);
        }
        Ok(())
    }

}

/// `super_operations` for a tmpfs mount: `statfs` reports live per-instance
/// block/inode accounting (Linux `shmem_statfs`), replacing the generic
/// fill-super statfs snapshot that reports only `f_type`/`f_bsize` (D33/D6).
/// # C: O(1)
pub struct TmpfsSuperOps { acct: Arc<TmpfsSb>, magic: u64 }
impl vfs::SuperOps for TmpfsSuperOps {
    /// # C: O(1)
    fn statfs(&self) -> KResult<vfs::SbStatFs> { Ok(self.acct.statfs(self.magic)) }
    /// Last-umount teardown drops this instance's quota classes: the records
    /// are the live dquots, so the mount going away is the records going away.
    /// # C: O(N_dq)
    fn put_super(&self) {
        if let Some(sb) = self.acct.quota_sb() { super::quota::disable(&sb); }
    }
}
