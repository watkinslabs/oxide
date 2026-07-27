extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;

use crate::dentry::Dentry;
use crate::namei::group_list::GroupList;
use crate::inode::InodeRef;

pub const MAX_SYMLINK_DEPTH: u32 = 40;

/// Max symlink NESTING depth — Linux historical `MAX_NESTED_LINKS` = 8, the
/// `nd->depth` cap. The number of suspended link-remainder frames stacked at
/// once (a link whose target resolution is still pending an outer remainder).
/// Distinct from [`MAX_SYMLINK_DEPTH`]: nesting is the live stack depth (rises
/// and falls with `put_link`), total is the lifetime follow count. Either cap
/// exceeded is ELOOP (Linux rejects both over-nesting and over-counting).
pub const MAX_NESTED_LINKS: u32 = 8;

/// `MAY_*` access mask bits (Linux `include/linux/fs.h`).
pub const MAY_EXEC:  u32 = 0x01;
pub const MAY_WRITE: u32 = 0x02;
pub const MAY_READ:  u32 = 0x04;

/// Mode bits that carry privilege (Linux `include/uapi/linux/stat.h`).
/// `S_ISUID`/`S_ISGID` are killed on chown of a regular file; `S_ISGID`
/// is killed on chmod when the caller is outside the file's group.
pub const S_ISUID: u16 = 0o4000;
pub const S_ISGID: u16 = 0o2000;
pub const S_IXGRP: u16 = 0o0010;

/// Resolution modifiers (`openat2(2)` RESOLVE_* + LOOKUP_* + O_NOFOLLOW).
#[derive(Clone, Copy, Default)]
pub struct LookupFlags {
    /// O_NOFOLLOW / AT_SYMLINK_NOFOLLOW: a symlink as the FINAL component is
    /// returned as-is rather than followed.
    pub no_follow_final: bool,
    /// LOOKUP_FOLLOW (Linux `fs/namei.c`): explicitly FOLLOW a trailing symlink.
    /// First-class counterpart to `no_follow_final` — when set it OVERRIDES the
    /// no-follow short-circuit so the final symlink is resolved even if
    /// `no_follow_final` is also set (Linux's flag set never holds both, and
    /// LOOKUP_FOLLOW wins where they conflict). DEFAULT OFF: with neither bit set
    /// the walk follows the trailing symlink as before (the historical
    /// `!no_follow_final` default), so this is purely additive. A caller that
    /// needs the Linux "always follow" semantics (stat/`AT_SYMLINK_FOLLOW`,
    /// `linkat` source) sets `follow`; O_NOFOLLOW/`AT_SYMLINK_NOFOLLOW` clear it
    /// and set `no_follow_final`.
    pub follow: bool,
    /// LOOKUP_EMPTY (Linux `AT_EMPTY_PATH`): an EMPTY pathname (`""`) is allowed
    /// and resolves to the dirfd/cwd base itself (the empty component queue ends
    /// the walk at the start position). Without this bit an empty pathname is
    /// `ENOENT` (Linux `filename_lookup`/`path_init`: `-ENOENT` unless
    /// LOOKUP_EMPTY). First-class replacement for the per-`*at`-handler
    /// AT_EMPTY_PATH gate — every path-taking `*at` now gets uniform empty-path
    /// semantics from the engine.
    pub empty: bool,
    /// RESOLVE_NO_SYMLINKS: any symlink anywhere → ELOOP.
    pub no_symlinks: bool,
    /// Confined-root marker (chroot, wired by `pathresolve::resolution_root`):
    /// the walk is scoped to `root`, so `..` cannot ascend above it and an
    /// absolute path / absolute symlink target restarts AT `root` (the clamp is
    /// performed by the `root`-relative `to_root`/`dotdot_step` machinery, so
    /// this field is currently informational). NOTE: Linux's openat2
    /// RESOLVE_BENEATH instead ERRORS `-EXDEV` on an escape attempt rather than
    /// clamping; that distinct behaviour is `beneath_exdev` below.
    pub beneath: bool,
    /// RESOLVE_BENEATH (`openat2(2)`, Linux `LOOKUP_BENEATH`): the START dirfd
    /// is the scoped resolution root and any attempt to escape ABOVE it ERRORS
    /// `EXDEV` rather than clamping (the distinction from the chroot `beneath`
    /// field). Three escapes are rejected: an absolute pathname, a `..` at the
    /// scoped root, and an absolute symlink target. `Nameidata::new` pins the
    /// resolution root to START (like `in_root`), so the boundary is the dirfd.
    pub beneath_exdev: bool,
    /// LOOKUP_DIRECTORY: the final component must resolve to a directory
    /// (else ENOTDIR).
    pub directory: bool,
    /// LOOKUP_PARENT: stop BEFORE the final component; return the parent
    /// directory in `VfsPath` and the leaf name in `VfsPath.last_component`
    /// (the shape mknod/rename/link/create-open need).
    pub parent: bool,
    /// RESOLVE_IN_ROOT: treat the START directory (dirfd) as "/" — `..`,
    /// absolute paths, and absolute symlink targets are all confined to it,
    /// overriding the passed resolution `root` (Linux `nd->root = nd->path`).
    pub in_root: bool,
    /// RESOLVE_NO_MAGICLINKS: magic links (`/proc/self/fd/N`, …) → ELOOP.
    /// The magic-link reopen lives at the open/dup layer (`path::dup_fd_target`),
    /// which gates on this flag; the walker carries it for completeness.
    pub no_magiclinks: bool,
    /// RESOLVE_NO_XDEV (`openat2(2)`): forbid mount-point traversal during
    /// resolution. A component that would descend INTO a mounted filesystem, or
    /// a `..` that would ascend OUT of the current mount, is rejected with
    /// `EXDEV` (Linux `LOOKUP_NO_XDEV`). The START position's own over-mount is
    /// normalised by `Nameidata::new` BEFORE the walk and is exempt — only
    /// crossings made WHILE walking are blocked.
    pub no_xdev: bool,
    /// LOOKUP_REVAL: forced revalidation (Linux's ESTALE-retry walk). Threaded
    /// to each cached dentry's `d_op->d_revalidate` so a fs that trusts an
    /// attribute-cache timeout normally re-checks its backing store on this
    /// pass; set by the retry path after a stale-handle failure.
    pub reval: bool,
    /// RESOLVE_CACHED (`openat2(2)`): resolve ONLY from the dcache — never
    /// invoke a filesystem `i_op->lookup` (which may block on I/O). A dcache
    /// miss that would take the slow path is `EAGAIN`, telling the caller to
    /// retry on a blocking path (Linux `try_to_unlazy`/`LOOKUP_CACHED` →
    /// `-EAGAIN`). A cached NEGATIVE dentry is still a definitive `ENOENT`.
    pub cached: bool,
    /// LOOKUP_RCU (Linux `fs/namei.c`) — OPT-IN lock-free "lazy" walk.
    /// DEFAULT OFF: the proven, D22-validated ref/Arc walk is the
    /// default-correct path. When set, the walk runs in rcu (lazy) mode,
    /// resolving components from the seqcount-gated dcache probe and only
    /// "legitimizing" (taking real references via `unlazy_walk`) at a
    /// complication point (symlink, mount crossing, the final component, a
    /// dcache miss). On ANY uncertainty it falls back to the ref/Arc walk
    /// (`unlazy_walk` failure → restart with rcu cleared), so the rcu mode can
    /// never produce a different result than the Arc walk — it is a pure
    /// fast-path overlay. A later lane flips the default to rcu after boot +
    /// stress; this lane lands it opt-in with the mandatory fallback.
    pub rcu: bool,
}

/// Caller credentials for the VFS permission checks — Linux `struct cred`
/// subset: fsuid/fsgid + supplementary groups + the DAC/owner/chown-bypass
/// capabilities. The vfs crate is task-agnostic, so the cred is threaded in
/// by the caller (the syscall layer supplies the task's via `current_cred()`;
/// `Cred::root()` is the default-allow used by the compat `path_lookup`
/// wrappers and internal resolves).
#[derive(Clone)]
pub struct Cred {
    pub uid: u32,
    pub gid: u32,
    /// CAP_DAC_OVERRIDE: bypass file DAC (dirs always; files iff some exec bit).
    pub cap_dac_override: bool,
    /// CAP_DAC_READ_SEARCH: bypass read + directory-search DAC.
    pub cap_dac_read_search: bool,
    /// CAP_FOWNER: bypass the owner check on chmod / utime / etc.
    pub cap_fowner: bool,
    /// CAP_CHOWN: change file ownership arbitrarily.
    pub cap_chown: bool,
    /// CAP_FSETID: keep S_ISGID across chmod / write by a non-group member.
    pub cap_fsetid: bool,
    /// Supplementary group ids (Linux `cred->group_info`) — the caller's
    /// FULL set, up to `NGROUPS_MAX`.
    pub groups: GroupList,
}

impl Cred {
    /// The all-powerful root cred (default-allow). # C: O(1)
    pub const fn root() -> Self {
        Cred {
            uid: 0, gid: 0,
            cap_dac_override: true, cap_dac_read_search: true,
            cap_fowner: true, cap_chown: true, cap_fsetid: true,
            groups: GroupList::empty(),
        }
    }

    /// True when `gid` is the cred's primary group or one of its
    /// supplementary groups (Linux `in_group_p`). # C: O(ngroups)
    pub fn in_group(&self, gid: u32) -> bool {
        if self.gid == gid { return true; }
        self.groups.contains(gid)
    }
}

impl Default for Cred {
    fn default() -> Self { Cred::root() }
}

/// Linux-style resolved path: a dentry is only meaningful together with the
/// mount that owns it. `inode` is cached from `dentry`/mount crossing for the
/// current lookup result. `last_component` carries the leaf name under
/// LOOKUP_PARENT (else `None`).
#[derive(Clone)]
pub struct VfsPath {
    pub mnt_id: u64,
    pub dentry: Arc<Dentry>,
    pub inode: InodeRef,
    pub last_component: Option<String>,
}

/// Mount syscall target: the final mountpoint dentry plus the parent path's
/// exact mount identity. Linux attaches a mount to `(parent vfsmount, dentry)`;
/// a bare dentry is ambiguous under bind mounts that share dentries.
#[derive(Clone)]
pub struct MountTarget {
    pub parent: VfsPath,
    pub mountpoint: Arc<Dentry>,
}

/// Linux `nd->last_type` (`fs/namei.c`) — the classification of a LOOKUP_PARENT
/// walk's final segment, derived from `VfsPath.last_component`. A caller
/// (`do_rmdir`/`do_unlinkat`/`do_renameat2`) matches on this to reject the
/// dot-forms WITHOUT re-parsing the pathname: `rmdir(".")` → `EINVAL` (`Dot`),
/// `rmdir("..")` → `ENOTEMPTY` (`Dotdot`), removing/renaming the root → `EBUSY`
/// (`Root`). `Norm` is an ordinary name (the only form a create/remove may act
/// on). `Bind` (Linux `LAST_BIND`, a procfs-style magic link as the leaf) is
/// not produced by this walker — magic links are handled at the open/dup layer
/// (`path::dup_fd_target`), so they never surface as a parent-walk leaf here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LastType { Norm, Dot, Dotdot, Root }

/// `i_op->get_link` result (Linux `fs/namei.c get_link`): either the symlink
/// BODY to follow as a path string (`Path`), or a MAGIC-link JUMP target — an
/// already-resolved `(mnt,dentry,inode)` the walk RESETS its current position
/// to (Linux `nd_jump_link`) INSTEAD of splicing a path string. Only magic
/// inodes (`/proc/<pid>/fd/<n>` and friends) produce `Jump`; every ordinary /
/// inline symlink produces `Path`, so the no-magic-link walk is unchanged.
pub enum LinkTarget {
    /// Ordinary symlink body — splice as a new path frame and resolve.
    Path(alloc::vec::Vec<u8>),
    /// Magic-link jump target — reset the walk's `(mnt,dentry,inode)` here.
    Jump(VfsPath),
}

impl VfsPath {
    /// Classify the LOOKUP_PARENT leaf (`last_component`) as Linux `last_type`.
    /// `Root` when there is no leaf — a full (non-PARENT) walk, or a PARENT walk
    /// of `/` whose leaf clamps at the resolution root. # C: O(1)
    pub fn last_type(&self) -> LastType {
        match self.last_component.as_deref() {
            None       => LastType::Root,
            Some(".")  => LastType::Dot,
            Some("..") => LastType::Dotdot,
            Some(_)    => LastType::Norm,
        }
    }
}
