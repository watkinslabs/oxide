//! `path_lookup` per `docs/16§3` — the single component-walking name
//! resolver, structured around a Linux-style `Nameidata`. Walks a path one
//! component at a time via the dcache (`dcache::d_lookup`, (parent,name)-keyed)
//! falling back to `Inode::lookup(name)` + `dcache::d_add`, crosses mount
//! points (switching the current dentry to the mounted superblock's `s_root`
//! — Linux `__follow_mount`), follows symlinks with a depth limit, handles
//! `.`/`..` (incl. `..` across a mount via `follow_dotdot`), checks
//! per-directory search permission (`may_lookup`, MAY_EXEC), and honors
//! dirfd-relative bases + LOOKUP_/RESOLVE_ flags. Returns the final `VfsPath`.
//!
//! THE KEYSTONE (Linux `__follow_mount`): when a resolved component is a
//! mountpoint, the walk replaces its current dentry with the mounted fs's
//! `s_root` DENTRY (not merely re-seating the inode). So `VfsPath.dentry`
//! inside a mount is the mounted-fs dentry, and `..` / path reconstruction are
//! mount-correct. The cascade — keeping `Dentry::absolute_path`, `rel_under`,
//! `parent_by_dentry`, and `descend` global-path-correct under a crossed
//! dentry chain — lives in `dentry.rs` / `mount.rs` (`prepend_path`).
//!
//! Mount crossing is keyed by dentry identity plus mount namespace. The dentry
//! records the covering mount id for each namespace; the mount table owns the
//! mounted root dentry/inode. The walker is otherwise filesystem-agnostic.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::types::{FileType, KResult, VfsError};

/// Max symlinks followed in one resolution (Linux `MAXSYMLINKS` = 40,
/// invariant 5 in `16§1`).
pub const MAX_SYMLINK_DEPTH: u32 = 40;

/// `MAY_*` access mask bits (Linux `include/linux/fs.h`).
pub const MAY_EXEC:  u32 = 0x01;
pub const MAY_WRITE: u32 = 0x02;
pub const MAY_READ:  u32 = 0x04;

/// Resolution modifiers (`openat2(2)` RESOLVE_* + LOOKUP_* + O_NOFOLLOW).
#[derive(Clone, Copy, Default)]
pub struct LookupFlags {
    /// O_NOFOLLOW / AT_SYMLINK_NOFOLLOW: a symlink as the FINAL component is
    /// returned as-is rather than followed.
    pub no_follow_final: bool,
    /// RESOLVE_NO_SYMLINKS: any symlink anywhere → ELOOP.
    pub no_symlinks: bool,
    /// RESOLVE_BENEATH: `..` may not ascend above `root`, and an absolute
    /// symlink target is rejected (Linux EXDEV; surfaced here as ELOOP).
    pub beneath: bool,
    /// LOOKUP_DIRECTORY: the final component must resolve to a directory
    /// (else ENOTDIR).
    pub directory: bool,
    /// LOOKUP_PARENT: stop BEFORE the final component; return the parent
    /// directory in `VfsPath` and the leaf name in `VfsPath.last_component`
    /// (the shape mknod/rename/link/create-open need).
    pub parent: bool,
    /// RESOLVE_IN_ROOT: treat `root` as "/" for absolute restarts + `..`
    /// (`..` and absolute symlink targets are confined to `root`).
    pub in_root: bool,
    /// RESOLVE_NO_MAGICLINKS: magic links (`/proc/self/fd/N`, …) → ELOOP.
    /// The magic-link reopen lives at the open/dup layer (`path::dup_fd_target`),
    /// which gates on this flag; the walker carries it for completeness.
    pub no_magiclinks: bool,
}

/// Caller credentials for `may_lookup` permission checks — Linux `struct cred`
/// subset: fsuid/fsgid + the two DAC-bypass capabilities. The vfs crate is
/// task-agnostic, so the cred is threaded in by the caller (the syscall layer
/// supplies the task's; `Cred::root()` is the default-allow used by the compat
/// `path_lookup` wrappers and internal resolves).
#[derive(Clone, Copy)]
pub struct Cred {
    pub uid: u32,
    pub gid: u32,
    /// CAP_DAC_OVERRIDE: bypass file DAC (dirs always; files iff some exec bit).
    pub cap_dac_override: bool,
    /// CAP_DAC_READ_SEARCH: bypass read + directory-search DAC.
    pub cap_dac_read_search: bool,
}

impl Cred {
    /// The all-powerful root cred (default-allow). # C: O(1)
    pub const fn root() -> Self {
        Cred { uid: 0, gid: 0, cap_dac_override: true, cap_dac_read_search: true }
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

/// `generic_permission` (Linux `fs/namei.c`) for the access `mask`. Inodes
/// with no per-fs perm info (`perm() == None`: pseudo-fs / synthetic) are
/// default-allow, preserving the pre-permission behaviour. # C: O(1)
fn permission(inode: &InodeRef, mask: u32, cred: &Cred) -> KResult<()> {
    let Some(mode) = inode.perm() else { return Ok(()); };
    let mode = mode as u32;
    let uid = inode.uid().unwrap_or(0);
    let gid = inode.gid().unwrap_or(0);
    let granted = if cred.uid == uid {
        (mode >> 6) & 0o7
    } else if cred.gid == gid {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };
    if granted & mask == mask { return Ok(()); }
    let is_dir = matches!(inode.file_type(), FileType::Directory);
    // CAP_DAC_OVERRIDE: dirs always; non-dir exec only if some exec bit set.
    if cred.cap_dac_override
        && (is_dir || mask & MAY_EXEC == 0 || (mode & 0o111) != 0) {
        return Ok(());
    }
    // CAP_DAC_READ_SEARCH: read + directory search (not write).
    if cred.cap_dac_read_search && mask & MAY_WRITE == 0 && (is_dir || mask & MAY_EXEC == 0) {
        return Ok(());
    }
    Err(VfsError::Eacces)
}

/// `may_lookup` (Linux): search permission (MAY_EXEC) on a directory before
/// resolving a component within it. # C: O(1)
fn may_lookup(inode: &InodeRef, cred: &Cred) -> KResult<()> {
    permission(inode, MAY_EXEC, cred)
}

/// Follow stacked mountpoints DOWN from `d`: while `d` is a mountpoint, switch
/// to the mounted fs's `s_root` dentry (Linux `__follow_mount`). Returns the
/// final dentry, its inode, and the deepest crossed mount id. # C: O(stack)
fn follow_mount_down(mut d: Arc<Dentry>, mut mnt_id: u64, ns: u64) -> KResult<(Arc<Dentry>, InodeRef, u64)> {
    while let Some(id) = d.mounted_mount(ns) {
        match crate::mount::root_dentry_for_mount_id(id) {
            Some(sr) => { d = sr; mnt_id = id; }
            None => break,
        }
    }
    let inode = d.inode().ok_or(VfsError::Enoent)?;
    Ok((d, inode, mnt_id))
}

/// `..` step with `follow_dotdot` mount-crossing (Linux). Clamps at the
/// resolution root (`/.. == /`, chroot/BENEATH/IN_ROOT confinement). At a
/// mounted fs root that is not the resolution root, cross back to the
/// mountpoint in the parent mount (looping for stacked roots), THEN take the
/// normal parent step. # C: O(stack)
fn dotdot_step(
    cur_dentry: &mut Arc<Dentry>,
    cur_mnt: &mut u64,
    cur_inode: &mut InodeRef,
    root_dentry: &Arc<Dentry>,
    root_mnt: u64,
) {
    loop {
        if Arc::ptr_eq(cur_dentry, root_dentry) { return; }
        if cur_dentry.is_root() && *cur_mnt != root_mnt {
            if let Some((mp, parent_mnt)) = crate::mount::mountpoint_of(*cur_mnt) {
                *cur_dentry = mp;
                *cur_mnt = parent_mnt;
                if let Some(i) = cur_dentry.inode() { *cur_inode = i; }
                continue;
            }
        }
        break;
    }
    if let Some(par) = cur_dentry.parent() {
        let par = par.clone();
        if let Some(pi) = par.inode() { *cur_inode = pi; *cur_dentry = par; }
    }
}

/// Linux `struct nameidata` — the walk's mutable resolution state: current
/// `(mnt, dentry, inode)` position, the resolution root (chroot / IN_ROOT /
/// BENEATH base), the symlink-nesting `depth`, the policy `flags`, and the
/// caller `cred` for `may_lookup`. Built by `path_lookup*`; driven by `walk`.
pub struct Nameidata {
    pub cur_mnt_id: u64,
    pub cur_dentry: Arc<Dentry>,
    pub cur_inode: InodeRef,
    pub root_mnt_id: u64,
    pub root_dentry: Arc<Dentry>,
    pub depth: u32,
    pub flags: LookupFlags,
    pub cred: Cred,
}

impl Nameidata {
    /// Build the walk state from a `start` (dirfd/cwd base) and a resolution
    /// `root`. Both are normalised through any mountpoint they sit on (Linux
    /// holds `(vfsmount, dentry)`; a covered base resolves inside the mounted
    /// fs). # C: O(start/root mount stack)
    pub fn new(start: Arc<Dentry>, root: Arc<Dentry>, flags: LookupFlags, cred: Cred) -> KResult<Self> {
        let ns = crate::mount::current_ns();
        let base_mnt = crate::mount::root_mount_id(ns).unwrap_or(0);
        let (root_dentry, _ri, root_mnt_id) = follow_mount_down(root, base_mnt, ns)?;
        let (cur_dentry, cur_inode, cur_mnt_id) = follow_mount_down(start, root_mnt_id, ns)?;
        Ok(Nameidata { cur_mnt_id, cur_dentry, cur_inode, root_mnt_id, root_dentry, depth: 0, flags, cred })
    }

    /// Reset the current position to the resolution root (absolute path /
    /// absolute symlink target). # C: O(1)
    fn to_root(&mut self) -> KResult<()> {
        self.cur_dentry = self.root_dentry.clone();
        self.cur_mnt_id = self.root_mnt_id;
        self.cur_inode = self.cur_dentry.inode().ok_or(VfsError::Enoent)?;
        Ok(())
    }

    /// `..` — `follow_dotdot` clamped at the resolution root. # C: O(stack)
    fn handle_dotdot(&mut self) {
        dotdot_step(
            &mut self.cur_dentry, &mut self.cur_mnt_id, &mut self.cur_inode,
            &self.root_dentry, self.root_mnt_id,
        );
    }

    /// Resolve `path` from the current state to a final `VfsPath`. # C:
    /// O(components × dir-lookup) + O(symlinks)
    pub fn walk(&mut self, path: &str) -> KResult<VfsPath> {
        let ns = crate::mount::current_ns();
        if path.as_bytes().first() == Some(&b'/') { self.to_root()?; }

        let mut queue: Vec<String> = components(path);
        let mut idx = 0usize;
        let mut last_component: Option<String> = None;

        while idx < queue.len() {
            let comp = queue[idx].clone();
            idx += 1;
            let is_final = idx == queue.len();

            if comp == "." { continue; }
            if comp == ".." { self.handle_dotdot(); continue; }

            // LOOKUP_PARENT: stop at the last component, returning the parent
            // dir + the leaf name (Linux `path_parentat`).
            if is_final && self.flags.parent {
                last_component = Some(comp);
                break;
            }

            // `may_lookup`: search permission (MAY_EXEC) on the current
            // directory before resolving a name within it. Only meaningful on
            // directories — a non-dir mid-path yields ENOTDIR from `lookup`.
            if matches!(self.cur_inode.file_type(), FileType::Directory) {
                may_lookup(&self.cur_inode, &self.cred)?;
            }

            // Resolve the named child via the dcache: fast path `d_lookup`
            // (parent,name)-keyed, else slow path `i_op->lookup` + `d_add`.
            let child = match crate::dcache::d_lookup(&self.cur_dentry, &comp) {
                Some(d) if !d.is_negative() => d,
                Some(_) => return Err(VfsError::Enoent), // cached negative
                None => crate::dcache::d_add(&self.cur_dentry, &comp, self.cur_inode.lookup(&comp)?),
            };

            // Symlink handling — use the child's OWN inode (a mountpoint is a
            // directory, never a symlink, so this precedes mount crossing).
            if matches!(child.inode().map(|i| i.file_type()), Some(FileType::Symlink)) {
                if self.flags.no_symlinks { return Err(VfsError::Eloop); }
                if is_final && self.flags.no_follow_final {
                    let inode = child.inode().ok_or(VfsError::Enoent)?;
                    return Ok(VfsPath { mnt_id: self.cur_mnt_id, dentry: child, inode, last_component: None });
                }
                self.depth += 1;
                if self.depth > MAX_SYMLINK_DEPTH { return Err(VfsError::Eloop); }
                let target = child.inode().ok_or(VfsError::Enoent)?.readlink()?;
                let target = String::from_utf8_lossy(&target).into_owned();
                // Splice the target's components ahead of whatever remains.
                let mut next: Vec<String> = components(&target);
                next.extend_from_slice(&queue[idx..]);
                queue = next;
                idx = 0;
                if target.as_bytes().first() == Some(&b'/') {
                    // Absolute target: restart at the resolution root. BENEATH
                    // forbids the escape (Linux EXDEV → surfaced as ELOOP);
                    // IN_ROOT confines it (restart at `root`, the default).
                    if self.flags.beneath { return Err(VfsError::Eloop); }
                    self.to_root()?;
                }
                // Relative target keeps walking from the symlink's directory.
                continue;
            }

            // KEYSTONE — mount crossing (Linux `__follow_mount`): switch the
            // current dentry to the mounted fs's `s_root`, looping for stacked
            // overmounts. `VfsPath.dentry` thus becomes the mounted-fs dentry.
            let (nd, ni, nm) = follow_mount_down(child, self.cur_mnt_id, ns)?;
            self.cur_dentry = nd;
            self.cur_inode = ni;
            self.cur_mnt_id = nm;
        }

        // LOOKUP_DIRECTORY: the resolved target must be a directory.
        if self.flags.directory && !matches!(self.cur_inode.file_type(), FileType::Directory) {
            return Err(VfsError::Enotdir);
        }

        Ok(VfsPath {
            mnt_id: self.cur_mnt_id,
            dentry: self.cur_dentry.clone(),
            inode: self.cur_inode.clone(),
            last_component,
        })
    }
}

/// Resolve absolute `path` to its inode by a PURE per-component walk from the
/// global root dentry (`d_lookup → i_op->lookup → d_add`, crossing mounts by
/// dentry identity). The per-component replacement for the deleted whole-path
/// `FileSystem::lookup`; used by `vfs::mount::lookup` (inotify dirent hooks).
/// # C: O(path components)
pub fn resolve_abs(path: &str) -> KResult<InodeRef> {
    let root = root_dentry().ok_or(VfsError::Enoent)?;
    let p = path_lookup_path(root.clone(), root, path, LookupFlags::default())?;
    Ok(p.inode)
}

/// Resolve absolute `path` to its canonical DENTRY (parent chain intact) by
/// the per-component walk from the global root. Used by `install_open` to
/// obtain the real parent dentry for an opened file. `None` if the root dentry
/// isn't built yet (early boot) or the path doesn't resolve. # C: O(components)
pub fn resolve_path_dentry(path: &str) -> Option<Arc<Dentry>> {
    let root = root_dentry()?;
    path_lookup_path(root.clone(), root, path, LookupFlags::default())
        .ok()
        .map(|p| p.dentry)
}

/// Global root-dentry provider — supplies the start of an absolute mount-
/// identification walk (`walk_to_mount`). Installed at boot from the syscall
/// layer (`pathresolve::root_dentry`). # C: O(1)
type RootDentry = fn() -> Option<Arc<Dentry>>;
static ROOT_DENTRY: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the global root-dentry provider. Called once at boot. # C: O(1)
pub fn set_root_dentry_provider(f: RootDentry) {
    ROOT_DENTRY.store(f as *mut (), Ordering::Release);
}

/// The installed global root dentry (start of an absolute walk), or `None`
/// before the provider is installed. # C: O(1)
pub fn root_dentry() -> Option<Arc<Dentry>> {
    let p = ROOT_DENTRY.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: only ever stores a `RootDentry` fn pointer via the setter.
    let f: RootDentry = unsafe { core::mem::transmute(p) };
    f()
}

/// Identify the mount that OWNS absolute `path` — the `mnt_id` of the deepest
/// mount whose subtree contains `path`. Walks components from the global root,
/// crossing mounts to the mounted fs `s_root` (Linux `__follow_mount`) so the
/// dcache stays canonical with `path_lookup`, tracking the last-crossed mount
/// id. NEVER invokes a whole-path delegate (so `resolve_mount → lookup →
/// resolve_mount` cannot recurse). On a missing/whole-path component it STOPS
/// and returns the current (owning) mount, so open-create/rename/link on a
/// not-yet-existing leaf still yield the parent's mount. `None` only before the
/// root exists. # C: O(components × dir-lookup)
pub fn walk_to_mount(path: &str) -> Option<u64> {
    let root = root_dentry()?;
    let ns = crate::mount::current_ns();
    let root_mnt = crate::mount::root_mount_id(ns).unwrap_or(0);
    let (mut cur_dentry, mut cur_inode, mut cur_mnt) =
        follow_mount_down(root.clone(), root_mnt, ns).ok()?;
    for comp in components(path) {
        if comp == "." { continue; }
        if comp == ".." {
            dotdot_step(&mut cur_dentry, &mut cur_mnt, &mut cur_inode, &root, root_mnt);
            continue;
        }
        // dcache fast path (d_lookup) then slow path (i_op->lookup + d_add).
        let child = match crate::dcache::d_lookup(&cur_dentry, &comp) {
            Some(d) if !d.is_negative() => d,
            Some(_) => return Some(cur_mnt), // cached negative: current mount owns it
            None => match cur_inode.lookup(&comp) {
                Ok(ci) => crate::dcache::d_add(&cur_dentry, &comp, ci),
                Err(_) => return Some(cur_mnt), // missing leaf / whole-path fs
            },
        };
        // Cross to the mounted fs `s_root` (keystone) for the next component.
        match follow_mount_down(child, cur_mnt, ns) {
            Ok((nd, ni, nm)) => { cur_dentry = nd; cur_inode = ni; cur_mnt = nm; }
            Err(_) => return Some(cur_mnt),
        }
    }
    Some(cur_mnt)
}

/// Split `path` into non-empty components, preserving `.`/`..`. # C: O(len)
fn components(path: &str) -> Vec<String> {
    path.split('/').filter(|c| !c.is_empty()).map(String::from).collect()
}

/// Resolve `path` from `start` (dirfd base / cwd) with `root` as the
/// resolution root, returning `(inode, dentry)`. Compatibility wrapper over
/// `path_lookup_path`; default-allow cred. # C: O(components) + O(symlinks)
pub fn path_lookup(
    start: Arc<Dentry>,
    root: Arc<Dentry>,
    path: &str,
    flags: LookupFlags,
) -> KResult<(InodeRef, Arc<Dentry>)> {
    let p = path_lookup_path(start, root, path, flags)?;
    Ok((p.inode, p.dentry))
}

/// Resolve `path` to a full `VfsPath`, preserving the mount identity that owns
/// the final dentry. Default-allow cred (`Cred::root()`); use
/// `path_lookup_cred` to enforce per-directory search permission.
/// # C: O(components × dir-lookup) + O(symlinks)
pub fn path_lookup_path(
    start: Arc<Dentry>,
    root: Arc<Dentry>,
    path: &str,
    flags: LookupFlags,
) -> KResult<VfsPath> {
    path_lookup_cred(start, root, path, flags, Cred::root())
}

/// Resolve `path` to a full `VfsPath`, enforcing `may_lookup` (MAY_EXEC) on
/// each traversed directory against `cred` (Linux `link_path_walk`).
/// # C: O(components × dir-lookup) + O(symlinks)
pub fn path_lookup_cred(
    start: Arc<Dentry>,
    root: Arc<Dentry>,
    path: &str,
    flags: LookupFlags,
    cred: Cred,
) -> KResult<VfsPath> {
    let mut nd = Nameidata::new(start, root, flags, cred)?;
    nd.walk(path)
}
