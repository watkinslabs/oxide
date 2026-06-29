//! FileSystem trait — per `docs/16` mount-table abstraction.
//!
//! Each FS backend (ext4 rootfs, devfs, procfs, tmpfs) implements
//! this trait. The kernel mount table (`vfs::mount`, R67) holds an
//! `Arc<dyn FileSystem>` per mount point and routes path lookup to
//! the longest-prefix-match instance.
//!
//! work fns per `docs/53§3`: no `SyscallArgs`, no
//! `sched::current()`, returns `KResult<T>` with typed `T`.

extern crate alloc;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use sync::{Devices as FsClass, Spinlock};
use crate::inode::InodeRef;
use crate::superblock::{FileSystemType, SuperBlock, SuperOps, SB_RDONLY};
use crate::types::VfsError;

/// `KResult<T>` is the VFS error envelope. Aliased here for
/// convenience inside trait bodies.
pub type KResult<T> = core::result::Result<T, VfsError>;

/// `struct fs_context` — the modern mount-API context (`docs/16§6`). Lives in a
/// submodule of `fs` so it re-exports through `vfs::fs::fs_context::*` without a
/// new top-level `lib.rs` module declaration. See [`fs_context::FsContext`].
pub mod fs_context;
pub use fs_context::{
    put_fs_context, reconfigure_super, vfs_get_tree, vfs_parse_fs_param, vfs_parse_fs_param_source,
    vfs_parse_fs_string, FsContext, FsContextOps, FsContextPhase, FsContextPurpose,
    FsContextSecurity, FsParameter, FsValue, LegacyFsContextOps, ParamResult, SB_FLAGS_USER_MASK,
};

bitflags::bitflags! {
    /// `file_system_type::fs_flags` (Linux `include/linux/fs.h`). A
    /// type-LEVEL property of the backend (NOT a per-mount `MNT_*` bit):
    /// it governs how the VFS mounts and classifies the fs. Numeric
    /// values match Linux exactly. Subset for v1; expand alongside their
    /// first real consumer.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    pub struct FsFlags: u32 {
        /// fs is backed by a block device — `mount(2)` needs a `dev`
        /// source (`mount_bdev`). Cleared on pseudo / in-memory fses
        /// (`mount_nodev`), which `/proc/filesystems` then tags `nodev`.
        const FS_REQUIRES_DEV       = 1;
        /// On-disk mount options are an opaque binary blob, not a comma
        /// string (Linux `FS_BINARY_MOUNTDATA`).
        const FS_BINARY_MOUNTDATA   = 2;
        /// fs name carries a `.subtype` suffix (`fuse.sshfs`).
        const FS_HAS_SUBTYPE        = 4;
        /// Mountable by a non-init user-namespace root (Linux
        /// `FS_USERNS_MOUNT`: tmpfs, proc, sysfs, …).
        const FS_USERNS_MOUNT       = 8;
        /// fanotify permission events are refused on this fs.
        const FS_DISALLOW_NOTIFY_PERM = 16;
        /// fs understands vfs idmappings (`FS_ALLOW_IDMAP`).
        const FS_ALLOW_IDMAP        = 32;
        /// `->rename` performs the `d_move` itself; the VFS must NOT
        /// (Linux `FS_RENAME_DOES_D_MOVE`, e.g. NFS).
        const FS_RENAME_DOES_D_MOVE = 32768;
    }
}

/// Append the decimal digits of `n` to `s` (no_std, no `format!`).
/// # C: O(log10 n)
fn push_u32(s: &mut String, n: u32) {
    if n == 0 { s.push('0'); return; }
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    let mut v = n;
    while v > 0 { i -= 1; buf[i] = b'0' + (v % 10) as u8; v /= 10; }
    // SAFETY: buf[i..] holds only ASCII '0'..='9', valid UTF-8.
    s.push_str(unsafe { core::str::from_utf8_unchecked(&buf[i..]) });
}

/// Filesystem instance per `16§2`. One impl per backend; one or
/// more instances per kernel (each registered to a mount point).
pub trait FileSystem: Send + Sync {
    /// Human-readable FS-type name. `"ext4"`, `"tmpfs"`, `"devfs"`,
    /// `"procfs"`. Used for `/proc/mounts` and error messages.
    /// # C: O(1)
    fn name(&self) -> &str;

    /// Superblock `s_magic` (linux/magic.h) reported by `statfs(2)` /
    /// `fstatfs(2)` `f_type`. systemd & friends detect fs type by this
    /// magic (cgroup2=0x63677270, tmpfs=0x01021994, proc=0x9fa0, …), so
    /// every real backend must override. `0` = "no opinion": the statfs
    /// classifier then falls through to its path-prefix table.
    /// # C: O(1)
    fn magic(&self) -> u64 { 0 }

    /// `file_system_type::fs_flags` for this backend (Linux
    /// `include/linux/fs.h`). Default `empty()` = a pseudo / in-memory fs:
    /// not block-device-backed, so `/proc/filesystems` tags it `nodev`.
    /// On-disk backends override with [`FsFlags::FS_REQUIRES_DEV`] (ext4,
    /// ext2/3, vfat, iso9660); pseudo fses that nonetheless want
    /// userns-mountability set [`FsFlags::FS_USERNS_MOUNT`].
    /// # C: O(1)
    fn fs_flags(&self) -> FsFlags { FsFlags::empty() }

    /// fs is backed by a block device (`mount(2)` requires a `dev` source).
    /// Mirrors Linux's `fs_flags & FS_REQUIRES_DEV` predicate used by
    /// `mount_bdev` vs `mount_nodev` and by `filesystems_proc_show`.
    /// # C: O(1)
    fn requires_dev(&self) -> bool { self.fs_flags().contains(FsFlags::FS_REQUIRES_DEV) }

    /// Stable backing-device id for superblock sharing (Linux `s_dev`, the
    /// `get_tree_bdev` key): two mounts of the SAME backing device must SHARE
    /// one `SuperBlock`. `Some(dev)` ⇒ the mount engine routes through
    /// [`crate::superblock::sget`] so a second mount of `dev` re-uses the live
    /// instance (one extra `s_active`) instead of allocating a fresh anonymous
    /// SB; `None` (the default) ⇒ an anon/pseudo fs (tmpfs, procfs, a bind
    /// marker) that gets a fresh per-mount `get_anon_bdev` SB, never shared.
    /// # C: O(1)
    fn dev_id(&self) -> Option<u64> { None }

    /// `->rename` drives `d_move` itself, so the VFS rename path must skip
    /// the generic dentry move (Linux `FS_RENAME_DOES_D_MOVE`). # C: O(1)
    fn rename_does_d_move(&self) -> bool {
        self.fs_flags().contains(FsFlags::FS_RENAME_DOES_D_MOVE)
    }

    /// One `/proc/filesystems` row for this backend, byte-identical to
    /// Linux `filesystems_proc_show` (`fs/filesystems.c`): a leading
    /// `"nodev"` for non-`FS_REQUIRES_DEV` fses (else empty), a TAB, the fs
    /// name, and `'\n'`. Replaces the hardcoded `/proc/filesystems` table:
    /// the `nodev` column is now DERIVED from `fs_flags`, not a string
    /// literal. # C: O(len name)
    fn proc_filesystems_line(&self) -> String {
        let mut s = String::new();
        if self.requires_dev() { /* FS_REQUIRES_DEV ⇒ no "nodev" prefix */ }
        else { s.push_str("nodev"); }
        s.push('\t');
        s.push_str(self.name());
        s.push('\n');
        s
    }

    /// `s_blocksize` (Linux `super_block::s_blocksize`) the mount reports as
    /// `statfs(2)` `f_bsize`. On-disk backends override from their parsed
    /// superblock (ext4 `1024 << s_log_block_size`, 1–64 KiB); pseudo /
    /// in-memory fses keep the 4096 page default. # C: O(1)
    fn block_size(&self) -> u32 { 4096 }

    /// Per-instance `super_operations` (Linux `sb->s_op`). `Some(_)` installs a
    /// backend-specific `SuperOps` — e.g. ext4 reports live on-disk block /
    /// inode accounting through its own `statfs` — instead of the generic
    /// `FsBackedSuperOps` (which reports only `f_type`/`f_bsize`). `None` keeps
    /// the generic adapter. Consulted once by [`SuperBlock::for_backend`] at
    /// fill_super. # C: O(1)
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { None }

    /// Root inode of this mounted filesystem — the `super_block::s_root`
    /// of `docs/16§2`. The dentry path-walk (`docs/16§3`) switches to this
    /// inode when it crosses into the mount, then resolves every component
    /// below it via `Inode::lookup` (`d_lookup → i_op->lookup → d_add`).
    /// Every real backend overrides this (or publishes a per-mount root via
    /// `mount::register_bind`'s `m.root`); `None` only for a marker fs whose
    /// root inode is carried by the mount table instead.
    /// # C: O(1)
    fn root(&self) -> Option<InodeRef> { None }

    /// Create a new regular file at `path` with permission `mode`.
    /// Default: read-only FS returns `Erofs`.
    /// # C: depends on FS.
    fn create(&self, path: &str, mode: u32) -> KResult<InodeRef> {
        let _ = (path, mode);
        Err(VfsError::Erofs)
    }

    /// Create an anonymous (`O_TMPFILE`) regular inode on THIS fs. `dir`
    /// is the directory (relative to this mount) the file would live in —
    /// disk FSes use it to pick an allocation group; in-memory FSes
    /// ignore it. The inode has no directory entry (nlink=0) and is
    /// reclaimed when its last fd drops. Must be dispatched on the fs that
    /// actually backs the path: `O_TMPFILE` on /run|/tmp|/dev/shm is tmpfs,
    /// not the ext4 rootfs. Default: read-only/unsupported FS returns Erofs.
    /// # C: depends on FS.
    fn create_anonymous(&self, dir: &str, mode: u32) -> KResult<InodeRef> {
        let _ = (dir, mode);
        Err(VfsError::Erofs)
    }

    /// Remove the regular file at `path`. Default: `Erofs`.
    /// # C: depends on FS.
    fn unlink(&self, path: &str) -> KResult<()> {
        let _ = path;
        Err(VfsError::Erofs)
    }

    /// Hardlink `target` to `link` within this filesystem. Both paths are
    /// absolute during the mount-table transition; mature backends may treat
    /// them as mount-relative once every caller passes stripped names.
    /// Default: read-only / unsupported FS returns `Erofs`.
    /// # C: depends on FS.
    fn link(&self, target: &str, link: &str) -> KResult<()> {
        let _ = (target, link);
        Err(VfsError::Erofs)
    }

    /// Materialize an unnamed inode, e.g. `linkat(fd, "", path,
    /// AT_EMPTY_PATH)`, into this filesystem. Backends must reject inodes
    /// from another filesystem with `Exdev`.
    /// # C: depends on FS.
    fn link_inode(&self, inode: InodeRef, link: &str) -> KResult<()> {
        let _ = (inode, link);
        Err(VfsError::Erofs)
    }

    /// Rename `from` to `to`. Both paths are relative to this FS.
    /// Default: `Erofs`.
    /// # C: depends on FS.
    fn rename(&self, from: &str, to: &str) -> KResult<()> {
        let _ = (from, to);
        Err(VfsError::Erofs)
    }

    /// Resolve a mount-relative `path` to its inode by walking from this
    /// FS root via `Inode::lookup`. `None` if any component is missing or
    /// the FS publishes no `root()`. Helper for [`exchange`]/[`whiteout`].
    /// # C: O(N components)
    fn lookup_path(&self, path: &str) -> Option<InodeRef> {
        let mut cur = self.root()?;
        for comp in path.split('/').filter(|c| !c.is_empty() && *c != ".") {
            cur = cur.lookup(comp).ok()?;
        }
        Some(cur)
    }

    /// `RENAME_EXCHANGE`: atomically swap the two existing paths `a` and
    /// `b`. Both must already exist (Linux `ENOENT` otherwise). Default is
    /// a non-atomic 3-step via `rename` through a fresh temp name in `a`'s
    /// directory, rolled back on partial failure; a backend with a
    /// journalled dirent swap should override for true atomicity.
    /// # C: O(N components)
    fn exchange(&self, a: &str, b: &str) -> KResult<()> {
        if self.lookup_path(a).is_none() || self.lookup_path(b).is_none() {
            return Err(VfsError::Enoent);
        }
        // Pick a temp name that does not currently exist on this FS.
        let mut tmp = alloc::string::String::new();
        let mut n: u32 = 0;
        loop {
            tmp.clear();
            tmp.push_str(a);
            tmp.push_str(".oxexch");
            push_u32(&mut tmp, n);
            if self.lookup_path(&tmp).is_none() { break; }
            n = n.checked_add(1).ok_or(VfsError::Eexist)?;
            if n > 65536 { return Err(VfsError::Eexist); }
        }
        self.rename(a, &tmp)?;                 // a -> tmp
        if let Err(e) = self.rename(b, a) {    // b -> a
            let _ = self.rename(&tmp, a);      // rollback: tmp -> a
            return Err(e);
        }
        if let Err(e) = self.rename(&tmp, b) { // tmp -> b
            let _ = self.rename(a, b);         // rollback: a -> b
            let _ = self.rename(&tmp, a);      //           tmp -> a
            return Err(e);
        }
        Ok(())
    }

    /// `RENAME_WHITEOUT`: rename `from` to `to`, then plant a whiteout at
    /// `from` — an overlayfs whiteout is a character device with rdev 0/0
    /// (`mknod_child(S_IFCHR|0, 0)`). On whiteout-create failure the rename
    /// is rolled back. Default works on any backend whose dir inode honours
    /// `mknod_child`; others surface that inode's error (e.g. `Erofs`).
    /// # C: O(N components)
    fn whiteout(&self, from: &str, to: &str) -> KResult<()> {
        const S_IFCHR: u16 = 0x2000;
        self.rename(from, to)?;
        // Parent dir + basename of `from` (now vacated by the rename).
        let from = from.strip_suffix('/').unwrap_or(from);
        let (parent, name) = match from.rfind('/') {
            Some(i) => (&from[..i], &from[i + 1..]),
            None    => ("", from),
        };
        let pino = match self.lookup_path(parent) {
            Some(p) => p, None => { let _ = self.rename(to, from); return Err(VfsError::Enoent); }
        };
        if let Err(e) = pino.mknod_child(name, S_IFCHR, 0, &crate::CreateCtx::root()) {
            let _ = self.rename(to, from); // rollback the move
            return Err(e);
        }
        Ok(())
    }

    /// Back-stamp the owning `SuperBlock` (Linux `fill_super` setting up
    /// `s_fs_info ↔ sb`). Called by [`SuperBlock::for_backend`] once the SB is
    /// built, BEFORE `d_make_root`, so the backend's per-mount state can hand
    /// the `Weak<SuperBlock>` to its inodes (their `i_sb()` then resolves and
    /// `fsid()` derives from `sb.s_dev` instead of a hardcoded constant).
    /// Default no-op for backends not yet SB-aware (registry-based pseudo-fs).
    /// # C: O(1)
    fn set_sb(&self, _sb: Weak<SuperBlock>) {}

    /// Filesystem-specific mount options for `/proc/mounts` &
    /// `/proc/self/mountinfo`, mirroring Linux `super_operations::show_options`
    /// (`fs/*/super.c`). The VFS renders the generic per-mount flags first
    /// (`rw`/`ro`, `relatime`, …); this hook then APPENDS the backend's own
    /// options — tmpfs `size=`/`nr_inodes=`/`mode=`, ext4 `data=ordered`,
    /// cgroup2 controller list, etc. Each option carries its own leading comma
    /// exactly as Linux emits them via `seq_puts(m, ",size=…")`, so the result
    /// concatenates directly after the generic flags with no separator fixup.
    /// Default `""` = no fs-specific options. # C: O(len opts)
    fn show_options(&self) -> String { String::new() }

    /// `/proc/mounts`-style description: `<src> <mnt> <fstype> <opts> 0 0`.
    /// Source and fstype default to the fs name; `<opts>` is the generic
    /// `rw,relatime` per-mount flags followed by [`Self::show_options`] (the
    /// procfs reader swaps the leading ` rw,` → ` ro,` for a read-only mount,
    /// Linux's per-mount `MNT_RDONLY` rendering). Backends with extra options
    /// override `show_options` ONLY — not this whole line — so the
    /// `<src> <mnt> <fstype> … 0 0` framing stays in one place. # C: O(1)
    fn mounts_line(&self, mount_point: &str) -> String {
        let mut s = String::new();
        s.push_str(self.name());
        s.push(' ');
        s.push_str(mount_point);
        s.push(' ');
        s.push_str(self.name());
        s.push_str(" rw,relatime");
        s.push_str(&self.show_options());
        s.push_str(" 0 0\n");
        s
    }
}

// ---------------------------------------------------------------------------
// `file_systems` registry — Linux `fs/filesystems.c`.
//
// A global, name-keyed list of `file_system_type`s. `register_filesystem`
// links a type in at module/boot init; `get_fs_type(name)` is the lookup
// `mount(2)` uses to resolve `-t <type>` to a `FileSystemType` instead of a
// hard-coded `match fstype { … }`. Insertion order is preserved (Linux keeps
// a singly linked list, `/proc/filesystems` renders it in registration
// order) and lookup is a linear scan — both matching Linux exactly.
// ---------------------------------------------------------------------------

/// `file_systems` — the registered `file_system_type` list (Linux `fs/filesystems.c`).
/// Insertion-ordered `Vec` (not a `BTreeMap`) to render `/proc/filesystems` in
/// registration order like Linux. A leaf lock: nothing else is acquired under
/// it (lookups only clone an `Arc`).
static FILESYSTEMS: Spinlock<Vec<Arc<dyn FileSystemType>>, FsClass>
    = Spinlock::new(Vec::new());

/// `register_filesystem` (Linux `fs/filesystems.c`) — link a `file_system_type`
/// into the global registry so `mount(2)` can resolve it by name. Rejects a
/// duplicate type name with `Ebusy` exactly as Linux (`-EBUSY`).
/// # C: O(N) over registered types
pub fn register_filesystem(fs: Arc<dyn FileSystemType>) -> KResult<()> {
    let mut list = FILESYSTEMS.lock();
    if list.iter().any(|t| t.name() == fs.name()) { return Err(VfsError::Ebusy); }
    list.push(fs);
    Ok(())
}

/// `unregister_filesystem` (Linux `fs/filesystems.c`) — unlink a type by name.
/// `Einval` if no type with that name is registered (Linux `-EINVAL`).
/// # C: O(N) over registered types
pub fn unregister_filesystem(name: &str) -> KResult<()> {
    let mut list = FILESYSTEMS.lock();
    match list.iter().position(|t| t.name() == name) {
        Some(i) => { list.remove(i); Ok(()) }
        None    => Err(VfsError::Einval),
    }
}

/// `get_fs_type` (Linux `fs/filesystems.c`) — resolve a `file_system_type` by
/// name. A `name.subtype` form (FUSE `fuse.sshfs`) resolves on the base name
/// before the first `'.'`, mirroring Linux `__get_fs_type`'s `.subtype` split.
/// `None` if no type is registered under that name. # C: O(N) over registered types
pub fn get_fs_type(name: &str) -> Option<Arc<dyn FileSystemType>> {
    let base = match name.find('.') { Some(i) => &name[..i], None => name };
    if let Some(t) = FILESYSTEMS.lock().iter().find(|t| t.name() == base).cloned() {
        return Some(t);
    }
    // D40: also surface the constructor-bearing `FsType` registry, so a type
    // registered for the production mount path resolves here too.
    FS_TYPES.lock().iter().find(|t| t.name == base).cloned().map(|t| t as Arc<dyn FileSystemType>)
}

/// Snapshot of every registered `file_system_type` in registration order — the
/// source `filesystems_proc_show` (`/proc/filesystems`) iterates. Includes both
/// the bare [`FileSystemType`] registrants and the constructor-bearing
/// [`FsType`] entries (D40). # C: O(N)
pub fn registered_filesystems() -> Vec<Arc<dyn FileSystemType>> {
    let mut v: Vec<Arc<dyn FileSystemType>> = FILESYSTEMS.lock().iter().cloned().collect();
    for t in FS_TYPES.lock().iter() { v.push(t.clone() as Arc<dyn FileSystemType>); }
    v
}

// ---------------------------------------------------------------------------
// `file_system_type` mount constructors — the production `mount(2)` dispatch.
//
// D40: the bare `FileSystemType` registry above stores name→`fill_super`
// (→`SuperBlock`); the boot mount engine (`vfs::mount::register*`) instead
// consumes an `Arc<dyn FileSystem>` backend object and builds the SB itself
// (`build_sb`, Linux `fill_super`). So the value the mount-dispatch path needs
// keyed by name is a CONSTRUCTOR yielding that backend object. `mount_fstype`
// resolves `-t <type>` through [`get_fs`] instead of a hard-coded
// `match fstype { … }`; unknown type → caller's ENODEV (Linux `get_fs_type`
// miss). Registered [`FsType`]s ALSO surface through [`get_fs_type`] /
// [`registered_filesystems`] so `/proc/filesystems` and the new-mount-API
// existence checks see them.
// ---------------------------------------------------------------------------

/// What a registered fs-type constructor hands the mount engine for ONE mount:
/// the backend [`FileSystem`] object, plus the bind-root inode for in-memory
/// fses whose root the engine must graft via `register_bind` (tmpfs/ramfs);
/// `bind_root == None` ⇒ the engine takes `fs.root()` (`register`, Linux
/// `mount_nodev`/`mount_bdev`). `strict` preserves the legacy per-fstype error
/// policy: `false` = the old `let _ = register(); 0` admit-and-ignore arms
/// (tmpfs/proc/sysfs/debugfs/tracefs), `true` = the arms that surface a
/// register failure as an errno (ext4, the kernfs pseudo-fses, autofs,
/// binfmt_misc).
pub struct MountSpec {
    /// Backend object the engine grafts (`vfs::mount::register*`).
    pub fs: Arc<dyn FileSystem>,
    /// `Some(root)` ⇒ bind-graft this root inode (tmpfs); `None` ⇒ `fs.root()`.
    pub bind_root: Option<InodeRef>,
    /// `true` ⇒ propagate a register error as errno; `false` ⇒ admit-and-ignore.
    pub strict: bool,
}

/// `file_system_type::init_fs_context`/`mount` constructor (Linux): resolve a
/// mount's `(source, target, data)` to a freshly-built backend instance.
/// `source` = the mount(2) device/source string; `target` = the rendered
/// mountpoint path (tmpfs/pseudo-fs root-inode naming); `data` = the raw mount
/// option string. Registered from the syscalls crate, where every backend crate
/// is in scope (the VFS crate itself must not depend on them).
pub type FsConstructor = dyn Fn(&str, &str, &str) -> KResult<MountSpec> + Send + Sync;

/// A name-keyed `file_system_type` carrying its mount constructor (D40). Also a
/// [`FileSystemType`] so it lists through [`get_fs_type`]/[`registered_filesystems`];
/// the boot mount path uses [`FsType::construct`] to obtain the backend object,
/// and the mount engine builds the `SuperBlock` (its `mount` here is the
/// equivalent `fill_super` for any SB-based caller/test).
pub struct FsType {
    name:  String,
    magic: u64,
    flags: FsFlags,
    ctor:  Box<FsConstructor>,
}

impl FsType {
    /// Build a registry entry: `name` (Linux `file_system_type::name`), `magic`
    /// (`s_magic`/statfs `f_type`), `flags` (`fs_flags`), and the mount
    /// constructor. # C: O(1)
    pub fn new(name: &str, magic: u64, flags: FsFlags, ctor: Box<FsConstructor>) -> Arc<Self> {
        Arc::new(Self { name: name.to_string(), magic, flags, ctor })
    }
    /// Run the constructor for ONE mount (`source`/`target`/`data`). # C: FS-dependent
    pub fn construct(&self, source: &str, target: &str, data: &str) -> KResult<MountSpec> {
        (self.ctor)(source, target, data)
    }
    /// `s_magic` this type stamps. # C: O(1)
    pub fn magic(&self) -> u64 { self.magic }
    /// `fs_flags` of this type. # C: O(1)
    pub fn fs_flags(&self) -> FsFlags { self.flags }
}

impl FileSystemType for FsType {
    fn name(&self) -> &str { &self.name }
    fn mount(&self, src: &str, opts: &str) -> KResult<Arc<SuperBlock>> {
        let spec = (self.ctor)(src, "", opts)?;
        let root = spec.bind_root.or_else(|| spec.fs.root());
        Ok(SuperBlock::for_backend(spec.fs, root, crate::superblock::next_anon_dev(),
            self.name.clone()))
    }
    fn fs_flags(&self) -> FsFlags { self.flags }
}

/// Constructor-bearing `file_system_type` list (D40), parallel to [`FILESYSTEMS`]
/// (which holds bare SB-builders). A leaf lock. # consumers: D40 mount dispatch.
static FS_TYPES: Spinlock<Vec<Arc<FsType>>, FsClass> = Spinlock::new(Vec::new());

/// Register a constructor-bearing `file_system_type` (D40). Duplicate name →
/// `Ebusy` (Linux `register_filesystem` `-EBUSY`). # C: O(N)
pub fn register_fs(fs: Arc<FsType>) -> KResult<()> {
    let mut list = FS_TYPES.lock();
    if list.iter().any(|t| t.name == fs.name) { return Err(VfsError::Ebusy); }
    list.push(fs);
    Ok(())
}

/// Resolve a constructor-bearing `file_system_type` by name (D40), honouring the
/// `name.subtype` split like [`get_fs_type`]. The production `mount(2)` dispatch
/// lookup. `None` ⇒ unregistered (caller maps to ENODEV). # C: O(N)
pub fn get_fs(name: &str) -> Option<Arc<FsType>> {
    let base = match name.find('.') { Some(i) => &name[..i], None => name };
    FS_TYPES.lock().iter().find(|t| t.name == base).cloned()
}

/// Unregister a constructor-bearing `file_system_type` by name (D40). `Einval`
/// if absent. # C: O(N)
pub fn unregister_fs(name: &str) -> KResult<()> {
    let mut list = FS_TYPES.lock();
    match list.iter().position(|t| t.name == name) {
        Some(i) => { list.remove(i); Ok(()) }
        None    => Err(VfsError::Einval),
    }
}

// ---------------------------------------------------------------------------
// `get_tree_*` superblock-sharing helpers — Linux `fs/super.c`.
//
// A backend's `FsContextOps::get_tree` calls one of these to materialise (or
// re-share) its superblock during `vfs_get_tree`:
//   * `get_tree_nodev`  — never share: a fresh SB per mount (tmpfs, ramfs).
//   * `get_tree_single` — share ONE SB across every mount of this fs_type
//     (sysfs, debugfs, the kernel's single-instance pseudo-fses).
//   * `get_tree_keyed`  — share an SB across mounts that present the same key
//     (mqueue per-netns, cgroup per-hierarchy).
//   * `get_tree_bdev`   — block-device-keyed sharing; NOT here (needs
//     `lookup_bdev` + the block-device registry — block-crate coupled).
//
// Sharing goes through a global registry (Linux's per-`file_system_type`
// `fs_supers` hlist) scoped by `(fs_type-name, key)`; a `sget_fc`-style probe
// bumps `s_active` on a live match instead of re-running fill_super.
// ---------------------------------------------------------------------------

/// One shared-superblock registry slot. `Weak` so a fully-unmounted SB (its last
/// live `Arc` gone after the final umount) reclaims its slot on the next probe;
/// the `(fs_name, key)` pair is the `sget` test predicate. # consumers: D6 sget.
struct SharedSuper {
    fs_name: String,
    key:     String,
    sb:      Weak<SuperBlock>,
}

/// `fs_supers` analogue — the live shared superblocks `get_tree_single`/
/// `get_tree_keyed` probe. A leaf lock (nothing else taken under it; the
/// fill_super closure runs OUTSIDE it, matching Linux `sget_fc`'s drop of
/// `sb_lock` around `alloc_super`).
static SHARED_SUPERS: Spinlock<Vec<SharedSuper>, FsClass> = Spinlock::new(Vec::new());

/// Stamp a context's user-settable `sb_flags` slice onto a freshly built SB
/// (Linux `sb->s_flags = (s_flags & ~mask) | (sb_flags & mask)` in
/// `sget`/`alloc_super`), keeping the dedicated `SB_RDONLY` writer-gate in sync.
/// # C: O(1)
fn stamp_sb_flags(sb: &SuperBlock, fc: &fs_context::FsContext) {
    let mask = fc.sb_flags_mask();
    let set = fc.sb_flags() & mask;
    let clear = !fc.sb_flags() & mask;
    sb.set_s_flags(set, clear);
    sb.set_readonly(set & SB_RDONLY != 0);
}

/// Probe the registry for a live SB matching `(fs_name, key)`, pruning dead
/// `Weak`s. On a hit, bumps `s_active` (`atomic_inc_not_zero`) and returns the
/// shared instance. # C: O(N live supers)
fn sget_probe(fs_name: &str, key: &str) -> Option<Arc<SuperBlock>> {
    let mut list = SHARED_SUPERS.lock();
    list.retain(|e| e.sb.strong_count() > 0);
    for e in list.iter() {
        if e.fs_name == fs_name && e.key == key {
            if let Some(sb) = e.sb.upgrade() {
                if sb.grab_active() { return Some(sb); }
            }
        }
    }
    None
}

/// `get_tree_nodev` (Linux `fs/super.c`) — materialise a BRAND-NEW superblock for
/// this mount with no sharing (every `mount -t tmpfs` is an independent
/// instance). Runs `fill` to build the SB, then stamps the context's `sb_flags`.
/// # C: FS-dependent
pub fn get_tree_nodev<F>(fc: &mut fs_context::FsContext, fill: F) -> KResult<Arc<SuperBlock>>
where F: FnOnce(&mut fs_context::FsContext) -> KResult<Arc<SuperBlock>> {
    let sb = fill(fc)?;
    stamp_sb_flags(&sb, fc);
    Ok(sb)
}

/// `get_tree_keyed` (Linux `fs/super.c`) — share a superblock across every mount
/// of this fs_type that presents the same `key` (e.g. mqueue per-netns). A live
/// match is returned with `s_active` bumped and `fill` is NOT re-run; otherwise
/// `fill` builds a fresh SB, its `sb_flags` are stamped, and it is registered
/// under `(fs_type, key)`. A `sget_fc`-style re-probe after `fill` resolves a
/// race where a sibling registered the same key meanwhile. # C: FS-dependent
pub fn get_tree_keyed<F>(fc: &mut fs_context::FsContext, key: &str, fill: F)
    -> KResult<Arc<SuperBlock>>
where F: FnOnce(&mut fs_context::FsContext) -> KResult<Arc<SuperBlock>> {
    let fs_name = fc.fs_type().name().to_string();
    if let Some(sb) = sget_probe(&fs_name, key) { return Ok(sb); }
    // No live match — build (fill_super runs outside the registry lock).
    let sb = fill(fc)?;
    stamp_sb_flags(&sb, fc);
    let mut list = SHARED_SUPERS.lock();
    // Re-probe: a concurrent mount may have registered the same key meanwhile.
    list.retain(|e| e.sb.strong_count() > 0);
    for e in list.iter() {
        if e.fs_name == fs_name && e.key == key {
            if let Some(shared) = e.sb.upgrade() {
                if shared.grab_active() { return Ok(shared); }
            }
        }
    }
    list.push(SharedSuper { fs_name, key: key.to_string(), sb: Arc::downgrade(&sb) });
    Ok(sb)
}

/// `get_tree_single` (Linux `fs/super.c`) — share ONE superblock across EVERY
/// mount of this fs_type (sysfs, debugfs, the single-instance pseudo-fses). The
/// keyed sharing with an empty key: all mounts of the type collapse to one SB.
/// # C: FS-dependent
pub fn get_tree_single<F>(fc: &mut fs_context::FsContext, fill: F) -> KResult<Arc<SuperBlock>>
where F: FnOnce(&mut fs_context::FsContext) -> KResult<Arc<SuperBlock>> {
    get_tree_keyed(fc, "", fill)
}

/// `reconfigure_single` (Linux `fs/super.c`) — reconfigure a single-instance
/// pseudo-fs's LIVE superblock from monolithic remount data. Builds a throwaway
/// `FS_CONTEXT_FOR_RECONFIGURE` context over `sb`'s root, replays each parsed
/// `param` through [`fs_context::vfs_parse_fs_param`], runs
/// [`fs_context::reconfigure_super`] to apply them plus the masked `sb_flags`,
/// then tears the context down ([`fs_context::put_fs_context`], running the LSM +
/// backend `free` hooks). This is the remount path a single-instance fs uses
/// instead of threading an `fs_context` through `mount_single`. A parse failure
/// fails the context and surfaces the errno; the live SB is left untouched until
/// `reconfigure_super` commits. # C: O(N params)
pub fn reconfigure_single(
    sb: Arc<SuperBlock>,
    sb_flags: u64,
    params: &[fs_context::FsParameter],
) -> KResult<()> {
    let root = sb.s_root().ok_or(VfsError::Einval)?;
    let mut fc = fs_context::FsContext::for_reconfigure(sb, root, sb_flags, SB_FLAGS_USER_MASK);
    for p in params {
        if let Err(e) = fs_context::vfs_parse_fs_param(&mut fc, p) {
            fc.fail();
            fs_context::put_fs_context(fc);
            return Err(e);
        }
    }
    let r = fs_context::reconfigure_super(&mut fc);
    fs_context::put_fs_context(fc);
    r
}
