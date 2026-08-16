# 16 VFS

FROZEN 2026-05-02. Dep:`01`,`02`,`06`,`08`,`09`,`12`,`15`. Provides:`fs-tmpfs`,`fs-ext4`, etc.; `19`,`28`.

Single tree of files/dirs/inode-typed objects abstracting underlying FSes. Path resolution, mount, inode/dentry caches, FD surface backing `read`/`write`/`open`/`close`/`stat`/`mmap`/...

## 1 Frozen invariants

1. Single root: every process sees tree rooted at its `root`, entered via `cwd`.
2. Dentry-inode link: cached `Dentry` → 1 `Inode` (or None for negative).
3. Inode-superblock link: every `Inode` belongs to 1 `Superblock`.
4. Mount stacking: ≤1 FS mounted on a directory per mount-ns at a time.
5. Path resolution termination: with `RESOLVE_NO_SYMLINKS` honored OR symlink-depth ≤40, every resolution terminates O(component_count) inode lookups.
6. No data races on inode metadata: mutations (size, mtime) via `i_lock`; cached attrs via seqlock for readers.

## 2 Public ifc

```rust
pub trait Inode: Send+Sync {
  fn ino(&self) -> Ino; fn mode(&self) -> FileMode; fn size(&self) -> u64;
  fn lookup(&self, name:&OsStr) -> KR<Arc<dyn Inode>>;
  fn create(&self, name:&OsStr, mode:FileMode) -> KR<Arc<dyn Inode>>;
  fn unlink(&self, name:&OsStr) -> KR<()>;
  fn mkdir(&self, name:&OsStr, mode:FileMode) -> KR<Arc<dyn Inode>>;
  fn rmdir(&self, name:&OsStr) -> KR<()>;
  fn rename(&self, ...) -> KR<()>;
  fn read(&self, off:u64, buf:&mut[u8]) -> KR<usize>;
  fn write(&self, off:u64, buf:&[u8]) -> KR<usize>;
  fn truncate(&self, new:u64) -> KR<()>;
  fn fsync(&self, datasync:bool) -> KR<()>;
  fn statx(&self, mask:StatxMask) -> KR<Statx>;
  fn poll(&self, mask:PollMask) -> PollMask;
  fn ioctl(&self, cmd:u32, arg:usize) -> KR<u64>;
  fn mmap(&self, vma:&Vma, off:u64) -> KR<()>;
  // ~30 methods; full enum in crate
}
pub trait Superblock: Send+Sync {
  fn root(&self) -> Arc<dyn Inode>; fn statfs(&self) -> KR<StatFs>;
  fn sync(&self) -> KR<()>; fn umount(&self) -> KR<()>;
}
pub trait Filesystem: Send+Sync {
  fn name(&self) -> &'static str;
  fn mount(&self, source:&OsStr, opts:&MountOpts) -> KR<Arc<dyn Superblock>>;
}
```

Dirent-mutation notification hooks: `set_dirent_create_hook` / `set_dirent_delete_hook` take `fn(&InodeRef, &str, bool)` and fire on the parent directory with the leaf name whenever an entry appears or disappears. Every FS that mutates dirents fires them; `fs::inotify` installs them to emit `IN_CREATE`/`IN_DELETE`/`IN_MOVED` (`19`).

## 3 Path resolution

`path_lookup(start, path, flags)`: split `/`, iterate; per component cached `Dentry` else `inode.lookup`; symlink → `readlink` recurse w/ depth check ≤40; mount point → switch to mount's root inode; `..` at mount root → pop to parent mount; `RESOLVE_BENEATH` keeps under `start`; `RESOLVE_NO_SYMLINKS` hard-error any symlink. Returns `(Arc<dyn Inode>, final Dentry)`.

## 4 Caches

- Dentry cache: open-addressed hash, key `(parent_dentry_id, name_hash)`, RCU read, lockless O(1) lookup.
- Inode cache: per-SB hash by inode number, RCU read.
- LRU + reclaim daemon: walk LRUs on memory pressure, evict unused.

## 5 FD table

```rust
struct FdTable { files: Vec<Option<Arc<File>>>, cloexec: BitVec }
struct File { inode:Arc<dyn Inode>, pos:AtomicU64, flags:AtomicU32, dentry:Arc<Dentry> }
```

Per-process; shared via `CLONE_FILES`.

## 6 Mount table

Per mount-ns. Tree:
```rust
struct Mount {
  sb: Arc<dyn Superblock>, mountpoint: Arc<Dentry>,
  parent: Option<Arc<Mount>>, children: Vec<Arc<Mount>>,
  flags: MountFlags, propagation: PropagationKind, // private|shared|slave|unbindable
}
```

Impls `mount`/`umount2` + new mount API (`fsopen`/`fsconfig`/`fsmount`/`move_mount`).

## 7 Union mounts (frozen)

One tree presented from several stacked ones, with writes landing in a single
writable layer. Owner: `crates/kernel/overlayfs` (`52§5` rule 17). Registered as
`overlay` and `overlayfs`; no source, every layer named in the option string.

### 7.1 Layer stack

| Term | Meaning |
|---|---|
| upper | writable layer; absent = mount is read-only |
| lower | read-only layers, topmost first |
| data-only | lower layer reachable only by an absolute redirect; no name resolves into it |
| workdir | scratch on upper's filesystem; objects are built here and renamed into place |
| indexdir | replaces workdir when `index=on`; keys copied-up objects by origin handle |

Refused at mount: workdir inside upperdir or vice versa, a layer that is not a
directory, a lower layer equal to upper or work, a lone lower layer with no
upper, more than `500` layers.

### 7.2 Records a layer carries

Namespace `trusted.overlay.` (`user.overlay.` under `userxattr`); doubled
namespace escapes an object's own attribute. Private records never appear in
`listxattr` and are never copied up.

| Record | On | Meaning |
|---|---|---|
| `opaque` | dir | `y` hides every lower dir of the name; `x` = holds marked whiteouts |
| `redirect` | any | where the object's lower half lives (name, or path from layer root) |
| `origin` | upper | file handle of the lower object it was copied from |
| `impure` | dir | holds entries whose lower origin is not their name |
| `metacopy` | reg | metadata only; data is still below |
| `upper`,`nlink`,`uuid`,`protattr`,`whiteout` | per `overlayfs` uapi module | |

Whiteout = character device, rdev 0. Second form (layers that hold no device
nodes): empty regular file carrying `whiteout`, in a dir whose `opaque` is `x`.
`mknod` of rdev-0 char inside the overlay: EPERM.

### 7.3 Invariants

1. Lookup order: upper, then each lower under the same parent, stopping at a
   whiteout, an opaque dir, or a complete non-directory.
2. A redirect is followed only when the mount asked for it (`redirect_dir`),
   and a metacopy record only under `metacopy=on`; otherwise EPERM.
3. Copy-up builds in workdir and renames into place LAST. Data before xattrs
   (a write clears file capabilities); size before timestamps.
4. Delete leaves a whiteout iff the name still resolves below.
5. Merged readdir: one entry per name, whiteouts filtered and hiding lower
   names, bottom layer's entries first in that layer's order.
6. A copied-up object keeps the inode number it had; `xino` tags lower numbers
   so two layers' objects never collide.
7. `statfs` reports the upper layer's numbers (topmost lower when read-only),
   with `f_type` = `OVERLAYFS_SUPER_MAGIC`.

### 7.4 Options

`lowerdir`,`lowerdir+`,`datadir+`,`upperdir`,`workdir`,`default_permissions`,
`redirect_dir`,`index`,`uuid`,`nfs_export`,`userxattr`,`xino`,`metacopy`,
`verity`,`fsync`,`volatile`,`override_creds`. Conflict resolution: two
explicitly named options that contradict are EINVAL; a named one against a
defaulted one wins silently. `userxattr` forces `redirect_dir=nofollow` and
`metacopy=off`. Without privilege over `trusted.`, naming `redirect_dir`,
`metacopy`, `verity` or a data-only layer is EPERM.

## 8 Concurrency

- Dentry cache: RCU read, spinlock insert, class `Dentry`.
- Inode cache: same shape, class `Inode`.
- Per-inode `i_lock`: rwlock for content+metadata.
- Mount table: RCU + spinlock, class `MountTable`.
- FD table: per-process spinlock, class `FdTable`.
- Order: `MountTable` < `Dentry` < `Inode` < `FdTable` < `Superblock` (cross-FS rename).

## 9 Perf budget

| Op | p99 cy |
|---|---|
| Cached lookup, 1 component | 250 |
| Cached lookup, 5 components | 1000 |
| `read` page-cache hit | 1500 |
| `write` page-cache hit (no dirty propagation) | 2000 |
| `fstat` cached | 600 |

## 10 Test contract (frozen)

- Path resolution unit tests on synthetic tree: `..`, symlinks, depth limit, BENEATH, mount transitions, cross-mount `..`.
- Property: random tree + random ops; verify dentry/inode invariants 2,3,4.
- Loom dentry-cache lookup-vs-insert: RCU correctness; depth 6.
- QEMU: mount tmpfs + ext4 image, `find /` + `cp -a` between them; no errors.
- PR-time gate uses `paranoid-ci` (`debug-vfs`) per `41§3`. Randomized fs_mark + find + concurrent touch/unlink workloads run in proptest harness; static counter reconciliation enforced at end.
- Coverage ≥95%.
- Union mounts (`§7`): hosted tests over in-memory layer stacks covering the
  lookup order, both whiteout forms, opaque and redirect, copy-up of every
  object type with its ordering, merged readdir order and deduplication, and
  the option conflict table. Positive control required on the copy-up ordering
  and on the whiteout-on-delete rule.

## 11 Failure modes

- Symlink loop: ELOOP.
- Cross-ns mount escape: EXDEV.
- Inode op returns invariant-breaking value: panic in debug; error to user in release.

## 12 Debug

`debug-vfs`: dentry+inode refcount audit per op.

## 13 Log

`target="vfs"`,`"vfs::lookup"`,`"vfs::mount"`. trace=per-lookup (debug only); debug=mount/unmount; warn=ELOOP retries.

## 14 Cross-spec

`12` (slab for inode/dentry alloc), `06` (RCU+seqlock+locks), `15` (file syscalls), `17` (page cache backing), `19` (procfs/sysfs/devtmpfs as Filesystems), `28` (devpts), `26` (mount-ns), `52§5` (union-mount crate ownership).

## 15 Changelog

- 2026-08-16: Added `## 7` union mounts (overlayfs): layer stack, layer
  records, invariants, options. Owner crate recorded in `52§5` rule 17.
