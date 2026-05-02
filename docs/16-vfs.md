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

## 7 Concurrency

- Dentry cache: RCU read, spinlock insert, class `Dentry`.
- Inode cache: same shape, class `Inode`.
- Per-inode `i_lock`: rwlock for content+metadata.
- Mount table: RCU + spinlock, class `MountTable`.
- FD table: per-process spinlock, class `FdTable`.
- Order: `MountTable` < `Dentry` < `Inode` < `FdTable` < `Superblock` (cross-FS rename).

## 8 Perf budget

| Op | p99 cy |
|---|---|
| Cached lookup, 1 component | 250 |
| Cached lookup, 5 components | 1000 |
| `read` page-cache hit | 1500 |
| `write` page-cache hit (no dirty propagation) | 2000 |
| `fstat` cached | 600 |

## 9 Test contract (frozen)

- Path resolution unit tests on synthetic tree: `..`, symlinks, depth limit, BENEATH, mount transitions, cross-mount `..`.
- Property: random tree + random ops; verify dentry/inode invariants 2,3,4.
- Loom dentry-cache lookup-vs-insert: RCU correctness; depth 6.
- QEMU: mount tmpfs + ext4 image, busybox `find /` + `cp -a` between them; no errors.
- Soak (bg, not gate per `40§3`): 4h cycles, `fs_mark`+`find`+random touch/unlink; zero corruption, zero leaked Arc (static counters reconcile). PR-time gate uses `paranoid-ci` (`debug-vfs`).
- Coverage ≥95%.

## 10 Failure modes

- Symlink loop: ELOOP.
- Cross-ns mount escape: EXDEV.
- Inode op returns invariant-breaking value: panic in debug; error to user in release.

## 11 Debug

`debug-vfs`: dentry+inode refcount audit per op.

## 12 Log

`target="vfs"`,`"vfs::lookup"`,`"vfs::mount"`. trace=per-lookup (debug only); debug=mount/unmount; warn=ELOOP retries.

## 13 Cross-spec

`12` (slab for inode/dentry alloc), `06` (RCU+seqlock+locks), `15` (file syscalls), `17` (page cache backing), `19` (procfs/sysfs/devtmpfs as Filesystems), `28` (devpts), `26` (mount-ns).

## 14 Changelog

(none)

