# KEYSTONE migration recipe — `impl Inode for X` → concrete `Inode` + ops

DRAFT 2026-06-28. Dep:16,53.

Stage B280a replaced the ~53-method god-trait `Inode` with a CONCRETE
`struct Inode` (`vfs/src/inode.rs`) carrying the state, plus two behaviour
vtables:

- `i_op: Arc<dyn InodeOps>`  (`vfs/src/inode_ops.rs`) = Linux `inode_operations`
  — `lookup`/`create`/`mkdir`/`rmdir`/`mknod`/`symlink`/`link`/`unlink`/`rename`/
  `readlink`/`getattr`/`setattr`/`permission`/`fallocate`/`truncate`/`fiemap`/
  `bmap`/`fileattr_get`/`fileattr_set`/`listxattr`.
- `i_fop: Arc<dyn FileOps>` (`vfs/src/file_ops.rs`) = Linux `file_operations`
  — `read`/`write`/`read_nonblock`/`write_nonblock`/`iterate`/`poll`/`poll_file`/
  `mmap_shared_frame`/`on_open`/`on_release`/`on_flush`/`fdinfo_extra`.

Per-inode backend state moves into `i_private: Arc<dyn Any+Send+Sync>` (the old
`as_any` downcast). Lifecycle state (`i_state`/`i_count`/`__i_nlink`) lives on
the struct; `superblock.rs` icache is now `BTreeMap<Ino, Weak<Inode>>` and
`iget`/`iput` drive `i_count`.

## The recipe

Convert one `impl Inode for X` (state struct `X` with N methods) as follows:

1. **Split `X` into data + ops.** The fields of `X` that were per-INSTANCE state
   become an `XData` struct stored in `i_private`. The METHODS become a (usually
   ZST) `XOps` that `impl InodeOps` and/or `XFileOps` that `impl FileOps`. One
   `Arc<XOps>` is shared by every inode of the backend (no per-inode closures).

2. **Map each old method to its op trait** by family:
   | old `Inode` method | new home |
   |---|---|
   | `lookup`/`mkdir`/`rmdir`/`create_child`→`create`/`unlink_child`→`unlink`/`symlink_child`→`symlink`/`mknod_child`→`mknod` | `InodeOps` |
   | `readlink`/`get_link`(via `i_link`)/`getattr`/`setattr`/`permission`/`truncate`/`fallocate`/`fiemap`/`bmap`/`fileattr_*` | `InodeOps` |
   | `read`/`write`/`read_nonblock`/`write_nonblock`/`readdir`→`iterate`/`poll`/`poll_file`/`mmap_shared_frame`/`on_open`/`on_release`/`on_flush`/`fdinfo_extra` | `FileOps` |
   | accessors `ino`/`file_type`/`perm`/`size`/`uid`/`gid`/`*time`/`rdev`/`i_flags`/`nlink`/`fsid`/`i_generation`/`i_link` | NONE — set as `InodeBuilder` fields; the inherent accessors read them. |
   | `set_perm`/`set_owner`/`set_times` | NONE — inherent field writers; `simple_setattr` uses them. |
   | `as_any` | `i_private` + `inode.private::<XData>()` |

   Each op method's signature gains `inode: &Inode` as the first non-`self`
   param (so the shared ops read the per-inode `XData` off `i_private`). Drop the
   methods that only returned the Linux default — the trait default now supplies
   them.

3. **Write `make_x_inode(...) -> InodeRef`** using `InodeBuilder`:
   ```rust
   InodeBuilder::new(ino, mode /* S_IFMT|perm */, Arc::new(XOps), Arc::new(XFileOps))
       .sb(sb).size(..).owner(uid,gid).rdev(..)        // accessor fields
       .private(Arc::new(XData { .. }))                // old as_any state
       .build()                                        // -> Arc<Inode>
   ```
   `mode` is the full `umode_t`: `(ft.to_ifmt() as u32) | (perm as u32 & 0o7777)`
   (helper `inode_ops::mk_mode`). Omit any builder field that takes its default
   (`size 0`, `nlink` = 2 for dir / 1 else, owner `0:0`, no mapping/seals/link).

4. **A backend that only needs ONE op family** uses the shared default for the
   other: `default_inode_ops()` (`lookup`→`ENOTDIR`, generic getattr/setattr/
   permission) or `default_file_ops()` (`read`/`write`→`EISDIR`/`EINVAL`,
   always-ready poll). A directory binds real `i_op` + `default_file_ops()`; a
   regular file binds `default_inode_ops()` + real `i_fop`.

5. **Call sites barely move.** The inherent methods on `Inode` keep the OLD
   names (`inode.lookup(n)`, `inode.read(off,buf)`, `inode.perm()`,
   `inode.mknod_child(..)`, …) and delegate to `i_op`/`i_fop` or read the
   fields, so existing callers compile unchanged. Generic helpers that took
   `<I: Inode + ?Sized>(inode: &I)` become `(inode: &Inode)`.

## Worked example — `vfs/src/devnode.rs` special inodes

### BEFORE (trait-object, three `impl Inode`)

```rust
pub struct DeviceNodeInode { ino: Ino, ft: FileType, devt: Devt, perm: u16, sb: Weak<SuperBlock> }
impl DeviceNodeInode {
    pub fn new(ino, ft, devt, perm, sb) -> Arc<Self> { Arc::new(Self { .. }) }
    pub fn devt(&self) -> Devt { self.devt }
    pub fn do_open(&self) -> KResult<()> { /* lookup_chrdev/blkdev(devt)?.open() */ }
    pub fn ioctl(&self, cmd, arg) -> KResult<usize> { /* dispatch */ }
}
impl Inode for DeviceNodeInode {
    fn ino(&self) -> Ino { self.ino }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.upgrade() }
    fn file_type(&self) -> FileType { self.ft }
    fn perm(&self) -> Option<u16> { Some(self.perm) }
    fn rdev(&self) -> u32 { self.devt.raw() }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(Enotdir) }
    fn read(&self, off, buf) -> KResult<usize> { /* lookup_chrdev/blkdev(devt)?.read() */ }
    fn write(&self, off, buf) -> KResult<usize> { /* …write() */ }
}
// + FifoInode, SocketInode (each their own struct + impl Inode), and
//   init_special_inode building `... as InodeRef`.
```

### AFTER (concrete struct + `i_private` data + shared ops + constructor)

```rust
// 1. per-instance state → i_private
pub struct DeviceNodeData { pub ft: FileType, pub devt: Devt }
fn device_data(inode: &Inode) -> KResult<&DeviceNodeData> {
    inode.private::<DeviceNodeData>().ok_or(VfsError::Einval)   // <- old as_any
}

// 2a. namespace ops (lookup only; metadata via trait defaults)
struct SpecialInodeOps;
impl InodeOps for SpecialInodeOps {
    fn lookup(&self, _inode: &Inode, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

// 2b. data ops — the old read/write/do_open, now reading devt off i_private
struct DeviceFileOps;
impl FileOps for DeviceFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = device_data(inode)?;
        match d.ft {
            FileType::CharDev  => lookup_chrdev(d.devt).ok_or(VfsError::Enxio)?.read(d.devt, off, buf),
            FileType::BlockDev => lookup_blkdev(d.devt).ok_or(VfsError::Enxio)?.read(d.devt, off, buf),
            _ => Err(VfsError::Eio),
        }
    }
    fn write(&self, inode, off, buf) -> KResult<usize> { /* symmetric */ }
    fn on_open(&self, inode) -> KResult<()> { /* the old do_open dispatch */ }
}

// 3. constructor
pub fn make_device_node_inode(ino, ft, devt, perm, sb) -> InodeRef {
    let mode = (ft.to_ifmt() as u32) | (perm as u32 & 0o7777);
    InodeBuilder::new(ino, mode, Arc::new(SpecialInodeOps), Arc::new(DeviceFileOps))
        .sb(sb).rdev(devt.raw())
        .private(Arc::new(DeviceNodeData { ft, devt }))
        .build()
}
```

`FifoInode`/`SocketInode` collapse the same way: both reuse `SpecialInodeOps`;
the FIFO binds `default_file_ops()` (the pipe `f_op` binds at `open`, so a bare
read is the default `EINVAL`), the socket binds a tiny `SocketFileOps` whose
`on_open` returns `ENXIO` (`sock_no_open`). `init_special_inode` switches on
`S_IFMT` and calls the three `make_*` constructors — returning `Arc<Inode>`
directly, no `as InodeRef` cast. The old public methods survive as free
helpers (`device_inode_devt`/`device_inode_open`/`device_inode_ioctl`) that
downcast `i_private`, so downstream callers keep the capability.

Net for devnode: three `pub struct` + three `impl Inode` (≈155 lines) → one
data struct + two shared ops + four constructors + three helpers, and the
behaviour is now keyed on the inode's stored `dev_t` rather than a bespoke
per-inode type.

## Same pattern, other vfs inodes already migrated

- `static_file.rs`: body → `StaticFileInode` (`i_private`); `StaticFileOps`
  reads it, `write`→`EROFS`; `make_static_file_inode` stamps `S_IFREG|0o444`.

## Downstream (Phase 2) and tests (B280b)

The 133 test files (`tests/`, `#[cfg(test)] mod tests` in src) and the
downstream kernel crates still `impl Inode for X` against the deleted trait —
they convert with this same recipe in B280b / Phase 2. `cargo build -p vfs`
(the lib) is green on host + both kernel arches at B280a; `cargo test -p vfs`
is expected RED until B280b.
