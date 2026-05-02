# 17 Block + Page Cache

FROZEN 2026-05-02. Dep:`01`,`02`,`06`,`08`,`09`,`10`,`11`,`12`,`16`. Provides: every FS; backed by `drv-virtio-blk`,`drv-nvme`,`drv-ahci`.

Two coupled subsystems:
- Block layer: dispatch I/O to block devices, batch+merge, async completion.
- Page cache: cache file-backed pages, serve VFS read/write, async writeback.

## 1 Frozen invariants

1. One owner per cache page: cached page belongs to exactly 1 `(Inode, off)`.
2. Dirty list integrity: every dirty page on exactly 1 writeback list at quiescence.
3. In-flight I/O accounting: page w/ in-flight I/O is `PG_LOCKED`, can't evict.
4. Write ordering: writes visible to subsequent reads same inode immediately (write-then-read consistency); dirty survives crash only after `fsync` returns success.
5. DMA safety: DMA buffers page-aligned, phys-contig when required, pinned for I/O duration.

## 2 Public ifc

```rust
pub trait BlockDevice: Send+Sync {
  fn block_size(&self) -> u32;            # 512 or 4096
  fn capacity_blocks(&self) -> u64;
  fn submit(&self, req:BlockRequest);     # async; cb on completion
  fn flush(&self) -> KR<()>;
}

pub struct BlockRequest {
  pub op: BlockOp,                         # Read|Write|Flush|Discard
  pub start_block: u64, pub len_blocks: u32,
  pub buffers: SmallVec<[BufferRef; 4]>,
  pub on_complete: Box<dyn FnOnce(KR<()>)+Send>,
}

pub struct PageCache { /* private */ }
impl PageCache {
  pub fn read_page(&self, ino:&Arc<dyn Inode>, off:u64) -> KR<Arc<CachedPage>>;   # # Sleeps:y
  pub fn write_page(&self, ino:&Arc<dyn Inode>, off:u64, data:&[u8]) -> KR<()>;
  pub fn fsync(&self, ino:&Arc<dyn Inode>, datasync:bool) -> KR<()>;              # # Sleeps:y
  pub fn invalidate(&self, ino:&Arc<dyn Inode>);
}
```

## 3 Block layer

Single-queue MQ-style. Per-device: submission ring (per-CPU SPSC where device supports, else per-device MPSC); completion runs in soft-IRQ.

Merge: adjacent reads same inode within 32-req window before submit.

Sched: `none` (FIFO) default; `mq-deadline`-equivalent feature-gated for spinning rust. NVMe+virtio-blk=none; AHCI=mq-deadline.

## 4 Page cache

### 4.1 Layout

`Inode` has `RadixTree<PageOffset, Arc<CachedPage>>`. Lookup O(log N), small N per file.

```rust
struct CachedPage {
  pfn: Pfn,
  flags: AtomicU32,    # PG_LOCKED|PG_DIRTY|PG_WRITEBACK|PG_REFERENCED
  refcount: AtomicU32,
  inode: Weak<dyn Inode>,
  offset: u64,
}
```

### 4.2 Read

1. Radix-tree lookup.
2. Hit ⇒ bump refcount, return.
3. Miss ⇒ alloc PMM frame, mark `PG_LOCKED`, submit `BlockRequest::Read`.
4. Caller waits (sync) or registers cb (async, io_uring).
5. On completion: clear `PG_LOCKED`, wake waiters.

### 4.3 Write (writeback)

1. Locate or alloc page.
2. Copy user data in.
3. Mark `PG_DIRTY`; per-inode dirty list + global dirty count++.
4. Return immediately.
5. Background `kflushd` walks dirty when total > threshold (default 10% RAM), submits writes.
6. `fsync` walks inode's dirty pages synchronously.

### 4.4 Eviction

LRU-2 (active+inactive). Reclaim daemon moves cold out on mem pressure. Dirty must be cleaned (written back) before eviction.

## 5 Concurrency

- Per-inode pagecache spinlock (sub-class `PageCache`, sibling of `Inode`).
- Per-page `PG_LOCKED` bit: contended-I/O serialization.
- Per-inode dirty list + global counter.
- Block submit ring: SPSC per-CPU where supported (modern virtio-blk queues) else MPSC.
- Completion in soft-IRQ; lock disciplines per `06§5`.

## 6 Perf budget

| Op | p99 cy |
|---|---|
| Pagecache read hit | 600 |
| Pagecache read miss submit path (no disk wait) | 3000 |
| Pagecache write (dirty path) | 800 |
| `fsync` clean inode | 1500 |
| Block submit uncontended | 1500 |

Disk-bound workloads = HW-limited, not these budgets.

## 7 Test contract (frozen)

- Pagecache property: random read/write/fsync/invalidate vs `BTreeMap<(Ino,off), Vec<u8>>` oracle; per-op assert invariants 1,4.
- Loom: read+write race same page; `PG_LOCKED` serializes; depth 6.
- Block fault injection: 10% submit failure rate; cb invoked with right error every time.
- Crash test: kill QEMU during `fs_mark` at 1000 random points; on reboot, journaling FS (ext4) `fsck` clean.
- Soak (bg, not gate per `40§3`): 4h cycles 4-CPU SMP, kernel-build-self + iperf + fs_mark + random R/W; zero corruption (SHA-256 corpus reconciles). PR-time gate uses `paranoid-ci` (`debug-pagecache`).
- Coverage ≥95%.

## 8 Failure modes

- Disk write error: page stays dirty; error at next `fsync`. After N consecutive fails (configurable), inode marked EIO; writes fail until reopen.
- Mem pressure preventing readahead: silently skip readahead.
- DMA buffer non-contig when device needs: bounce buffer from reserved low-mem pool.

## 9 Debug

`debug-pagecache`: per-page state machine audit per op.

## 10 Log

`target="pagecache"`,`"block"`. trace=per-page transition (debug only); debug=read/write/fsync/invalidate; warn=I/O fail; error=EIO inode mark.

## 11 Cross-spec

`10` (PMM frames), `11` (file mmap PT setup), `12` (slab for `CachedPage`/`BlockRequest`), `16` (VFS reads through here), `30` (io_uring async I/O hook), `35` (driver `submit`/completion).

## 12 Changelog

(none)

