# state.md — session hand-off

## Headline
N22 (and greeter/desktop blockers) are SYMPTOMS of slow process/service startup —
proven NOT netlink/udev/NM. Two costs; TWO perf fixes landed this session with a
measured boot speedup. main @ bd5a8e163.

## Root cause + what's fixed (evidence-backed, clean KVM boots)
Services take 15-62s (Linux 2-5s). N22's SSH-forward times out because NM never
finishes → no DHCP. The cost is ext4 per-page-fault block I/O.
- **B1382 (PR#3895)** framecache `shared_frame` (MAP_SHARED): skip the per-fault
  inode-table BLOCK read on a cache hit. bash script children 13.6s→0.06s (~200×).
- **B1383 (PR#3897)** framecache `read_framed`/`write_buffered` (MAP_PRIVATE — the
  executable/library path) + `ensure_page`: read the on-disk inode ONLY on a
  genuine page miss (was every call, an uncached busy-polled ~10ms read). Measured:
  resolved 15→10s, logind 34→23s, NM 62→50s; multi-user.target ~15s sooner.

## Next win (the remaining dominant cost)
Cold demand-fault DATA block reads: `fill_page` (framecache.rs:120) reads file
blocks ONE at a time (`read_file_block` loop), one virtio-blk read per 4KB page,
SERIALIZED (`drv-virtio-blk wait.rs acquire_turn` = one request in flight, no
pipeline). A lib faults hundreds of pages = hundreds of serial round-trips.
**Fix = READAHEAD/clustering:** on a fault miss for page X, fill a contiguous run
X..X+N in one multi-block read (the writeback path already clusters via
DATA_WRITE_CLUSTER_BYTES — mirror that for reads). Touches the fault-fill path;
do it carefully. (Tried a per-inode inode cache — NO measurable boot benefit, data
reads dominate, discarded.) Secondary: virtio-blk request pipelining (multiple
in-flight) — driver concurrency, higher risk.

## Proven NOT the cause (do not re-open)
udev processes eth0 (/run/udev/data/n2 — needs debug-udevdb to see); netlink
dump/ack/ns correct; af_unix→epoll + scheduler wake paths correct; the IP-seed and
IFF_UP flags are red herrings. See memory `boot-slowness-root-cause`.

## Merged this session (15 PRs, all both-arch built)
Net parity: B1373-B1377, B1379-B1381 (bind_file build, subsystem symlink, notifier
+getlink test, IPV6_TCLASS, rtnetlink neighbor, netlink trace, DEVTYPE, net attrs).
Perf: **B1382, B1383**. Docs: D371, D372.

## Parked: B1378 (local, unmerged) — IP-seed removal + admin-down NIC regs. Linux-
correct but blocked (regresses to no-network until DHCP works). Orthogonal to the
slowness. Resume only after the fault-fill readahead lands + DHCP verified.

## Tooling
Boot CLEAN (`OXIDE_QEMU_FEATURES=""`) to measure — debug UART spam is NOT the
slowness. Service durations = systemd `Starting`→`Started` gaps in the harness log.
KVM confirmed (/dev/kvm). NM TRACE: debugfs-write an NM conf.d into
target/builds/<ID>/root-x86_64.img (harness already debugfs-writes safely).
Counters: B next=1384.
