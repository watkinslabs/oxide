# state.md — session hand-off

## Headline
N22 (and the greeter/desktop blockers) RE-ROOTED: NOT netlink/udev/NM — those all
work (proven). They are SYMPTOMS of **slow process/service startup**. Two distinct
costs found; ONE fixed this session with a measured ~200× spawn win. main @
8bf1d80b0.

## The real problem (evidence-backed, instrumented boots)
Under KVM, services take 15-62s to start (Linux: 2-5s). N22's SSH-forward times
out because NM never finishes → no DHCP. TWO costs:
1. **Process-SPAWN cost = per-fault ext4 block I/O. FIXED (B1382/PR#3895).**
   `ext4 shared_frame` did a block-device inode read + csum recompute on EVERY
   page fault, even framecache hits. Now checks the page cache first. Measured:
   a bash script's children went 13.6s-to-first-command → ~0.06s apart.
2. **Service/IPC-WAIT cost = D-Bus activation / af_unix waits. OPEN.**
   B1382 did NOT speed up NM/logind/resolved (they're wait-bound, not spawn-
   bound). Smoking gun: NM's `StartServiceByName(hostname1)` TIMES OUT at 25s.
   Mechanism = the DOCUMENTED [[desktop-blocker-tmpfiles-userdbd]] bug: **af_unix
   listener accept-readiness not waking the accepting service's epoll** → D-Bus
   activation stalls → services crawl. See memory `boot-slowness-root-cause`.

## Proven NOT the cause (do not re-open)
udev DOES process eth0 (`/run/udev/data/n2` — traces need `debug-udevdb`, absence
last session was instrumentation-blind); netlink dump/ack/ns all correct; the
IP-seed and IFF_UP flags are red herrings (removing them → NM identical).

## FIRST TASK next session
Attack cost #2: **af_unix accept-readiness → accepting service's epoll wakeup.**
Trace a socket-activated service (userdbd/hostnamed): when a client connects to
its listening af_unix socket, does the listener's POLLIN/accept-readiness wake the
service's epoll_wait promptly? Files: `net/src/unix_sock/{listener,events}.rs`
(wake_peer_subs → notify_epoll_waiters), the epoll readiness path in sched/vfs.
Also open on the fault path (cost #1 remainder): `framecache mark_dirty` fires on
read-only code faults → needless writeback (move dirtying to the write path;
MAP_SHARED writes must still be tracked — data-loss risk if done naively).

## Merged this session (13 PRs, all both-arch built)
B1373 net plain-build · B1374 subsystem symlink · B1375 notifier+getlink test ·
B1376 IPV6_TCLASS · B1377 rtnetlink neighbor · B1379 netlink trace · B1380
DEVTYPE · B1381 net attrs + debug-udevdb/NL-REQ traces · **B1382 framecache
per-fault inode read (the 200× spawn fix)** · D371 doc.

## Parked: B1378 (local, unmerged) — IP-seed removal + admin-down NIC regs. Linux-
correct but blocked (regresses to no-network until DHCP works). Orthogonal to the
slowness root; resume only after cost #2 is fixed.

## Tooling
Boot CLEAN (`OXIDE_QEMU_FEATURES=""`) — debug UART spam is NOT the slowness (clean
≈ debug service times). NM TRACE: inject via `debugfs -w write` an NM conf.d file
into `target/builds/<ID>/root-x86_64.img` (harness already debugfs-writes safely).
Harness caps boot 180s; raise QEMU_TIMEOUT_MAX to watch past it. KVM confirmed
(/dev/kvm). Counters: B next=1383.
