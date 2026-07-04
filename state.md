# state.md — session handoff

## Headline
THREE bugs FOUND+FIXED (committed+pushed, B318): 2 mount-ns bind-sharing + a
NETLINK UNICAST bug (39221106) that was the primary udev amplification source.
Before the netlink fix, systemd-udevd's manager dispatched each uevent to ONE
worker by addressing that worker's netlink PORT (nl_pid, nl_groups=0), but our
sendmsg IGNORED the destination nl_pid and BROADCAST it to all group-0 sockets —
so EVERY worker ran EVERY event (~20× amplification) → udev queue never drained →
card0 (SEQNUM 50) never processed → no master-of-seat → CAN_GRAPHICAL=0.
With the fix, card0 IS now processed (queue drains past 50; was halting ~47) and
CAN_GRAPHICAL reaches 1. Greeter STILL doesn't render: boot is still ~145s
(a RESIDUAL worker→manager completion loop re-processes each event ~25×), so
CAN_GRAPHICAL=1 lands at ~132s — AFTER gdm already started+exited code=1 at
~105s. Fix the residual completion loop → faster boot → CanGraphical ready before
gdm → greeter.

## Fixes landed this session (branch B318, pushed)
- b71fb455 fix(devfs): register /dev/hugepages mount-point dir (systemd
  per-service sandbox binds it; was ENOENT).
- 29194e13 fix(vfs): thread walked DEST mnt_id through MS_MOVE
  (`move_mount_by_id_to`) — bind-shared dentry defeated parent_by_dentry, so
  MS_MOVE onto /run/systemd/mount-rootfs/<sub> was falsely rejected "dest within
  source subtree". Fixed 12/13 namespace MS_MOVEs.
- e66f8386 fix(vfs): thread walked PARENT mnt_id through mount graft
  (`register_at`/`register_bind_at`/`attach_sb_with_flags_at` + parent_hint in
  attach/graft_realized). systemd creates the apivfs at /run/systemd/namespace-X
  AFTER rbinding / onto /run/systemd/mount-rootfs, so the /run root dentry is
  bind-shared and the new mount was BORN parented under mount-rootfs/run
  (rendered /run/systemd/mount-rootfs/... — unreachable via real /run). Now
  renders correctly. 41 hosted vfs mount tests green.
- crates/kernel/vfs/tests/sandbox_nested_primary.rs added (passes; note: the
  string-keyed hosted fixture can't reproduce true bind-dentry ambiguity, so it's
  a non-regression guard, not the repro — the repro is the boot trace).

## KEY measured finding: code=265 storm is NOT the greeter blocker
- mount(2) failures ≈ 0 after the two mount fixes (was assumed to be the cause —
  it was NOT; measure-don't-guess paid off).
- ~25 `code=265` exits are `sd-executor` (`/proc/self/fd/9`) probe-forks that
  exit after `waitid=ECHILD` + `pause=EINTR`; 265 > systemd's EXIT_ range
  (max ~246) so it's not EXIT_NAMESPACE. Services like upower still reach
  "Started" afterward. Treat 265 as a red herring until proven otherwise.

## RESIDUAL to fix — worker→manager completion loop (boot too slow)  [START HERE]
The netlink UNICAST fix (39221106) removed the BROADCAST-dispatch fan-out (was:
manager dispatch to one worker got broadcast to ALL workers → every worker ran
every event). card0 now processes; CAN_GRAPHICAL reaches 1. But each event is
STILL re-processed ~25× because the manager RE-DISPATCHES — the worker→manager
COMPLETION isn't registering. Measured:
- Completion is NETLINK, not socketpair (udevd creates only ONE socketpair all
  boot; per-worker comms are netlink).
- Manager = netlink port 6, bound group-1 (kernel monitor); it dispatches to
  workers via unicast FROM port 6 (my fix delivers these, found=1). No netlink
  message is ever sent back TO port 6 — so workers do NOT unicast completions to
  the manager; they BROADCAST results (nl_groups=2).
- rebroadcast_cooked_uevent SKIPS every group-1 socket (netlink/src/lib.rs ~329
  `if (grp & 1) != 0 continue`) — so the worker-result broadcast (dgrp=2) is
  NEVER delivered to port 6 (measured: port 6 skipped 118×). If port 6 is the
  manager's ONLY monitor, it never learns events completed → re-dispatch loop.
- RESOLVED by measurement (trace: log recvmsg reader exe when dequeuing a
  libudev-magic datagram): ZERO group-2 readers exist. Cooked RESULT broadcasts
  are read only by port=2 (empty exe = PID1, 87×, legit) and by the udev WORKERS
  themselves (ports 8-16, exe=systemd-udevd, ~10× each — they uselessly DRAIN the
  broadcasts because register_uevent_listener subscribes EVERY uevent socket at
  socket(2), even a worker's send-only result monitor). The MANAGER (port 6) reads
  NONE. So the manager has NO netlink channel for worker completions → it
  re-dispatches until it gives up (~20-25×/event), bounding the loop but wasting
  the whole boot.
- WHERE TO LOOK NEXT (needs systemd-source review, not just kernel traces): how
  does systemd v257 udev-manager RECEIVE worker completion? Options: (a) worker
  UNICASTs the result to the manager's monitor port — then our sendmsg is reading
  a wrong/zero dest nl_pid for the worker's result send (I saw worker result
  sends as dest_pid=0 groups=2 = broadcast, NOT unicast to port 6 — verify the
  worker's msg_name offset/content; if systemd DOES set a dest, we're dropping
  it); (b) completion is the worker's EXIT (SIGCHLD/pidfd) not a message — then
  audit our SIGCHLD/pidfd/waitid for workers (ties to the earlier sd-executor
  waitid=ECHILD finding); (c) the manager's result monitor needs a group we
  aren't delivering. Read src/udev/udev-manager.c on_worker / worker_returned +
  device_monitor. CAUTION: do NOT deliver cooked to the group-1 kernel monitor
  (libudev rejects libudev-magic on a kernel monitor; skip is a deliberate
  busy-loop guard). SECONDARY cleanup: workers shouldn't be subscribed as uevent
  LISTENERS at all (their result monitors are send-only) — register_uevent_listener
  over-subscribes; gating subscription on an actual bind/group would stop workers
  draining broadcasts.
- Consequence of the loop: boot ~145s; CAN_GRAPHICAL=1 lands ~132s AFTER gdm
  started+exited code=1 at ~105s → greeter never launches. Even in a
  CAN_GRAPHICAL=1 boot, no gnome-shell (checked). Fix the loop → fast boot →
  seat graphical before gdm → greeter.
- Method to continue: re-add klog to netlink/Cargo.toml; trace emit/dequeue
  (port+group+cooked)/send(dest_pid+groups)/unicast(from,to,found) in
  netlink/src/lib.rs + syscalls/src/netlink_fd.rs (all reverted now).

## (superseded) earlier framing — CAN_GRAPHICAL=0 = udev RE-PROCESSING loop
MAJOR advance this session: the CanGraphical blocker is NOT mount and NOT module
loading — it is a **udev event-reprocessing amplification loop**. Measured (all
via kernel klog traces on the netlink uevent path, since reverted):
- Kernel emits each uevent EXACTLY ONCE (51 emits, 51 distinct seqnums; card0 =
  seq 50 emitted once, delivered to udevd's group-1 socket once). NOT a kernel
  duplication bug.
- udevd reads each RAW kernel event EXACTLY ONCE (raw dequeue = 1 per seq,
  grp=1). Correct.
- BUT each event is RE-PROCESSED ~20× by udev WORKERS: the COOKED libudev result
  for one device (e.g. SEQNUM=32) is SENT ~20× (traced in
  netlink::rebroadcast_cooked_uevent — senders are worker ports 6,8-16) and
  dequeued ~40× by monitors (port=2 = systemd PID1, grp=0, gets ~21 copies;
  later-created monitors get fewer → early events loop more before udevd's ~36s
  idle-cleanup). Re-processing count DECREASES over seqnum (seq33 ~59×, seq48
  ~3×) — bounded by the 36s cutoff, consistent with a re-dispatch loop.
- CONSEQUENCE: workers spend all their time re-processing seqnums 31-49; card0
  (SEQNUM 50) is "queued"+"ready" (~23s) but NEVER gets a worker; udevd idles at
  ~36s with card0 pending → card0 never tagged systemd/master-of-seat →
  `/run/udev/data/c226:0` never written → CAN_GRAPHICAL=0 → gdm exits code=1.
- ROOT: udevd re-dispatches each event ~20× because the WORKER→MANAGER
  COMPLETION signal is not registering. In systemd udevd the worker sends the
  processed device to the manager (addressed netlink unicast on MONITOR_GROUP_UDEV,
  OR a socketpair — DETERMINE WHICH) so the manager marks the event done. Our
  amplification is the symptom; the completion channel is the bug.
- DISPROVEN (measured, don't re-chase): kernel emit dup; recv re-read
  (recvmsg/recvfrom correctly dequeue vs MSG_PEEK); duplicate listener
  registration (register_uevent_listener: 0 "already", list bounded ~13);
  finit_module slowness (0 finit_module calls — modules are built-in).
- SUSPECT: netlink::rebroadcast_cooked_uevent (netlink/src/lib.rs ~290) SKIPS
  every group-1 socket (`if (grp & 1) != 0 continue`); port=6 (grp=1, also a
  worker sender) is skipped 109×. If the manager's completion-receiving socket
  has the group-1 bit set, it never gets worker results. NEXT: (1) confirm the
  worker→manager completion channel (netlink unicast vs socketpair) by tracing
  which port DEQUEUES the cooked result addressed to the manager, or by checking
  if udevd uses a socketpair (then the bug is in our AF_UNIX/pipe IPC, not
  netlink); (2) fix delivery so the manager registers completions ONCE per event.
  Trace recipe: add [UEMIT]/[UDEQ R|C grp/port]/[USEND]/[USKIP] klog lines to
  netlink/src/lib.rs emit_uevent_with_env / dequeue / rebroadcast_cooked_uevent
  (needs `klog` dep added to netlink/Cargo.toml), grep per-seq counts.
- LEADING FIX HYPOTHESIS (verify before coding): our netlink recvfrom/recvmsg
  stamps the source address `nlmsg_pid = 0` (kernel) for ALL cooked receives
  (netlink_fd.rs ~416-421) because rebroadcast_cooked_uevent enqueues a bare
  `msg.to_vec()` and does NOT record the sender's port. If the udevd MANAGER
  distinguishes a worker-completion (cooked, sender = worker pid) from a fresh
  kernel event (sender pid 0) by that source pid, stamping 0 makes it treat each
  worker completion as a NEW kernel event → re-queue → re-dispatch → the 20×
  loop. Candidate fix: carry the sender port_id alongside each queued datagram
  (rx_queue becomes (msg, src_port)) so recvfrom stamps the true sender for
  cooked worker→manager messages. RISK: the existing pid=0 stamping is validated
  for PID1's group-0 monitor (code comment, netlink/src/lib.rs ~264) — don't
  regress that; only worker→manager cooked unicast needs the real pid. Confirm
  the manager's check first (read systemd udev-manager.c on_uevent / libudev
  udev_monitor_receive_device sender validation) before changing the stamp.
- gdm exits code=1 (059_execve: only execs plymouth=ENOENT, non-fatal) — a
  downstream symptom of CAN_GRAPHICAL=0. Fix the reprocessing loop first.

## Diagnostic method (measure, don't guess — enforced this session)
- Mount parent/dest bugs cracked by: trace each EINVAL return tag in
  move_mount_m; dump the mount table (id, parent_id, rendered_path) at the
  reject; then a [GRAFT] trace at creation showing the mount born with the wrong
  parent. All traces reverted after use.
- The bind-dentry ambiguity is the recurring theme (see auto-memory
  "mount-dentry-sharing-gotcha"): ALWAYS pass the walked path->mnt, never
  re-derive a mount from a bare dentry when binds are in play.

## Boot harness
`bash <scratchpad>/boot.sh <log> 200` (kills stale qemu, boots live-gnome ISO,
serial→log). Build: `cd ../oxide-images && make kernel ARCH=x86_64 && cd
../kernel && cargo run -q -p xtask -- artifacts --arch x86_64 && cd
../oxide-images && cargo run -q -p imagectl -- build-boot --profile live-gnome
--arch x86_64`. STALE-ARTIFACT TRAP: a compile FAIL still lets `xtask artifacts`
export the last-good kernel — always confirm the build `Finished` line.
Checks: `grep CAN_GRAPHICAL <log>`; `grep -c code=265 <log>`;
udev queue: `grep 'Device processed' <log>`; card0: `grep -i card0 <log>`.

## Ledger
metadata/index.md: B next=319 (318 in use this session), D next=120, F next=650.
