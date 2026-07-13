Boot investigation notes, 2026-07-10

Scope: no code changes. Derived from `state.md`, `scratch/poll.md`, current
source, and `log.txt`.

Problem 1: all-idle missing wakeup after systemd-userdbd

Observed state:
- `state.md` reports ext4 corruption fixed, then boot reaches userdbd and later
  stalls with `CPU-STALL ... nr_running=0`.
- `nr_running=0` means this is not a runnable spin or transaction-gate deadlock.
  All tasks are asleep and nothing delivered the wake that should make progress.
- `log.txt` shows `systemd-userdbd.socket` listening at ~10.739s and
  `systemd-userdbd.service` started at ~13.213s.

Most likely mechanism:
- AF_UNIX listener readiness itself appears correct. In
  `crates/kernel/net/src/sock/io.rs`, `SockKind::UnixListener` returns
  `POLL_IN | POLL_OUT` when `accept_q` is non-empty.
- `UnixRegistry::connect()` in `crates/kernel/net/src/unix_sock/listener.rs`
  pushes the pair into `listener.accept_q`, wakes blocking `accept()` waiters,
  then calls `listener.notify_subs()`.
- The weak point is epoll subscription identity. In
  `crates/kernel/fs/src/epoll.rs`, `EPOLL_CTL_ADD` subscribes to the watched
  inode with `subs.subscribe(ep.id, weak)`.
- In `crates/kernel/vfs/src/poll_subs.rs`, `subscribe_flags()` treats `id` as
  unique and replaces an existing subscription with the same id.
- Therefore the subscriber key is the epoll instance, not the watched fd /
  epitem. A single epoll watching multiple fds on a shared subscriber source can
  replace its own prior registration.
- `EPOLL_CTL_MOD` only mutates the local `EpollEntry`; it does not re-register
  the `PollSubscribers` mask/exclusive state.

Conclusion:
- This can produce exactly the observed shape: the listener would report ready
  if scanned, but the epoll waiter never receives the direct wake, all tasks go
  idle, and watchdog reports `nr_running=0`.
- This is Linux-model wrong: Linux registers callbacks per epitem/waitqueue, not
  per epoll instance.

Evidence anchors:
- `crates/kernel/fs/src/epoll.rs`: `EpollEntry` has no per-subscription id.
- `crates/kernel/fs/src/epoll.rs`: ADD calls `subs.subscribe(ep.id, weak)`.
- `crates/kernel/fs/src/epoll.rs`: MOD only changes `events`, `data`,
  `et_seen`.
- `crates/kernel/fs/src/epoll.rs`: DEL unsubscribes with `ep.id`.
- `crates/kernel/vfs/src/poll_subs.rs`: same id replaces existing subscription.
- `crates/kernel/net/src/unix_sock/listener.rs`: connect pushes accept queue then
  calls `notify_subs()`.

High-value proof trace:
- Log `epoll_ctl ADD/MOD/DEL`: ep id, fd, inode, event flags, subscription key.
- Log `UnixRegistry::connect`: path, accept queue len before/after, whether
  `notify_subs()` upgraded a live subscriber, subscriber generation.
- Log userdbd epoll scans only: fd, raw poll mask, wanted events, `et_seen`,
  `last_gen`, `last_ggen`.

Problem 2: intermittent SMP virtio #PF during PCI enumeration

Observed state:
- `state.md` reports intermittent SMP virtio `#PF` during PCI enumeration with
  `cr2` equal to a virtio notify page.
- One boot reached the later all-idle stall, another faulted around 11s.
  Flakiness suggests timing/CPU placement, not deterministic device decode.

Most likely mechanism:
- `crates/arch/hal-x86_64/src/mmu_ops.rs` already documents the exact class:
  device MMIO BARs are spliced into the active boot address space after
  `capture_kernel_master()`, while APs boot using `kernel_master()`. If the
  master lacks those BAR mappings, an AP access to a virtio BAR VA faults.
- Boot ordering confirms the race:
  - `crates/kernel/kmain/src/kmain/runtime.rs` calls `init_smp(info)` before
    `init_network_and_pci()`.
  - `init_network_and_pci()` runs `pci_boot::enumerate_and_log()`.
  - Virtio PCI probe maps common/config/notify BAR pages during enumeration via
    `TransportMappings::map_page()` and `map_queue_notify_va()`.
  - `crates/kernel/kmain/src/kmain/rootfs.rs` calls
    `hal_x86_64::mmu_ops::resync_kernel_master()` later, at rootfs init.
- AP startup code in `crates/kernel/arch-irq/src/smp_x86.rs` explicitly uses
  `hal_x86_64::mmu_ops::kernel_master()` as the AP CR3.

Conclusion:
- On x86 SMP, APs are already alive on the stale master page table before
  virtio BAR/notify pages are mapped during PCI enumeration. If an AP touches
  one of those VAs before the later rootfs resync, it can #PF. That matches
  `cr2 = virtio notify page` and intermittent behavior.

Evidence anchors:
- `crates/arch/hal-x86_64/src/mmu_ops.rs`: comment above
  `resync_kernel_master()` describes AP missing post-PCI BAR mappings.
- `crates/kernel/kmain/src/kmain/runtime.rs`: SMP starts before PCI.
- `crates/kernel/kmain/src/kmain/rootfs.rs`: master resync happens later.
- `crates/kernel/pci-boot/src/virtio_transport.rs`: notify VA mapped from BAR
  page during virtio probe.
- `crates/kernel/arch-irq/src/smp_x86.rs`: AP trampoline loads
  `kernel_master()` CR3.

High-value proof trace:
- On `#PF`, log CPU id and classify whether `cr2` is in
  `0xffff_fd00_0000_0000` MMIO-map space.
- Log every `mmio_map::map_pages()` call: CPU id, active CR3, PA, VA.
- Log `resync_kernel_master()` timing relative to PCI enumeration and AP online.

Likely fixes, not applied:
- Epoll: allocate a unique subscription id per `EpollEntry`; ADD/MOD/DEL use
  that id, not `ep.id`; MOD re-registers mask/exclusive state.
- AF_UNIX: longer-term, listener owns the real readiness subscriber list and
  the listener socket inode exposes that same list; avoid cached weak side
  pointer as the event source.
- x86 SMP/MMIO: ensure kernel master and active CR3 share/post all PCI MMIO
  mappings before APs can touch them, or reorder PCI/MMIO mapping before AP
  bring-up, or resync immediately after each post-master MMIO splice while APs
  are online.
