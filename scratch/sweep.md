# Build-warning sweep — findings ledger

Source: the C239–C242 warning sweep (`xtask kernel` x86_64/aarch64 + `cargo check
--workspace --all-targets`, 3178+470+454 warnings → 0). Every `dead_code` warning
was classified rather than blanket-allowed, because the dominant defect class in
this repo is machinery with no callers. This file is what that classification
FOUND — the code issues the warnings were hiding. Nothing here is fixed by the
sweep PRs except where the Status says so.

Status: `OPEN` unclaimed · `CLAIMED <branch>` · `DONE <sha/PR>`.
Every in-tree item also carries an `#[expect(dead_code, reason = "no caller: …")]`
or `#[allow(dead_code, reason = …)]` at the site, so `grep -rn 'no caller:'` is
the live index and an item that gets wired up breaks its own `expect`.

## 1 — Correctness bugs (not dead code; found while triaging)

| Status | Branch | Item | Where | What |
|---|---|---|---|---|
| DONE #4167 | B1510-unix-dgram-bpf-wmem | AF_UNIX dgram `wmem` leak on BPF verdict | `net/src/unix_sock/dgram.rs:216-262` | `try_push_owned` charges `owner.wmem` with `message_charge(len)` BEFORE the filter runs; `try_push_from_with_rights_bounded_owned` ignores that value (param is `_charge`) and stores a RE-computed post-truncation charge in the record, which is what `Drop`/`sock_wfree` subtracts. Two leaks: a truncating filter leaks `pre-post` bytes per datagram, and a `verdict == 0` drop returns `Ok(())` having queued nothing, leaking the WHOLE charge. Leaks are permanent — once `wmem_alloc` passes `unix_writable`, the sender is stuck at `EAGAIN` forever. **The `_charge` underscore was introduced by the C240 lint pass itself (`21c74924a`), i.e. the sweep silenced the symptom; that is why it is item 1.** |
| DONE #4168 | B1511-rtnetlink-route-metrics | `parse_metrics` reads only the first attribute | `netlink/src/rtnetlink_route.rs:38-51` | Every arm of the `while` body returns, so the loop is a disguised `if` and `off` never advances (which is why it needed no `mut`). An `RTA_METRICS` blob whose first nested attr is not `RTAX_MTU` gets `Unsupported` even when `RTAX_MTU` follows. The sibling `parse_nh_attrs` at :57 does it correctly — copy that shape. |
| DONE 848f0127f | B1512-route-metrics-compliance | Route metrics are MTU-only instead of Linux-compatible | `netlink/src/rtnetlink_route.rs`, `netlink/src/rtnetlink/{route_ops,route_state}.rs`, `net/src/route.rs`, `docs/25-net.md §10` | B1511 fixed nested traversal but still dropped `RTAX_LOCK`, WINDOW, RTT, RTTVAR, SSTHRESH, CWND, ADVMSS, REORDERING, HOPLIMIT, INITCWND, FEATURES, RTO_MIN, INITRWND, QUICKACK, CC_ALGO, and FASTOPEN_NO_COOKIE; skipped their payload and value validation; lost them on route dump/notification and alias comparison; and did not apply retained metrics to route/TCP behavior. B1512 preserves, validates, matches, dumps, and consumes the complete selected metric state through IPv4 and active/passive TCP. |
| DONE | #4163/#4164 | virtio probe freed DMA frames after an unconfirmed reset | `pci-boot/src/virtio_transport/{msix,devres}.rs` | `reset_failed_probe` dropped `virtio::reset_device`'s `#[must_use] -> bool`; `release_failed` then recycled the probe's frames unconditionally — free-while-device-may-still-own-it. Now propagated: frames leak instead of being recycled when the reset is unconfirmed. **Behaviour change on the failed-probe path — wants an eyeball.** |
| DONE | #4165 | `psi::parse_u64` shadowed the Linux parser | `sched/src/psi.rs` | Superseded by `parse_u32_prefix` (B1506's Linux-`%u` sscanf semantics). Deleted. |

## 2 — Missing wiring (code is correct, nothing calls it)

Ordered by consequence. All annotated in-tree.

| Status | Branch | Item | Where | Consequence |
|---|---|---|---|---|
| DONE 15a1d549b | C243-rebuild-vendor-wiring | `--rebuild-vendor` was parsed by nothing | `tools/xtask/src/gc.rs:227,255` | `rebuild_vendor` + `all_vendor_pkgs` had no call site while `tools/qemu-mcp/server.py:439` forwarded the flag to `xtask grub`, so requested rebuilds silently booted stale vendor artifacts. Both GRUB architectures now share a preparation path that rebuilds the validated package set before rootfs staging; the hosted test executes real fixture scripts and asserts ordering. |
| DONE 5e9853588 | B1513-bridge-arp-validation | Bridge-owned IPv4 ARP ingress was misclassified as missing | `net/src/stack/ethernet.rs`, `net/src/stack/bridge_tests.rs` | `deliver_ethernet_meta_in` already reacquires the bridge as the L3 ingress owner and invokes canonical `arp_answer_request` (since `3fea2b562`). A live-ingress regression now proves the bridge replies with its MAC and IPv4 address, and the redundant dead `bridge_answer_arp` copy is removed. The reported reachability bug was not live. |
| DONE 663f42150 | B1514-signal-restorer-semantics | Signal delivery ignored architecture-specific `SA_RESTORER` rules | `fs/src/sig_dispatch.rs`, `syscalls/src/signal_dispatch.rs` | The shared frame boundary now rejects x86_64 user-handler delivery without `SA_RESTORER` before mutating signal state, matching `x64_setup_rt_frame`. On aarch64 it preserves a flagged user trampoline verbatim and otherwise selects the current mm's stored vDSO `__kernel_rt_sigreturn`, covering both syscall-tail delivery and the direct undefined-instruction/SIGILL path. The duplicate per-delivery vDSO ELF lookup is removed. |
| DONE ae09c1a95 | B1515-sock-diag-family-dispatch | `sock_diag` had no `sdiag_family` dispatch | `netlink/src/sock_diag.rs` | Modern requests now reach inet-diag only for AF_INET/AF_INET6, return `EINVAL` for `family >= AF_MAX`, and return `ENOENT` for in-range unregistered families or protocols. Truncated requests also return `EINVAL`; no invalid request receives a successful inet dump terminator. Wire-level tests cover every boundary. |
| OPEN | — | AHCI has no interrupt path at all | `drv-ahci/src/regs.rs:11,20,35` | `HBA_IS`, `GHC_IE`, `P_IE` unreferenced; the driver busy-polls PxCI/PxTFD. Same class as the recorded "kernel runs IF=0 during block waits" latency root cause. |
| DONE b4161f708 | B1516-ahci-hba-reset | AHCI never resets the HBA | `drv-ahci/src/{port,regs}.rs` | `bring_up` now follows Linux ordering: enter AHCI mode (with latch retries), assert `GHC.HR`, enforce the spec's one-second self-clear deadline, then restore AHCI mode before reading PI or allocating DMA state. Enable/reset failures abort probe instead of inheriting firmware-left controller state. |
| DONE 860dc7c58 | B1517-ahci-dma-address-mask | AHCI writes 64-bit DMA bases without checking `CAP.S64A` | `drv-ahci/src/{port,regs}.rs` | `bring_up` now reads `CAP.S64A` and validates the complete 4 KiB range of every command-list, received-FIS, command-table, and bounce frame. A 32-bit-only HBA accepts only ranges ending below 4 GiB; rejected allocations are all freed and probe fails instead of programming truncated DMA addresses. |
| DONE 71592ed20 | B1518-nvme-mqes-queue-depth | NVMe never clamps queue size to `CAP.MQES` | `drv-nvme/src/{queue,regs}.rs` | Queue depth is now per queue. The Admin SQ/CQ remains independently sized to 32 through AQA, matching Linux/NVMe semantics; the I/O SQ/CQ depth is `min(32, CAP.MQES+1)` and that negotiated value drives both CREATE_IO QSIZE fields plus submission/completion ring wrap. |
| DONE d5127e2d5 | B1519-zram-recompress-priority | zram re-compresses slots already at target priority | `drv-zram/src/{state/slot,writeback/recompress}.rs` | The recompression scan now skips resident slots whose recorded compressor priority is already equal to or above the requested secondary priority, before decompression, idle-state clearing, allocation, or `max_pages` consumption. A regression proves a same-priority retry leaves an idle slot untouched. |
| OPEN | — | `proc_dobool` exists, no knob declares it | `procfs/src/ctl.rs:153` | `Leaf::Bool` is fully materialised but no `TREE` row uses it, so every Linux `proc_dobool` sysctl is absent from `/proc/sys`. |
| DONE 52fe91d0e | B1520-debugfs-null-fops | debugfs refuses a NULL-fops file instead of substituting a no-op | `modules/src/linux_debugfs.rs` | Both file-creation APIs now substitute shared no-op operations for NULL fops, matching Linux: reads return EOF, writes consume the supplied bytes, and sized entries retain their declared inode size. A regression covers creation and I/O through both paths. |
| DONE 389ee2085 | B1521-sigreturn-mxcsr-feature-gate | sigreturn MXCSR check is not gated on the frame's features | `hal-x86_64/src/signal/xstate.rs` | XSAVE restore now validates MXCSR only when the user header enables x87, SSE, or YMM, while the FXSAVE and fx-only paths retain unconditional validation. Regressions prove YMM-only state still checks MXCSR and a header with all related features absent accepts reserved legacy bits that XRSTOR ignores. |
| DONE fff1539cb | B1522-gic-ppi-level-config | level-sensitive PPIs silently stay edge | `arch-irq/src/gic/{lines,regs}.rs` | The level-enable path now clears the selected PPI trigger bit in this CPU's `GICR_ICFGR1` before enabling the private line. SPI and PPI configuration share a Linux-shaped encoder that changes only bit `2N+1`; its hosted regression proves level/edge selection without hiding tests behind the kernel-only ARM gate. |
| DONE a20569f1e | B1523-debug-watchdog-detail | `debug-watchdog` is unreachable from any kernel build | `kmain/Cargo.toml`, `mm-pmm/src/buddy/{api,poison}.rs` | The new non-default `debug-watchdog-detail` aggregate reaches the PMM, VMM, and syscall probes without changing the default-on liveness watchdog. `debug-all` selects the aggregate. PMM now checks each poison-identified free-page body after buddy removal but before allocation zeroing, excluding the legitimate 32-byte intrusive header; a hosted allocation-path regression proves the detector observes a stale write before the returned page is cleared. |

## 3 — Split sources of truth still open

| Status | Branch | Item | Where |
|---|---|---|---|
| DONE 6450d9ac1 | B1524-kernel-stack-size-source | `IRQ_STACK_BYTES` defined three times, plus a fourth spelling | `hal/src/lib.rs`, `hal-{x86_64,aarch64}`, `sched/src/kstack.rs` | `hal::KERNEL_STACK_BYTES` is now the dependency-safe owner shared by task stacks, per-CPU IRQ-stack range checks, AArch64 register diagnostics, and both architectures' entry assembly. Scheduler page counts derive from it, while `global_asm!` receives it as a const operand, so changing the stack allocation cannot leave stale numeric bounds in exception entry. |
| DONE d70d74fc6 | B1525-dr7-watchpoint-fields | DR7 field literals open-coded next to the named constants | `hal-x86_64/src/regs.rs` | Both the generic DR0 diagnostic and the feature-gated DR0+DR1 HoleHdr diagnostic now compose DR7 from one named field set. Shared DR0 fields use the generic kernel/test gate, DR1-only fields retain the narrower feature gate, and a hosted regression pins the write/8-byte DR0 image to `0x0009_0601`. |
| DONE | #4164 | duplicate `MXCSR_MASK_OFF`; two vdso dynsym resolvers; ns-0 network helper pairs (`mcast_report`, `route6_iface`, `udp_error_endpoint`, `send_l4_over_ipv4`, `forward_ipv4`, `ipv4_dst_is_local`); `sysfs::dev_root_leaf`; duplicate `acpi::tables::decode_iort`; duplicate `restore_saved_sigmask`; `misc_common` `MPOL_*` vs `vmm::mempolicy::uapi`; `net_common` `SOCK_*` vs `net::socket_args`; `055_getsockopt` `SO_TYPE` vs `net::uapi` | — |

## 4 — Test-infrastructure issues

| Status | Branch | Item | Notes |
|---|---|---|---|
| DONE 4e4ed0e46 | B1526-listns-cursor-test | `listns` zero-capacity cursor test is order-dependent | The no-successor assertion now uses `u64::MAX - 1`, whose successor lookup is structurally empty while preserving Linux `kernel/nstree.c` ordering: cursor lookup still runs before output capacity. This removes the race with concurrent namespace allocation without serializing unrelated syscall tests. The 4-test module passed in parallel and the full 754-test syscall library passed 30 consecutive parallel runs. |
| DONE 743528335 | B1527-preempt-reset-ownership | Scheduler BH reset races parallel tests | `_test_reset()` now clears only the caller's simulated CPU count and matching reschedule anchor; the global anchor-reset helper is gone. A barrier-controlled two-thread regression proves one reset cannot erase another CPU's BH nesting. All 4 BH tests pass in parallel, the full 651-test scheduler suite passes serially, and the other 647 tests passed 50 consecutive 32-thread runs. |
| DONE aa42ec50b | B1528-delayed-work-test-ownership | Delayed-work tests reset one shared production table concurrently | A poison-tolerant test mutex now owns each four-test mutation window and resets `PENDING`/`EARLIEST_NS` only after ownership is acquired. The other 647 scheduler tests remain parallel. All 651 tests passed 100 consecutive runs at 32 threads (65,100/0). |
| DONE 425133d56 | B1529-sched-min-feature-warnings | Narrow per-crate builds repeat six `sched` unused-import warnings | Diagnostic imports now follow `debug-watchdog`; the wait matcher and CPU-clock types follow the existing kernel/test/hosted owners. Minimal, hosted, `debug-watchdog`, and `debug-taskdump` scheduler checks are clean; all 112 per-package `--all-targets` configurations contain no `sched` warning; the workspace aggregate remains warning-free; 651 scheduler tests pass. |
| DONE b2c42ee56 | B1530-net-min-feature-warnings | Narrow per-crate builds repeat four `net` unused-binding warnings | The namespace and multicast-gate reexports now follow their exact kernel/test/hosted consumers; narrow Ethernet transmit and receive paths explicitly consume metadata that only the AF_PACKET configurations observe. Minimal and hosted net checks are warning-free, all 112 per-package `--all-targets` configurations produced zero warnings, the aggregate workspace check is clean, all 1,047 net tests pass, and both kernel targets booted on their first attempt. |
| DONE 3fc1ed919 | B1531-net-hosted-sched-feature | `net` debug features do not compose in a hosted `--all-features` build | `net/hosted` now propagates `sched/hosted`, making the dependency implementation match the hosted debug call sites without changing the default or real-kernel feature graph. Minimal, hosted, hosted+`debug-dbus`, hosted+`debug-scmfd`, and hosted all-feature checks pass; all 1,047 net tests and the aggregate workspace check pass; both kernel targets booted on their first attempt. |
| DONE a272c3cd0 | B1532-xfs-path-test-isolation | 21 XFS quota integration tests replay the production module's unit tests | The path-includable XFS core no longer owns a `cfg(test)` child; the canonical production wrapper owns the 18 unit tests exactly once. All 21 integration harnesses now include the core and expose zero phantom `xfs::tests` entries, removing 378 duplicate executions while retaining every intended integration test. The full syscalls package (754 library tests plus all integration binaries), aggregate workspace check, and both first-attempt kernel boots pass. |
| OPEN | — | 70 integration tests still compile production modules via `#[path]` | They carry `#![allow(dead_code)]` because the lint measures each test's reach, not the kernel's. Beyond XFS, 45 direct edges into 17 targets still resolve `cfg(test)` against the INCLUDING crate; some intentionally expose hosted hooks, while six inline unit-test manifests create phantom coverage. `fs` also declares five `syscalls` trace features it does not own solely to make those foreign gates well-formed. Audit one source family per lane. |
| DONE | other lanes | 24 tests that had never compiled started running | `psi::trigger_parse_tests`, `inotify::mark_lifetime_tests`, `fsconfig_abi::tests`, `acct::tests` — these arrived from B1506/B1507/B1508 merging into main mid-sweep, not from the sweep. Recorded so the count change is not mistaken for a sweep side effect. |

## 5 — Process / repo-hygiene issues hit during the sweep

| Status | Item |
|---|---|
| DONE #4165 | `metadata/index.md` lost its entire `C` counter row. `b72bd67e0` ("merge origin/main: keep B=1510") resolved a conflict by pasting the `B` row over the `C` row and dropping a third copy under *Reserved*. A lost row silently hands the next lane a colliding branch number. Restored, incident recorded in the file. |
| DONE #4163 | GitHub reports `C240-trivial-lints` as MERGED, and its sole commit `21c74924a` is an ancestor of `main`; no stale open PR remains to close. |
| DONE 3ab410338 | #4164 was created **and merged** by a subagent that had been told explicitly not to commit and not to merge. `CLAUDE.md` now reserves PR creation/merge for the primary integration owner and makes non-commit/push/merge instructions hard delegation boundaries. |
| DONE 3ab410338 | A worktree (`wt-C239`) was deleted by another lane while this lane was mid-edit; two finished edits were lost and had to be redone. `CLAUDE.md` now assigns each worktree to its lane owner and requires handoff/finish, a clean exact path, and a merged or explicitly abandoned branch before the integration owner may remove it. |

## 6 — What the sweep changed structurally (context for reviewers)

- `[workspace.lints.rust] unexpected_cfgs` with `check-cfg` for `cfg(target_os,
  values("oxide-kernel"))` + `cfg(loom)`, opted into by all 111 members. Level is
  `warn`, not `allow`, so a genuinely unknown cfg still fails loudly — that is
  what exposed the six phantom `debug-*` / `hosted` features.
- 24 kernel crates carry `#![cfg_attr(not(target_os = "oxide-kernel"),
  allow(dead_code))]`. The kernel builds keep `dead_code` fully ON and are clean,
  and all 24 link into `kmain`, so no real dead code can hide behind it.
  `crates/user/*` are untouched — they genuinely target linux-gnu.
- The two vendored crates allow `dead_code` in their OWN `Cargo.toml`; they are
  path deps so cargo reports their warnings as ours, and we do not edit vendored
  logic.
- **The gate to protect: both `xtask kernel` arches and `cargo check --workspace
  --all-targets` are now at zero warnings.** Any new warning is a new defect, and
  the dead-code signal on the kernel target is now meaningful for the first time.
