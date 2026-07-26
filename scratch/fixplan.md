# Fix plan — road to a graphical boot

Created 2026-07-26. Baseline `main` @ `cf25080f3`.
Companion doc: `broke.md` holds the EVIDENCE for every row here; this file is
the execution ledger. Update the Status cell the moment a lane changes state.

Status vocabulary: `TODO` / `CLAIMED <branch>` / `PR #n` / `DONE <merge sha>` /
`BLOCKED <reason>`.

Rules for every lane:
- fresh branch off current `origin/main`, own worktree, one lane per branch
- counter from `metadata/index.md`, increment it in the same commit
- author `Chris Watkins <chris@watkinslabs.com>`, never a `Co-Authored-By` trailer
- hosted tests are the inner loop; a QEMU boot is the final gate, not the dev loop
- both arches must build before push

---

## Phase 1 — unwedge the machine (nothing else matters first)

| # | Item | Why it blocks | Status | Branch |
|---|---|---|---|---|
| W1 | **RTNL is a `Spinlock`; Linux `rtnl_lock()` is a sleeping mutex.** | THE wall | **DONE** PR #3963 `5458d241e` | `B1408-ktimers-rtnl-mutex` |
| W1a | `run_due` phase/callback instrumentation. | diagnosis capability | **DONE** PR #3963 | `B1408-ktimers-rtnl-mutex` |
| W1b | Re-boot after W1 and find the NEXT wall. | unblocks planning | **DONE** — see below | — |

### W1 result (boot 2026-07-26, `live-gnome` x86, SMP=1, KVM)

| | before W1 | after W1 |
|---|---|---|
| survived to | **191 s, dead** | **377 s, no wedge** |
| soft lockups / no-progress | 1 / 1 | **0 / 0** |
| targets reached | `basic.target` | + `network.target`, **`network-online.target`**, **`multi-user.target`** |
| gdm | never started | **`Started gdm.service`** at 367 s, `/usr/bin/gdm` exec'd |

`network-online.target` is a second, unplanned win: NetworkManager now
completes. The N22 "NM never finishes" symptom was at least partly this wedge,
not only the `IFF_UP` issue (N6) — re-test N6 against this baseline before
assuming it is still the blocker.

## Phase 1b — THE NEW WALL: D-Bus service activation timeouts

The machine now survives, so the real desktop blocker is visible for the first
time. gdm starts but restarts (counter 1), because the services it depends on
time out one after another:

| Unit | Symptom | Count |
|---|---|---|
| `upower.service` | start operation timed out | 3 failures / 5 "Failed to start" |
| `polkit.service` | Failed to start | 2 |
| `accounts-daemon.service` | start operation timed out | 2 |
| `udisks2.service` | start operation timed out | 1 |
| `switcheroo-control.service` | start operation timed out | 1 |
| `rtkit-daemon.service` | start operation timed out | 1 |

All are D-Bus-activated system daemons; all *start* and then hang rather than
crashing. This is the "service activation is slow" class from
`broke.md` — previously masked by the wedge. That is now item **W2**, the top
of the plan.

| # | Item | Status |
|---|---|---|
| W2 | Six D-Bus system daemons hang during start and hit their unit timeout, so gdm crash-loops. Find the single shared stall (D-Bus activation? af_unix readiness? a syscall that never returns?) rather than chasing six services. | `TODO` — next |

### W1 audit result (2026-07-26) — conversion is gated on 4 softirq paths

Every `rtnl_lock()` site classified: **78 PROCESS (safe), 0 HARDIRQ, 0
UNDER-SPINLOCK, 0 UNKNOWN**, and **4 SOFTIRQ-reachable** which must be fixed
FIRST or the mutex sleeps inside softirq — a new bug traded for the old one.

| # | Unsafe site | Path | Fix |
|---|---|---|---|
| W1-a **DONE** `8fac637c7` | `net/src/stack_igmp.rs:440` `handle_igmp` | `drv-virtio-net rx_drain_softirq` (`Slot::NetRx`) → `deliver_ethernet_meta_in` → `deliver_rx_in` (`IpProto::Igmp`) → **synchronous, no queueing** | defer like RA |
| W1-b **DONE** `8fac637c7` | `net/src/stack_ipv6/mld.rs:454` `respond_mld_query` | same chain → `deliver_rx_icmpv6` (`ICMPV6_TYPE_MLD_QUERY`) | defer like RA |
| W1-c `PR` `B1409-sock-drop-softirq-defer` | `net/src/mcast_filter.rs:432` `SocketMcast::release` | `impl Drop for InetSocket` (`sock_drop.rs:128` → `release_file`) | defer final socket release out of softirq |
| W1-d `PR` `B1409-sock-drop-softirq-defer` | `net/src/sock/packet_membership.rs:84` `PacketMemberships::release` | same Drop glue | same |

**The deferral pattern already exists in this codebase and IGMP/MLD simply do
not use it.** IPv6 Router Advertisement looks identical in the RX path but is
safe: `queue_router_advertisement_ingress` only pushes onto `v6_ra_pending`, and
the `rtnl_lock()`-taking `apply_router_advertisement_lease` runs later from the
`ipv6_control_timer` ktimers callback. Linux does the same thing — IGMP/MLD
report sending is timer-driven (`igmp_gq_timer`/`igmp_ifc_timer`), never inline
in RX. So W1-a/b copy a pattern already proven in-tree.

W1-c/d are a real race, not hypothetical: `sock/packet.rs::deliver()` (AF_PACKET
fan-out, inline in the same NetRx softirq) holds temporary `Arc<InetSocket>`
clones from `Weak::upgrade()`. If the owner closes the fd while a frame is in
flight, the owner's `Arc` drops to 1, then `deliver()`'s locals drop the LAST
reference **from softirq** → `InetSocket::Drop` → `rtnl_lock()`. Linux avoids
this by never destroying a socket in softirq (`__sk_destruct` runs from an RCU
callback / process context).

Dead code to decide on while converting (zero production callers):
`bridge.rs::bridge_add_port_named`/`bridge_del_port_named`,
`iface_addr.rs::set_ipv4_prefix_meta_in`/`remove_ipv4_prefix_in`,
`policy_rule.rs::insert`/`remove`.

W1 execution contract:
1. ~~Audit every `rtnl_lock()` call site for context.~~ **DONE — see table above.**
2. Fix W1-a/b/c/d first. Then convert `Rtnl::lock` to
   `sched::live::Mutex`. `RtnlGuard` keeps its public shape so the 117 callers
   are untouched.
3. If any site is softirq/hardirq: that site converts to `rtnl_trylock()`
   semantics (Linux does exactly this — `linkwatch_event` uses `rtnl_trylock`)
   or moves to a workqueue. Do NOT leave a sleeping lock reachable from softirq.
4. `Rtnl::new()` is `const fn` today — the mutex must be const-constructible or
   the stack's construction changes with it.
5. Hosted tests: contended acquisition still excludes; a holder that sleeps no
   longer wedges a second acquirer.
6. Boot gate: `live-gnome` x86 must pass 191 s and reach further than this
   capture did. Both arches must build.

---

## Phase 2 — security holes (unprivileged process can own the box)

Every row here is a real privilege escalation, found by audit with file:line
evidence in `broke.md`. These are not theoretical.

| # | Item | Status | Branch |
|---|---|---|---|
| S1 | `ptrace` performs **zero** permission checks on every request. Any unprivileged process can read/write memory and registers of, or SIGKILL/single-step, any process including root's. The correct pattern already exists in the same crate (`ptrace_fpu.rs:113,153` check `traced_by` + `Stopped`) and was never propagated. `101_ptrace.rs` | `TODO` | — |
| S2 | `keyctl`/`add_key`/`request_key` never enforce key permission bits or possession; serials are sequential from `0x1000_0000` and trivially enumerable. Full keyring bypass. `fs/src/keyring.rs` | `TODO` | — |
| S3 | `rt_sigqueueinfo`/`rt_tgsigqueueinfo` skip `sig_perm_check` (which sits directly above them and IS used by `kill`). Arbitrary signal injection with spoofed sender identity. `signal_common.rs:39` | `TODO` | — |
| S4 | `prlimit64` rewrites any process's rlimits with no CAP_SYS_RESOURCE or uid check. `302_prlimit64.rs:19` | `TODO` | — |

## Phase 3 — desktop-relevant correctness

| # | Item | Status | Branch |
|---|---|---|---|
| D1 | `mount -t cgroup` (v1) returns **success without mounting anything** (`"devpts" \| "cgroup" => 0`). systemd mounts cgroup v1 hierarchies. `fsmount_common/mount_ops.rs:26` | `TODO` | — |
| D2 | `prctl(PR_SET_NAME)` is a no-op — the name pointer is never read, so `pthread_setname_np()` and every systemd thread rename silently do nothing. `PR_GET_NAME` echoes the spawn-time name. `sched/src/prctl.rs:64` | `TODO` | — |
| D3 | `PR_SET_DUMPABLE` no-op, `PR_GET_DUMPABLE` always 1 — dumpable can never be cleared (compounds S1). | `TODO` | — |
| N6 | Ether NICs register with `IFF_UP` **hardcoded**; Linux registers carrier-only and lets userspace bring the link up. This is why NetworkManager never manages `eth0` (the N22 blocker). Fix exists at `archive/B1378-remove-boot-ip-seed-hack`; the boot IP-seed hack must die in the same change. | `TODO` | — |

## Phase 4 — Linux-shape violations

| # | Item | Status | Branch |
|---|---|---|---|
| L1 | `openat` validates `dirfd` before checking whether the path is absolute; Linux ignores `dirfd` entirely for absolute paths. | `PR #3961` | `B1407-openat-absolute-dirfd` |
| S5 | `membarrier` is `{ 0 }` — argument never bound. `CMD_QUERY` reports nothing supported while barrier commands report success, on an SMP-capable kernel. `324_membarrier.rs` | `TODO` | — |
| S8 | `io_uring_setup` never reads the params struct; `IORING_SETUP_SQPOLL` etc. silently ignored. | `TODO` | — |
| S9 | `io_uring_enter` binds `min_complete`/`flags` to `_` and never reads them; `IORING_ENTER_GETEVENTS` returns instantly instead of waiting. | `TODO` | — |
| N1 | `TtyStruct.fg_pgrp` has three driver-side shadow copies kept in sync by hand, plus a second unreachable `TIOCSPGRP` path that updates only the core. Linux has one field. | `TODO` | — |
| N2 | configfs `CREATED: BTreeMap<String, usize>` keyed by FULL path, duplicating the kernfs tree; `child_has_children` does a prefix-string scan. Linux has one tree. | `TODO` | — |
| N3 | Root device falls back to `first_device` — an arbitrary disk — when the `oxide-root` serial is absent. Linux resolves `root=` one way and panics otherwise. | `TODO` | — |
| N4 | `notify_change` silently no-ops chmod/chown on `is_public_device()` inodes. | `TODO` | — |
| F1 | futex PI ops (`LOCK_PI`/`UNLOCK_PI`/`TRYLOCK_PI`/`*_REQUEUE_PI`) fall into `_ => 0` — `PTHREAD_PRIO_INHERIT` mutexes believe they locked something that was never arbitrated. | `TODO` | — |
| F2 | `mlock` family never enforces `RLIMIT_MEMLOCK` or `CAP_IPC_LOCK`. | `TODO` | — |
| F3 | `SO_SNDBUFFORCE`/`SO_RCVBUFFORCE` take the non-FORCE path with no `CAP_NET_ADMIN` check. | `TODO` | — |
| F4 | `sigaltstack` rejects nothing — no unknown-flag, `MINSIGSTKSZ`, or on-stack check. | `TODO` | — |
| F5 | `statmount` hardcodes `MNT_ROOT` to `"/"`, so bind mounts misreport. Breaks `findmnt`/libmount. | `TODO` | — |
| F6 | `fcntl(F_SETLKW)` busy-spins through `schedule()` instead of parking on a wait queue. | `TODO` | — |
| F7 | `SCHED_DEADLINE` returns `EOPNOTSUPP`; `SCHED_RESET_ON_FORK` is masked off and discarded. | `TODO` | — |
| F8 | `file_getattr` zero-fills while `ioctl(FS_IOC_GETFLAGS)` really reads ext4 `i_flags` — two syscalls, same state, different answers. | `TODO` | — |
| F9 | `clone(CLONE_CHILD_SETTID)` only writes the TID when `CLONE_VM` is set. | `TODO` | — |
| F10 | `open_by_handle_at` only checks the inode cache, so any evicted-but-valid handle wrongly gets `ESTALE`. | `TODO` | — |
| F11 | `seccomp(GET_ACTION_AVAIL)` never reads the queried action; every value reports available. | `TODO` | — |
| F12 | `TCP_INFO` fills ~13 fields and zeroes the rest, with a test asserting the zero tail. `ss -i` always shows no traffic. | `TODO` | — |

## Phase 4b — found while fixing, not yet lanes

| # | Item | Status |
|---|---|---|
| X2 | `net` :: `unix_sock::tests::scm_gc::newer_observer_cannot_reblock_released_generation` fails in the full `cargo test -p net --lib` run but passes 3/3 in isolation — an order/parallelism-dependent flake, pre-existing. The net suite is not reliably green. | `TODO` |
| X1 | `cargo test -p vfs --test dcache_drop_unhash` :: `freed_dentry_is_not_resurrected_from_bucket` FAILS on clean `origin/main`. Pre-existing, unrelated to any lane here, but it means the vfs suite is not green on main. | `TODO` |

## Phase 5 — doc lies (cheap, and they cause future bugs)

| # | Item | Status |
|---|---|---|
| L3 | `258_mkdirat.rs:23` claims "Ignores dirfd"; the code honours it. | `TODO` |
| N5 | `vfs/src/setattr.rs:130,201`, `perms_common.rs:62` describe a chmod/chown metadata overlay removed by D17. | `TODO` |
| P5a | `062_kill.rs:10` says `kill(-1)` unimplemented; it is fully implemented. | `TODO` |
| P5b | `101_ptrace.rs:24-32` calls PEEKUSER/POKEUSER/GETSIGINFO/SETSIGINFO stubs; all four are real. | `TODO` |
| P5c | `271_ppoll.rs:12` says sigmask is a follow-up; it does a real swap-and-restore. | `TODO` |
| P5d | `145_sched_getscheduler.rs:8` says 144 shares a no-op path; 144 really applies the policy. | `TODO` |
| P5e | `055_getsockopt.rs:20` claims silent zero-fill; ~40 options are handled correctly. | `TODO` |

## Phase 6 — resume the standing campaigns

Only after the machine boots. All hosted-iterable, none boot-gated except where
noted. Detail and staleness corrections live in `broke.md`.

| Track | Open | Status |
|---|---|---|
| `ext4fix.md` | 9 real items (jbd2 checksums, backup SB/GDT sync, `inline_data`, `COLLAPSE`/`INSERT_RANGE`, mballoc, jbd2 batching, flex_bg parse, **POSIX ACL enforcement**, dx_tail verify) | `TODO` |
| `network-plan.md` | 16 `[~]` + 9 `[ ]`; N22 gated on N6 | `TODO` |
| `syscall-compliance-matrix.md` | 116 `PARTIAL`, 207 `NEEDS-AUDIT`, 1 `DISPATCH-GAP` | `TODO` |
| `tcp-edge-inventory.md` | all 10 rows | `TODO` |
| `console2.md` | SOW-2/3/4 (boot-gated) | `TODO` |
| mount rows | 165, 166, 428-433, 442, 457/458, 467 still `PARTIAL` | `TODO` |
