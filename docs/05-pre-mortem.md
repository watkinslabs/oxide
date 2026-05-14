# 05 Pre-Mortem

DRAFT (living). Dep:`00`,`03`,`04`,`08`.

Before-code enumeration of how the plan fails. Living doc per `MANIFEST§freeze-order`.

Tiers: A=hard contradiction; B=scope/calendar off; C=Rust-as-kernel; D=verification limits; E=hardware reality; F=missing entirely; G=process.

## A Hard contradictions

### A1 Syscall budget vs KPTI
`04§1` was 200cy entry; `03§8` mandates KPTI. KPTI alone 100–300cy x86, 50–150cy arm. Linux Zen4 `getpid` 60–80ns (~300–400cy after 30y tuning + PCID). Won't beat tuned C 2× same posture.
Fix: budgets rewritten in `04§1` (800 x86 KPTI+PCID, 600 arm; vDSO covers `clock_gettime`/`getcpu`/`gettimeofday` to <100cy).

### A2 systemd vs no-BPF
systemd≥254 uses BPF: `IPAccounting=`, `IPAddressDeny=`, `RestrictNetworkInterfaces=`, parts of `ExecPaths=`/`NoExecPaths=`, cgroup-attached BPF for per-unit net counters. Without BPF, unit files silently no-op or fail.
Fix: full systemd PID 1 sits at `43§4`. Phase 23 adds the BPF subset systemd needs. Don't quietly miss.

### A3 runc OCI vs no-FUSE
Rootless containers need fuse-overlayfs (real overlayfs needs CAP_SYS_ADMIN in init userns until recent kernels). Privileged runc fine without FUSE.
Fix: privileged runc lands first at `43§3`; rootless runc gates on overlayfs in userns (later phase, same `43§3` row when ready).

### A4 ext4+journal scope
JBD2 is its own substrate — crash-safe, ordered-writeback, power-cut-survival; Linux JBD2 ~15KLOC and still gets bugs. Bundling it with block+pagecache+ext4 RW into a single phase under-scopes the work.
Fix: split phases — block+pagecache (own); ext4 RO (own); JBD2+ext4 RW (own). Each phase advances on its §Test contract green, not on calendar.

### A5 Acceptance binary list mis-sorted
Tiered per `43§2-4`:
- Smoke: busybox, bash 5, coreutils 9, redis 7 (epoll/eventfd/signalfd/accept4/SO_REUSEPORT), Go≥1.22 + Rust≥1.75 statically-linked, openssh 9 (PTYs+modern crypto), nginx (without io_uring), sqlite 3.45.
- Dynamic-userspace: nginx + io_uring; runc + privileged OCI bundle; bpftrace; perf record/report.
- Distro: systemd≥254 PID1 (~150 syscalls + BPF + cgroup subtree + sd_notify + journald + 100s of unit-file edges); rootless runc; Wayland GUI.

## B Scope

### B1 (retired 2026-05-07) Calendar / week-estimate framing
Old plan listed per-phase week ranges + multi-month total. Removed 2026-05-07 — AI-driven solo work doesn't follow team-of-50 calendars; gate on per-spec §Test contract green, not duration. See `feedback_no_time_estimates`.

### B2 io_uring scope
Needs: SQ/CQ ring shared mmap, sqpoll worker(s), 80+ opcodes, polled completion, buffer registration, fixed files, multishot, chained SQEs, timeouts, cancels, IOPOLL. Standalone subsystem. Tracked as phase 22 per `00§3`. epoll covers most use until then.

### B3 TCP scope vs Linux-app compatibility
smoltcp = single-thread, embedded. Linux-compat TCP needs MP-CPU lock-free socket tables; BBR/CUBIC/DCTCP; TCP_NODELAY/CORK/FASTOPEN/SO_REUSEPORT (hash-LB); window-scale, SACK, TLP, RACK, PRR; conntrack for any iptables-userspace.
Real-app compat is "every TCP_* opt has documented Linux semantic", not "iperf3 100Mb/s." Its own sub-phase.
Fix: scope phase 8 honestly. Phase 8 gate = "loopback + AF_INET TCP/UDP + AF_UNIX passes must-run binary list"; not NIC-tuned line-rate. Real virtio-net live driver is phase 13 (done); AF_INET6 + DHCP/DNS land in phase 15.

## C Rust-as-kernel risks

### C1 HAL trait dispatch
`dyn MmuOps` = vtable per page-table op. Generic = monomorphize per arch (fine, threads type param everywhere; ergonomic cost; tempt to use `dyn` "just here").
Fix: HAL traits **type-level only**, never `dyn`. CI grep on demangled symbols (`07§5`). Per-spec §3 invariants enforce.

### C2 `panic="abort"`
Unwinding in kernel = leak resources past unwind boundary or run drop glue through IRQ frame → corruption.
Fix: `panic="abort"` every kernel profile (`07§2`).

### C3 `core::fmt` bloat
`Display`/`Debug` pulls big formatting machinery. `panic!("oops")` brings it in. klog interning doesn't help `assert!`/`panic!`/`debug_assert!`.
Fix: `kassert!(cond, "literal")` only (`07§5`). `panic!(fmt)` build-fail (CI grep `panic!.*\{`).

### C4 `-Zbuild-std` + toolchain
`*-unknown-none` w/ custom CPU features needs custom rustc OR `-Zbuild-std`. Plan doesn't pick.
Fix: nightly + `-Zbuild-std`, `rust-toolchain.toml` pin (`07§1`). Stable Rust support gates on inline-asm + naked-fn + ABI-pin stabilization upstream.

### C5 Atomic model on weak arches
Rust uses C++11; Linux LKMM has address-dependency / control-dependency tricks not exact-match on aarch64.
Fix: `06` doc — explicit `Acquire` where Linux uses `READ_ONCE`+addr-dep. Cost ~1–2% on RCU-heavy paths. Documented, not silent.

### C6 `unsafe` audit at scale
50K+ `unsafe` blocks at maturity. Greppable rule scales mechanically; reviewer attention doesn't. Lazy "we just did this" SAFETY comments will appear.
Fix: SAFETY comment must name (a) raw-pointer/aliasing/atomicity precondition, (b) fn/lock/state establishing it. CI grep ≥30 chars with fn-name OR state-name. Crude but catches worst.

### C7 miri coverage limits
miri does NOT model: MMIO/volatile-on-device-mem, weak-memory cache effects, custom GlobalAlloc reliably, inline asm clobbers, TLB.
Fix: spec reality. miri runs hosted unit tests of arch-free crates only (`pmm` policy, `slab` policy, `sched` policy, VFS path resolution). Not on `hal-*`, drivers, MMIO. Document so no false confidence.

### C8 loom is bounded
Loom: depth-bounded all-interleavings; perfect for 2–4 threads on lock-free DS; for 8+ threads / whole-subsystem SMP → exponential / misses rare.
Fix: loom mandatory for primitives (locks, MPSC, RCU). SMP differential mandatory for whole-subsystem behavior (proptest with seeded randomized concurrent ops + post-condition oracle). Neither replaces other.

## D Verification limits

### D1 Oracle proptest catches correctness, not liveness/perf
proptest vs buddy oracle proves no overlapping memory. Doesn't prove no contention deadlock, no slow path, no slab leak over weeks.
Fix: liveness watchdog (no-progress-N-sec); bench harness hooked to oracle (`04§5`); long-running counters (slab obj, PT pages, refcounts) tracked across QEMU-acceptance runs.

### D2 (retired) Soak gating
Original concern: per-phase soak gate stalls a solo project. Resolved 2026-05-07 by removing soak gating entirely per `00§17`. PR-time CI is the only wall; release exit per `00§15` is acceptance-binary pass.

### D3 (retired) Two-machine reproduction
Release exit no longer requires multi-machine reproduction. PR-time CI on GHA hosted runners + `43§2` acceptance suffices.

## E Hardware reality

### E1 Modern HW floor cuts users
`03§7` mandates x2APIC + TSC-deadline + invariant TSC + GICv3 + ECAM. ~2013 (Haswell, Cortex-A53) x86, ~2019 arm. Cloud meets bar; bare-metal users (older laptops, RPi 4 = GICv2!) don't. Pi 5 = GICv3.
Fix: explicit support matrix. Pi 4 not supported, Pi 5 yes. Don't be vague.

### E2 No AML cripples bare-metal laptop power
Most laptop power (thermal, sleep, lid, fan) flows through AML methods. UEFI Runtime Services + `_S5` reset reg = enough for halt+reboot, not "doesn't melt".
Fix: explicit. First ladder rungs target cloud + headless server bare-metal. Power = halt+reboot+CPU-temp-via-MSR. Laptops gate on hibernate/S3 (phase 41).

### E3 virtio-only first deployment
`03§7` once listed igc/ice/mlx5 as if first-rung. Each is its own driver-grade subsystem. First-rung target = QEMU/KVM + virtio + serial; real NICs land per phase 35.
Fix: driver list amended (`35§4`). First-rung: virtio-{blk,net,console,rng,vsock,input,gpu}, AHCI, NVMe, PS/2 kbd. Real NIC drivers (igc/ice/mlx5) per phase 35.

## F Missing entirely

### F1 Userspace toolchain
"Modern musl/glibc binaries run" needs a libc that knows our syscall ABI. Options: patch musl (~3 patches; small), use relibc (Redox), build scratch (no).
Fix: `29§4` musl vendored fork.

### F2 init / PID 1
Phase 5 says "musl busybox sh runs"; doesn't say *who runs sh*. PID 1 is special: kernel hands initial AS, ignores most signals, reaps orphan zombies. Need minimal init (10–50 lines Rust) before busybox useful.
Fix: `29§3`.

### F3 Image pipeline
Bootable image = kernel + initramfs (cpio); tooling/layout/mkfs absent from master plan.
Fix: `39§5`.

### F4 Time / RTC / wall clock
`03§7` says "no RTC except wall-seed at boot"; doesn't describe wall maintenance, NTP slewing, what `clock_gettime(REALTIME)` returns first second of uptime, TSC freq-change resistance (modern CPUs adjust under thermal pressure even with invariant-TSC; invariance = constant ratio to wall, not constant frequency).
Fix: `23` covers (calibration, slewing, vDSO, namespaces).

### F5 Power / reset / shutdown
"Halt" in HAL trait list; "reboot" wasn't. UEFI Runtime Services or platform reset reg — pick.
Fix: `32` covers (UEFI, PSCI, halt path).

### F6 Errno mapping
~140 errno values w/ subtle distinctions (`ENOTBLK` vs `EBADF`, `ETXTBSY` lifecycle). Wrong one → bash prints wrong msg → 1d wasted.
Fix: `01§6` frozen Errno enum w/ Linux numbers.

### F7 Caps + namespace lifecycle
`03§3` says namespaces d1. Lifetime = refcount + parent + teardown order. user-ns + pid-ns + mnt-ns interactions at process exit = recurring Linux CVE.
Fix: `26` covers.

### F8 Memory model
C5 mentions ordering; need single doc naming kernel memory model. Where which orderings used; RCU grace period definition; seqlock acq/rel ↔ reader barrier.
Fix: `06`.

### F9 Custom Rust target triple
Phase-0 deliverable. 4 triples (kernel × 2 arches, user × 2 arches). Without it, every crate has ad-hoc target flags, no consistent ABI.
Fix: `07§3`.

### F10 Per-CPU primitive
Affects every per-CPU DS. Phase-0-or-earlier decision.
Fix: `06§4` (`PerCpu<T>` via `gs:`/`tpidr_el1`).

## G Process (solo dev)

### G1 Spec discipline assumes reviewer
Solo "sign-off" = self-loop. Discipline still has value (pre-commit forcing) but social mechanism absent.
Fix: time-delayed self-review (`02§7`). 48h cool-off on text; re-read fresh.

### G2 (retired) Two-machine repro
Cf D3. Resolved 2026-05-07 — release exit now PR-time CI + `43§2` acceptance per `00§15`.

### G3 (retired 2026-05-07) Timeline-as-risk framing
Old concern was "long calendar kills morale." AI-driven solo cadence makes that framing obsolete; risk is now scope creep and substrate gaps, not duration. Each phase ships a usable artifact (PMM smoke, kernel boots, login works, etc.) — the visible-artifact mitigation already applies regardless of calendar.

## H Summary fixes (priority)

1. Realign cycle budgets w/ KPTI on (`04§1`). ✓
2. Tier must-run binary list smoke/dynamic-userspace/distro (`03§11`,`43§2-4`). ✓
3. Phases for io_uring, JBD2/ext4-RW, TCP-real-app (`00§3`). pending master-plan compress
4. Toolchain strategy `-Zbuild-std` on pinned nightly (`07`). ✓
5. `panic=abort`, `kassert!`-only, no-`dyn`-HAL rules (`07§5`). ✓
6. `06` memory model exists. ✓
7. `01` w/ frozen Errno. ✓
8. Userspace+init+image-pipeline phase 5 sub-tasks (`29`,`39`). ✓
9. Move runc/systemd off the smoke tier into distro tier (`43§4`). ✓
10. Solo-dev calendar realism (`00§3`). pending master-plan compress

## I Changelog

(none)

## J OQ

Living doc; OQs handled by individual fixes above.
