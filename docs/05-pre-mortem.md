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
Fix: systemd→v2 (`43§4`). v1.x adds BPF subset. Don't quietly miss.

### A3 runc OCI vs no-FUSE
Rootless containers need fuse-overlayfs (real overlayfs needs CAP_SYS_ADMIN in init userns until recent kernels). Privileged runc fine without FUSE.
Fix: v1.x = privileged runc only. Rootless = v2 (`43§3`).

### A4 ext4+journal in 4 weeks
JBD2 = 4–6mo: crash-safe, ordered-writeback, power-cut-survival. Linux JBD2 ~15KLOC, 20y, still bugs. 4-week phase incl block+pagecache+ext4 RW+power-cut soak off 4–6×.
Fix: split phases — block+pagecache (own); ext4 RO (own); JBD2+ext4 RW (own). 12–16wk total.

### A5 Acceptance binary list mis-sorted
v1 split (per `43§2-4`):
- v1: busybox, bash 5, coreutils 9, redis 7 (epoll/eventfd/signalfd/accept4/SO_REUSEPORT), Go≥1.22 + Rust≥1.75 statically-linked, openssh 9 (PTYs+modern crypto), nginx (without io_uring), sqlite 3.45.
- v1.x: nginx + io_uring; runc + privileged OCI bundle; bpftrace; perf record/report.
- v2: systemd≥254 PID1 (~150 syscalls + BPF + cgroup subtree + sd_notify + journald + 100s of unit-file edges); rootless runc; Wayland GUI.

## B Scope / calendar

### B1 9-phase calendar off ~3×
Per-phase 24CPU-hr soak gate. Failed soak restarts. Real per-phase 4–5wk vs claimed 2.

| Phase | Stated | Realistic solo |
|---|---|---|
| 0 build infra | 1wk | 1–2wk |
| 1 PMM | 2wk | 4–6wk |
| 2 VMM | 3wk | 8–12wk |
| 3 Slab+alloc | 2wk | 3–4wk |
| 4 Sched+ctxsw+SMP | 4wk | 12–16wk |
| 5 Syscalls+userspace | 3wk | 8–12wk |
| 6 VFS+tmpfs+ext4 RO | 3wk | 6–8wk |
| 7 Block+pagecache+ext4 RW | 4wk | 12–20wk (A4) |
| 8 Net | 6wk | 20–30wk |
| 9 Hardening/obs | ongoing | ongoing |

Honest total v1: **18–24mo solo full-time**. Plan's "29+wk" off 2–3×.
Fix: replace week-numbered headings with effort estimates + dependency edges in `00§3`. Calendar drift fine; pretending isn't.

### B2 io_uring not in any phase
Needs: SQ/CQ ring shared mmap, sqpoll worker(s), 80+ opcodes, polled completion, buffer registration, fixed files, multishot, chained SQEs, timeouts, cancels, IOPOLL.
4–6mo standalone. v1 promise nginx+io_uring → need phase 5.5 with own soak. Or drop from v1; epoll covers most.
Fix: io_uring → v1.x (`43§3`).

### B3 TCP years not weeks
smoltcp = single-thread, embedded. Linux-compat TCP needs: MP-CPU lock-free socket tables; BBR/CUBIC/DCTCP; TCP_NODELAY/CORK/FASTOPEN/SO_REUSEPORT (hash-LB); window-scale,SACK,TLP,RACK,PRR; conntrack for any iptables-userspace.
Real-app compat is "every TCP_* opt has documented Linux semantic", not "iperf3 100Mb/s." Multi-month sub-phase.
Fix: scope phase 8 honestly. v1 = "loopback + virtio-net + TCP passes must-run binary list"; not NIC-tuned line-rate.

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
Fix: nightly + `-Zbuild-std`, `rust-toolchain.toml` pin (`07§1`). Stable v2+.

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
Fix: loom mandatory for primitives (locks, MPSC, RCU). SMP soak mandatory for whole-subsystem behavior. Neither replaces other.

## D Verification limits

### D1 Oracle proptest catches correctness, not liveness/perf
proptest vs buddy oracle proves no overlapping memory. Doesn't prove no contention deadlock, no slow path, no slab leak over weeks.
Fix: liveness watchdog (no-progress-N-sec); bench harness hooked to oracle (`04§5`); long-running counters (slab obj, PT pages, refcounts) tracked across soak.

### D2 (resolved) 24h soak gate ≠ solo dev calendar
Original concern: 24h × 2 arches × per-phase gate = perpetual wall. Fix applied 2026-05-02: soak demoted to continuous bg diagnostic per `40§3`; phase gate moved to PR-time (≤5min + canary 1h) + `paranoid-ci` build (`41§3`). Single soak box; v1 tag is sole 168h wait.

### D3 Two-machine reproduction = CI infra
v1 exit `00§15`: "second machine independently reproduces from same commit". Solo dev = "I ran it twice on different boxes". Team = "CI on multi-runner". Either way infra not yet planned.
Fix: lower v1 exit → "same machine, same image hash, soak passes". Multi-machine = v1.x/v2 once CI exists.

## E Hardware reality

### E1 Modern HW floor cuts users
`03§7` mandates x2APIC + TSC-deadline + invariant TSC + GICv3 + ECAM. ~2013 (Haswell, Cortex-A53) x86, ~2019 arm. Cloud meets bar; bare-metal users (older laptops, RPi 4 = GICv2!) don't. Pi 5 = GICv3.
Fix: explicit support matrix. Pi 4 not supported, Pi 5 yes. Don't be vague.

### E2 No AML cripples bare-metal laptop power
Most laptop power (thermal, sleep, lid, fan) flows through AML methods. UEFI Runtime Services + `_S5` reset reg = enough for halt+reboot, not "doesn't melt".
Fix: explicit. v1 supports cloud + headless server bare-metal. Power = halt+reboot+CPU-temp-via-MSR. Laptops v2+.

### E3 virtio-only first deployment
`03§7` lists igc/ice/mlx5 as if v1. Each 6–12mo solo. v1 = QEMU/KVM + virtio + serial. Real NICs v2.
Fix: driver list amended (`35§4`). v1: virtio-{blk,net,console,rng,vsock,input,gpu}, AHCI, NVMe, PS/2 kbd. Real NIC v1.x/v2.

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

### G2 Two-machine repro unrealistic solo
Cf D3.
Fix: v1 exit lowered → same machine + image hash + soak. Multi-machine v1.x/v2.

### G3 18–24mo timeline kills projects
Biggest risk = morale/abandonment. Mitigation = visible artifact every phase, not just v1. Phase 5 (busybox sh) = first "we have a thing" — should be wk30 honest calendar, not wk15.
Fix: (a) compress phases by reducing verification rigor for NON-critical subsystems (never for mem/sched/ctxsw); or (b) accept timeline + demo every phase boundary so project feels alive.

## H Summary fixes (priority)

1. Realign cycle budgets w/ KPTI on (`04§1`). ✓
2. Split must-run binary list v1/v1.x/v2 (`03§11`,`43§2-4`). ✓
3. Phases for io_uring, JBD2/ext4-RW, TCP-real-app (`00§3`). pending master-plan compress
4. Toolchain strategy `-Zbuild-std` on pinned nightly (`07`). ✓
5. `panic=abort`, `kassert!`-only, no-`dyn`-HAL rules (`07§5`). ✓
6. `06` memory model exists. ✓
7. `01` w/ frozen Errno. ✓
8. Userspace+init+image-pipeline phase 5 sub-tasks (`29`,`39`). ✓
9. Cut runc/systemd from v1 (`43§4`). ✓
10. Solo-dev calendar realism (`00§3`). pending master-plan compress

## I Changelog

(none)

## J OQ

Living doc; OQs handled by individual fixes above.
