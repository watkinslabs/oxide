# 41 Debug Flags Catalog

Status: DRAFT 2026-05-02
Depends on: `04`,`07`,`08`.

## 1 Purpose

Authoritative list of every `debug-*` Cargo feature in the workspace. Each one's owning crate, what it does when on, cost when on. Per `04§3` and `07§3`.

## 2 Rules

- `debug-<aspect>` exposed by the crate that owns the aspect.
- Off by default. `debug-build` profile = `dev` + `debug-all`.
- When off: zero cost (verified by `cargo asm` snapshot tests).
- Each feature listed below: (a) what it adds, (b) ballpark slowdown, (c) notable false-positive sources.

## 3 Catalog

| Feature | Crate | Adds | Slowdown | Notes |
|---|---|---|---|---|
| `debug-pmm` | `pmm` | audit() per op; full-page poison check | 10-20× | covers `10§9` |
| `debug-pmm-track-leaks` | `pmm` | per-PFN caller-PC ring | +20% | leak diagnosis |
| `debug-alloc` | `slab` | redzone, freed-fill, poison cookie, caller-PC ring | 3× | `12§3.4` |
| `debug-slab-audit` | `slab` | walk every cache after every op | 50× | only for chasing slab corruption |
| `debug-vmm` | `vmm` | VMA tree audit each op; PT walker invariants | 5× | `11§3` checks |
| `debug-lockdep` | `sync` | lock-class graph; cycle detector | 10% | `06§3.6` |
| `debug-preempt` | `sched` | assert preempt_count valid at every kernel entry/exit | 5% | catches paired-disable bugs |
| `debug-sched` | `sched` | per-switch trace ring; runqueue audit; current-pointer canary | 30% | `13§17` |
| `debug-sched-canary` | `sched` | per-task canary `[u64;16]` checked every yield | 2× | the `14§8` test mode |
| `debug-irq` | `irq` | per-line latency histogram; spurious detect; full pt_regs save | 20% | `22§14` |
| `debug-vfs` | `vfs` | dentry+inode refcount audit | 40% | `16§10` checks |
| `debug-pagecache` | `pagecache` | per-page state machine audit on every op | 20% | `17§3` |
| `debug-net` | `net` | per-pkt L2-L4 trace; conn-state log | 50% | very expensive |
| `debug-tty` | `tty` | per-byte input/output trace; termios dump | 5× | tty internals only |
| `debug-fw` | `fw` | dump every parsed table | boot-only | `33§9` |
| `debug-pci` | `pci` | per-device cfg dump; cap walk trace | boot-only | `34§13` |
| `debug-driver` | `drv-*` | per-driver verbose probe | boot+10% runtime | each driver crate has its own |
| `debug-modules` | `modules` | reloc trace; sig-verify timing; symbol map dump | load-only | `18§12` |
| `debug-elf` | `elf` | per-PHDR; auxv dump; reloc trace | execve-only | `31§11` |
| `debug-time` | `time` | timer fire/cancel trace; vvar update audit; cross-CPU skew sampler | 10% | `23§14` |
| `debug-iouring` | `iouring` | per-op trace; ring state dump | 30% | `30§12` |
| `debug-cgroup` | `cgroup` | per-cgroup charge trace | 20% | `26§10` |
| `debug-security` | `security` | every cap_check denial logged; seccomp/landlock denials | <5% | `27§18` |
| `debug-init` | `init` (userspace) | trace every fork+exec | boot-only | `29§12` |
| `debug-syscalls` | `syscall` | log every syscall + args + retval | 50× | extreme; do not enable in soak |
| `debug-panic` | `panic` | full caller-saved reg dump on panic | panic-only | `38§10` |
| `debug-obs` | `klog` | ring stats every 10s; tracepoint-enable history | <1% | `37§15` |
| `debug-procfs` | `procfs` | log every open with path+caller | <1% | `19§11` |
| `debug-hal-x86_64` | `hal-x86_64` | full GDT/IDT/TSS dump; per-CPU MSR snapshot | boot-only | `20§17` |
| `debug-hal-aarch64` | `hal-aarch64` | TCR/MAIR/SCTLR/per-cpu reg dump | boot-only | `21§17` |
| `debug-power` | `power` | log reboot attempts, idle states | <1% | `32§11` |
| `debug-ipc` | `ipc` | pipe/AF_UNIX buffer dumps; futex queue dump; signal trace | 20% | `24§14` |
| `debug-boot` | `boot-*` | dump Limine responses; full memmap | boot-only | `36§9` |
| `debug-all` | meta | enables all `debug-*` except `debug-syscalls`, `debug-slab-audit`, `debug-net` (too expensive for general use) | varies | recommended for routine debug work |
| `paranoid-ci` | meta | substitute for the dropped 24h soak gate. Enables: `debug-pmm` + `debug-alloc` + `debug-lockdep` + `debug-preempt` + `debug-sched-canary` + `debug-vmm` + `debug-vfs` for PR-time CI builds. Catches what soak would catch in a 5-min run by aggressive auditing rather than long randomized workloads. | 5–10× | **MANDATORY in `pr.yml` test-hosted job per `40§2`** |

## 4 Combinations

- Routine debugging: `--features debug-all`.
- Memory bug hunt: `+ debug-pmm + debug-pmm-track-leaks + debug-alloc + debug-slab-audit`.
- Concurrency bug: `+ debug-lockdep + debug-preempt + debug-sched + debug-sched-canary`.
- Protocol issue: `+ debug-net + debug-iouring + debug-pagecache`.
- Driver bring-up: `+ debug-driver + debug-pci + debug-irq + debug-fw`.

## 5 Test contract (frozen)

- Every feature in the catalog: `cargo build --features <name>` succeeds.
- `--features debug-all` builds and boots in QEMU within 30s of bootloader handoff (slowdown bounds verified).
- Each feature has at least one test that exercises its instrumentation path.

## 6 Cross-spec

Every subsystem spec from `10` upward; `04§3`,`07§3.1`.

## 7 Open Questions

- Per-feature build matrix in CI: build every `debug-*` individually nightly to catch bit rot. Lean: yes; cheap.
- Run-time toggle for some flags via sysctl (without rebuild)? Lean: no; defeats the zero-cost-when-off rule. Build-time only.
