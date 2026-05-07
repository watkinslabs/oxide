# 00 Master Plan: oxide2

DRAFT (living). Dep:`02`,`03`,`04`,`05`,`06`,`07`,`08`,`09`,`MANIFEST`.

Goal: self-hosting, multi-user, preemptive, SMP, virtual-memory OS in Rust. Targets `x86_64-unknown-oxide-kernel`, `aarch64-unknown-oxide-kernel` (`07§3`). HAL trait-based per-arch.

Rule: every subsystem ships with model + hosted oracle test + property suite. **Phase advance gated on PR-time CI**: build both arches, 10M-op property tests, loom, miri, QEMU smoke, coverage ≥95%, bench within 5%. PR-time green is the only wall. **No soak gating** — duration-based stress runs are not how an AI-driven solo project finds bugs; oracle proptests + miri + loom + QEMU differential do.

## 0 Last-attempt failures (recorded so we don't repeat)

1. PMM/slab/VMM written before testable; corruption undebuggable from inside the kernel using the corruption.
2. Buddy split/merge never oracle-diffed; "tested by booting"; failed under fragmentation patterns after 90min.
3. PT walker by-hand vs no QEMU monitor cross-check; off-by-one PTE flags burn long stretches of debug time each.
4. Ctxsw saved wrong reg set on less-tested arch; manifested only when preempt landed mid-syscall after a callee-saved clobber. Found via long stretch of register dumps.
5. No per-subsystem CI; PMM change broke slab silently.
6. "Compiles" ≠ "works"; 60% kernel is `unsafe`.

Corollary rules in §13. Detailed pre-mortem in `05`.

## 1 Workspace

`#![no_std]` everything except hosted tests. Layout in `39§3`. Rule: every non-HW-touching crate buildable for host AND kernel target — single most important architectural decision (oracle-diffability).

## 2 HAL

Trait set (`hal` crate). Kernel never names `x86_64`/`aarch64` outside `hal-*` crates. Type-level only, never `dyn` (`05§C1`,`07§5`).

```rust
pub trait CpuOps {
  fn id() -> CpuId; fn halt() -> !;
  unsafe fn enable_irq(); unsafe fn disable_irq();
  fn irqs_enabled() -> bool; fn pause(); fn memory_barrier();
}
pub trait MmuOps {
  type PhysAddr: Copy+Ord; type VirtAddr: Copy+Ord; type PageTable;
  const PAGE_SIZE: usize; const HUGE_SIZES: &'static [usize];
  fn new_address_space() -> Self::PageTable;
  unsafe fn map(pt:&mut Self::PageTable, va, pa, flags:PteFlags, sz) -> Result<(),MapError>;
  unsafe fn unmap(pt:&mut Self::PageTable, va, sz) -> Result<Self::PhysAddr,MapError>;
  unsafe fn switch_to(pt:&Self::PageTable);
  fn flush_tlb_va(va); fn flush_tlb_all();
}
pub trait IrqOps   { /* mask/unmask/eoi/send_ipi; `22§6` */ }
pub trait TimerOps { /* monotonic_ns, set_oneshot; `23§6` */ }
pub trait Context  {
  unsafe fn switch(prev:*mut Self, next:*const Self);   // `14`
  fn new_kernel(stack_top:*mut u8, entry:extern "C" fn(usize)->!, arg:usize) -> Self;
  fn new_user(stack_top:*mut u8, ip:u64, sp:u64) -> Self;
}
```

`#[cfg(target_arch=...)]` outside `hal-*`/`boot-*` = bug.

| Concern | Lives in |
|---|---|
| long-mode entry, GDT/IDT/TSS, x2APIC discovery | `boot-x86_64`,`hal-x86_64` (`20`) |
| EL1 entry, vector table, GICv3, gen-timer | `boot-aarch64`,`hal-aarch64` (`21`) |
| PT format (4-level both arches) | `hal-*::mmu` |
| Ctxsw asm | `hal-*` `.S` ≤50 lines (`14`) |
| Atomics | `core::sync::atomic`; never reinvented |
| anything else | arch-free crate |

## 3 Phases

Phase exit = PR-time gates green (build both arches + property tests + miri + loom + QEMU smoke + coverage + bench) + per-spec §Test-contract acceptance. Sequential within a release; v2 and v2 are bookmarked as their own ladders below.

### 3.1 v1 — kernel substrate + minimum userspace (DONE except phase 12 net polish)

Goal: kernel boots both arches, broad syscall surface, ext4 RW, IPv4 net, login shell, static-musl userspace runs. Tag `v1.0` once `43§2` minimum acceptance binaries pass + PR-time CI green.

| # | Subsystem | State | Spec |
|---|---|---|---|
| 0 | Build infra (xtask, targets, hello-world boot, CI, Docker img) | done | `07`,`39`,`40` |
| 1 | PMM (buddy + bitmap-truth + oracle) | done | `10` |
| 2 | VMM + MMU bring-up + per-CPU areas + TLB shootdown | done | `11`,`20`,`21` |
| 3 | Slab + GlobalAlloc | done | `12` |
| 4 | Sched + ctxsw + preempt + SMP | done (UP; SMP cooperative-with-timer-wake) | `13`,`14` |
| 5 | Syscalls + ELF loader + init + busybox-sh | done — 134 syscall handlers, kernel-completeness sweep landed sessions 38 (PR-A..U) | `15`,`31`,`29` |
| 6 | VFS + tmpfs + procfs + sysfs + devtmpfs + ext4 RO | done | `16`,`19` |
| 7a | Block layer + page cache | done | `17` |
| 7b | ext4 RW + JBD2 (depth ≤2; small files) | done | `17` |
| 8 | Net (loopback + AF_INET TCP/UDP + AF_UNIX); virtio-net types only — DHCP/DNS NOT v1 | partial; promote remainder to v2 phase 18 | `25` |
| 9 | Hardening, observability, klog cfg-gating | ongoing | `27`,`37`,`18` |
| 10 | Modules loader (ELF ET_REL parse + relocator + section placement + symbol resolution + `init_module`/`finit_module`/`delete_module`/`/proc/modules`) | done | `18`,`31` |
| 11 | PCI / PCIe enumeration | done | `34` |
| 12 | virtio shared infrastructure (split virtqueue, status bits, feature negotiation) | done | `34`,`35` |

**v1 exit:** §15.

### 3.2 v2 — kernel parity + userspace platform (Fedora-class endgame)

Single ladder for everything downstream of `v1.0`. Phases are **independent** — no global ordering — gated only by per-spec deps. v2 covers two tracks bundled in one release window:

- **Kernel parity** (phases 18-32, 38): de-stub the deferred subsystems flagged in `docs/kernel-audit.md` + the v1 non-goals from §9.
- **Userspace platform** (phases 33-37): real ld.so, libc/NSS/PAM, system manager, RPM, agetty/login — turns "kernel boots, sh runs" into "Fedora binaries install + run."

Detailed plan in `docs/00-v2.md`; this is the index.

| # | Subsystem | Spec hook |
|---|---|---|
| 18 | AF_INET6 socket layer + DHCP client + DNS resolver | `25` |
| 19 | Real virtio-net live driver (tx/rx ring service, link-state, feature negotiation) | `25`,`35` |
| 20 | mremap (real, MREMAP_MAYMOVE), per-PTE mprotect with TLB shootdown, MAP_SHARED, MADV_DONTNEED zero-fill | `11`,`20§7` |
| 21 | Namespaces: unshare/setns/pivot_root + per-NS mount/uts/pid/user | `13`,`16`,`26` |
| 22 | ptrace family (PTRACE_ATTACH/SINGLESTEP/PEEK/POKE/SYSCALL + signal-stop integration) | `27`,`13` |
| 23 | io_uring (setup/enter/register, SQE/CQE rings, fixed-buffer registration, IORING_OP_*) | `30` |
| 24 | bpf + seccomp + landlock | `27` |
| 25 | SysV IPC (shm/sem/msg) + POSIX MQ + keyring | `24` |
| 26 | xattr family (real, ext4-backed) + ACLs + capability bits on files | `16`,`27` |
| 27 | fanotify_init + fanotify_mark + finish inotify gaps | `16` |
| 28 | userfaultfd + memfd_secret enforced isolation | `11` |
| 29 | Modern mount API (fsopen/fsconfig/fsmount/fspick + mount_setattr) + real mount/umount/chroot | `16` |
| 30 | perf_event_open + tracefs/ftrace + ebpf programs running tracepoints | `27`,`37` |
| 31 | Core dump generation (sigaction SIGSEGV → ELF coredump in fs) | `27`,`16` |
| 32 | DRM/KMS framebuffer + virtio-gpu + input subsystem (evdev) | new spec |
| 33 | Dynamic linker (real ld-musl: PT_INTERP, DT_NEEDED, GOT/PLT, RELA/JMPREL, ld.so.cache, LD_LIBRARY_PATH, dlopen/dlsym) | `31`,`29a` |
| 34 | Standard userspace libc + NSS + PAM (musl-with-nss, /etc/{passwd,group,shadow}, pam_unix for login/su/sudo) | `29a`,`43` |
| 35 | System manager (real PID 1 — service supervision, dependency order, journalctl-equivalent on klog ring) | `29a` |
| 36 | Package manager (rpmbuild against our libc, dnf/microdnf install, /var/lib/rpm) | `43`,`29a` |
| 37 | TTY + login flow (agetty per /dev/tty[0-N], terminfo/ncurses, motd/issue) | `28`,`29a` |
| 38 | AF_INET6 + sendmmsg/recvmmsg + AF_UNIX SCM_CREDS — net completion not in 18-19 | `25` |

### 3.3 v2.x — desktop / hardware-rich (open scope)

Wayland, GNOME, USB stack, real ACPI runtime / AML interp, NUMA, hibernate/S3, KVM/hypervisor, NFS/CIFS, FUSE, SELinux/AppArmor/IMA full LSM impls, DT overlays, full netfilter, vDSO, FSGSBASE, glibc compat surface (set_thread_area i386, IFUNC). Each is its own subsystem; promotion to a numbered v2.x phase happens when scope is firm.

### 3.4 Status snapshot (this revision)

**Done:** v1 phases 0-7b + 10-12 fully landed; phase 5 syscall surface saturated by sweep PR-A..U; phase 8 IPv4-half done.
**Open in v1:** phase 8 net polish (only; remainder promoted to v2/18-19), phase 9 hardening (ongoing).
**v1 exit blocker:** `43§2` minimum acceptance binary list — once those run + PR-time CI green, tag `v1.0`.

## 4 Verification stack (`42` for patterns)

1. Oracle proptest — every algorithmic subsystem has stupid reference impl in `tools/oracle-*/`; lockstep diff per op. Single biggest change vs last attempt.
2. Loom — every lock-free / fine-grained-lock DS. Hosted, in CI, every PR.
3. Miri — hostable crates, unit tests in CI. Caveats `05§C7`.
4. QEMU+monitor differential — MMU: random map+`gva2gpa`+`info tlb`+`info mem` cross-check. We never wrote this last time.
5. Boot-N-times — different RNG seeds; userspace probe OK. Catches early-init races. PR-time job runs N=100; nightly bumps to higher N if needed.
6. Coverage — pmm/slab/vmm/sched/vfs ≥95% hosted; HAL ≥80% asm trampoline coverage in QEMU. PR-blocking.
7. Static — `clippy::pedantic`, `cargo deny`, SAFETY comments enforced (`07§5`,`05§C6`).

## 5 Memory mgmt detailed design

### 5.1 PMM (buddy)
- Orders 0..=20 (4KiB..4GiB). 1 zone v1 (NUMA later).
- Per-order intrusive free lists (16-byte node in freed page; magic poison).
- Split: pop order N+1, push upper half to order N, return lower. Always lower (deterministic).
- Merge: XOR-buddy, check **bitmap is-free-at-this-order = source of truth** (not free-list walk; that was the v0 bug). Bitmap O(1) atomic. Overhead ~0.05% RAM.

Detail: `10`.

### 5.2 Slab
- Size classes 8..8192 powers-of-2 + 96, 192. Per-cache partial/full/empty lists.
- Per-CPU magazine layer in phase 4 (after per-CPU areas exist).
- Object header poison `0xDEADBEEFCAFEBABE` on free; redzone in debug.
- Slab = bump allocator over fixed-size backing. No ctor/dtor.

Detail: `12`.

### 5.3 VMM
- `AddressSpace { root: PageTable, vmas: BTreeMap<VirtAddr, Vma> }`.
- `Vma`: range, prot, flags, backing (anon/file/special).
- mmap: find hole, insert vma, lazy fault. munmap: split/clip vmas, unmap PT range, free pages. mprotect: walk vmas, split at boundaries, update PTE flags, TLB shootdown via IPI broadcast.
- COW fork: clone vmas, mark writable PTEs RO in both, refcount on phys page.
- All testable via fake `MmuOps` recording calls.

Detail: `11`.

### 5.4 Kernel allocator
- One `GlobalAlloc` (`kalloc`); ≤8K → slab, >8K → direct PMM order alloc.
- No vmalloc-equivalent v1; added when drivers need >slab discontig-phys contig-virt.

## 6 Scheduler detailed design

### 6.1 Model
- Per-CPU `Runqueue`. Tasks bound to CPU until migrated.
- 3 classes: Idle, Normal (CFS-like vruntime in BTreeMap), RealTime (priority array, FIFO/RR per level).
- Sched = pure fn `(state,event)→(state,action)` on hosted tests. No globals/`static mut`. Globals injected via HAL.

### 6.2 Ctxsw rules
- Asm `.S` per arch ≤50 lines. Callee-saved + IP + SP + FS/GS or TPIDR base only.
- FPU lazy (xsaveopt x86 / FPSIMD trap arm) on first FP fault post-switch.
- No inline asm; one `extern "C" fn` to one `.S`. (Inline asm clobbers were proximate cause of last attempt's bug #4.)
- Test: 2-thread ping-pong; per-switch verify all callee-saved match. Canary in r12/x19 read back.

### 6.3 Preempt
- Timer-driven (per-CPU oneshot).
- Gated by per-CPU `preempt_count` (locks/IRQs/exceptions raise; zero ⇒ check `need_resched` ⇒ tail-call sched).
- `preempt_count` in per-CPU struct, single-instr access (`gs:[..]` x86, TPIDR_EL1-rel arm).

### 6.4 SMP
- Per-CPU runqueues; load-balance every 10ms or on-idle.
- Cross-CPU wakeup IPI; receiver runs sched on IRQ exit.
- Shared structs: RCU (read-mostly: task list, mount table) or per-CPU + occasional locked rebalance (runqueues).

Detail: `13`,`14`.

## 7 Syscall ABI

- Linux-compat at numbers; unmodified musl-linked binaries run.
- One table (`SYSCALL_TABLE: [SyscallFn; 462]`) called from per-arch trampoline in `hal-*`.
- Every syscall: `fn(&SyscallArgs) -> KR<u64>`. Trampoline marshals regs.
- Userspace ptrs via `UserPtr<T>` newtype; check before deref. No raw `*mut u8` past dispatch.

Full table + bit-flag tables: `15`.

## 8 Drivers

- Each driver own crate `drv-*`. Core kernel depends on no driver.
- Registration via `linkme::distributed_slice!(DRIVERS)`; kernel iterates at boot.
- v1 first-class: uart-{16550,pl011}, virtio-{blk,net,console,rng,vsock,input,gpu}, AHCI, NVMe, PS/2-keyboard (x86 console fallback). Detail: `35`.

## 9 Explicit non-goals v1

Things v1 doesn't ship — explicitly to keep `v1.0` reachable. Most of these are now v2 phases (see §3.2) rather than absolute exclusions.

| Item | Disposition |
|---|---|
| 32-bit anything; PAE / x86 segment tricks beyond long mode | absolute exclusion — never |
| hibernate / S3 | v2.x |
| KVM/hypervisor | v2.x |
| swap to disk | v2.x |
| quotas | v2 phase 26 (with xattr/ACL bundle) |
| NFS/CIFS | v2.x |
| FUSE | v2.x |
| SELinux/AppArmor/IMA | v2 phase 24 (LSM hooks) — surface only |
| DRM/KMS/GPU graphics | v2 phase 32 |
| USB stack | v2.x (HID-only via virtio in v1; full stack v2.x) |
| ACPI runtime / AML interp | v2.x |
| DT overlays | v2.x |
| iptables/netfilter | v2.x (BPF hooks via phase 24) |
| vDSO | v2.x |
| io_uring | v2 phase 23 |
| ptrace | v2 phase 22 |
| bpf/seccomp/landlock | v2 phase 24 |
| namespaces (real) | v2 phase 21 |
| AF_INET6 socket layer + DHCP + DNS | v2 phase 18 |
| real virtio-net | v2 phase 19 |
| mremap proper + per-PTE mprotect | v2 phase 20 |
| SysV IPC + POSIX MQ + keyring | v2 phase 25 |
| fanotify | v2 phase 27 |
| userfaultfd | v2 phase 28 |
| modern mount API + real mount/chroot | v2 phase 29 |
| perf/ftrace/ebpf-trace | v2 phase 30 |
| core dumps | v2 phase 31 |
| pkey (Memory Protection Keys) hardware | v2.x |

Tempted to slip something into v1? Add to v2 ladder instead.

## 10 CI

PR (the phase gate): build both arches both profiles, `xtask test --hosted` (10M-op proptest), miri, loom, QEMU smoke both arches, bench-vs-history, coverage gate, clippy `-D warnings`, deny, spec-lint. Detail `40§2`.

PR cannot merge without green. Detail: `40`.

## 11 Doc discipline

Per `02`. MANIFEST authoritative. Every spec has §Cross-spec. Boot flow Mermaid in `36`.

## 12 Tooling (off-the-shelf, no rewrites)

`qemu-system-{x86_64,aarch64}`, `gdb-multiarch`, `bochs` (secondary x86 ref), `proptest`,`loom`,`miri`, `defmt`-style klog (own decoder), `cargo-binutils`,`rust-objcopy`,`rust-lld`, `limine` (x86) / `EDK2`+`U-Boot` (arm), `mkfs.ext4`+`e2fsck` (FS differential).

## 13 Risk register

| Risk | Mitigation |
|---|---|
| Buddy free-list corruption (last time) | bitmap-truth `5.1`,`10§3`; oracle diff |
| Ctxsw register loss (last time) | fixed save set, asm ≤50 lines, canary test `14§8` |
| TLB shootdown SMP bugs | single `flush_tlb_range_smp` chokepoint; deliberate-stale-TLB stress proves *absence* |
| Lost wakeup in sched | loom `wake/sleep`; proptest oracle |
| `unsafe` UB | miri (hostable); SAFETY comments enforced `07§5` |
| Driver explodes kernel | drivers no `static mut`; state owned by instance kernel hands them; review checklist |
| Bootloader weirdness | exactly Limine x86 / EDK2 or U-Boot arm; anything else = unsupported |
| Slow CI killing momentum | hosted <2min, QEMU smoke <5min, no duration-based gating |

## 14 The five rules

1. No subsystem merge until PR-time gates green (build, oracle proptest 10M ops, loom, miri, QEMU smoke, coverage, bench).
2. No `unsafe` ships without SAFETY naming invariant.
3. Phases sequential within a release ladder (v1 sequential; v2 phases independent).
4. Bug >2d to localize ⇒ stop, build the missing test infra that would have localized it. Don't just fix.
5. Out-of-release-scope feature ⇒ promote to next ladder, don't smuggle.

## 15 v1 exit criterion

`v1.0` ships when:
1. PR-time CI green on the tagged commit, both arches, both profiles.
2. All `43§2` minimum acceptance binaries run end-to-end on QEMU (boots → login → run binary → exit clean).
3. Kernel-completeness audit `docs/kernel-audit.md` shows no remaining stub regressions vs the sweep landed sessions 38.

That's it. No 168h soak, no duration-based wait — PR-time green + acceptance is the wall. AI-driven oracle proptests + miri + loom + QEMU differential are how bugs get found, not duration runs.

Artifact = `(commit, arch, sha256s of kernel + rootfs, acceptance-binary list with exit codes)`. When in repo → tag `v1.0`.

## 16 Appendix A — spec list

See `MANIFEST.md`.

## 17 Changelog

- 2026-05-07b: folded v1.x into v2. There's no real dependency between userspace-platform work (real ld.so, libc/NSS/PAM, system manager, RPM, agetty/login) and kernel-parity work (AF_INET6, namespaces, io_uring, etc.) — they're parallel. Single v2 ladder (§3.2), single endgame tag. Old v1.x phases 13-17 renumbered as v2 phases 33-37. New phase 38 = AF_INET6 + sendmmsg/recvmmsg + AF_UNIX SCM_CREDS net completion. All `v1.x` references in the doc tree bulk-renamed to `v2`.
- 2026-05-07: v1 tightened to "kernel substrate + minimum userspace" (phases 0-12 + minimal acceptance). Old phases 13-17 initially placed in a "v1.x" bridge; superseded by 2026-05-07b fold. NEW v2 phase ladder (§3.2) covers kernel parity + userspace platform + de-stubbed subsystems. v2.x covers desktop/hardware-rich. **All soak gating removed** — duration-based runs are not a v1 exit criterion or phase gate; PR-time CI + `43§2` acceptance is the wall.
- 2026-05-06: phase ladder gains explicit rows 10/11/12 for modules loader, PCI enumeration, virtio common infra. Spun out from "phase 9 + driver work backing phase 8" because each turned out to be a multi-PR slug deserving its own gate.
- 2026-05-06: phases 13–17 added covering the Linux-userspace integration arc — dynamic linker, libc/NSS/PAM, system manager, RPM toolchain, agetty/login flow. Each phase is a usable milestone (e.g. phase 13 alone unlocks running unmodified Fedora binaries with a small set of .so files staged).

## 18 OQ

Living doc. OQs handled by individual fixes in subsystem specs.
