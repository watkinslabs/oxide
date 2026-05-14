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

Phase exit = PR-time gates green (build both arches + property tests + miri + loom + QEMU smoke + coverage + bench) + per-spec §Test-contract acceptance.

Single ladder. Every Linux subsystem is in scope — there is no
"deferred to v2", no parking lot, no subset framing. The contract
is full Linux parity. Phases are ordered roughly by dependency, but
non-overlapping phases land in parallel once their deps are green.

| # | Subsystem | State | Spec |
|---|---|---|---|
| 0 | Build infra (xtask, targets, hello-world boot, CI, Docker img) | done | `07`,`39`,`40` |
| 1 | PMM (buddy + bitmap-truth + oracle) | done | `10` |
| 2 | VMM + MMU bring-up + per-CPU areas + TLB shootdown | done | `11`,`20`,`21` |
| 3 | Slab + GlobalAlloc | done | `12` |
| 4 | Sched + ctxsw + preempt + SMP | done (UP; SMP cooperative-with-timer-wake) | `13`,`14` |
| 5 | Syscalls + ELF loader + init + busybox-sh | done — 134 syscall handlers, kernel-completeness sweep PR-A..U | `15`,`31`,`29` |
| 6 | VFS + tmpfs + procfs + sysfs + devtmpfs + ext4 RO | done | `16`,`19` |
| 7a | Block layer + page cache | done | `17` |
| 7b | ext4 RW + JBD2 (depth ≤2; small files) | done | `17` |
| 8 | Net loopback + AF_INET TCP/UDP + AF_UNIX | done (IPv4 half) | `25` |
| 9 | Hardening, observability, klog cfg-gating | ongoing | `27`,`37`,`18` |
| 10 | Modules loader (ELF ET_REL parse + relocator + symbol resolution + `init_module`/`finit_module`/`delete_module`/`/proc/modules`) | done | `18`,`31` |
| 11 | PCI / PCIe enumeration | done | `34` |
| 12 | virtio shared infrastructure (split virtqueue, status bits, feature negotiation) | done | `34`,`35` |
| 13 | Real virtio-net live driver (tx/rx ring service, link-state, feature negotiation) | done | `25`,`35` |
| 14 | mremap real (MREMAP_MAYMOVE) + per-PTE mprotect with TLB shootdown + MADV_DONTNEED zero-fill + file-backed mmap | open | `11`,`20§7` |
| 15 | AF_INET6 socket layer + DHCP client + DNS resolver + sendmmsg/recvmmsg + AF_UNIX SCM_CREDS | open | `25` |
| 16 | Namespaces: unshare/setns/pivot_root + per-NS mount/uts/pid/user/net | open | `13`,`16`,`26` |
| 17 | Modern mount API (fsopen/fsconfig/fsmount/fspick + mount_setattr) + real mount/umount/chroot | open | `16` |
| 18 | xattr family ext4-backed + ACLs + capability bits on files | open | `16`,`27` |
| 19 | fanotify_init + fanotify_mark + inotify completeness | open | `16` |
| 20 | userfaultfd + memfd_secret enforced isolation | open | `11` |
| 21 | ptrace family (ATTACH/SEIZE/DETACH/CONT/SYSCALL/SINGLESTEP/GETREGS/SETREGS/PEEK/POKE/GETSIGINFO/SETOPTIONS + signal-stop integration) | open | `27`,`13` |
| 22 | io_uring (setup/enter/register, SQE/CQE rings, fixed-buffer registration, IORING_OP_*) | open | `30` |
| 23 | bpf + seccomp + landlock (verifier + JIT both arches + hook points) | open | `27` |
| 24 | SysV IPC (shm/sem/msg) + POSIX MQ + keyring | open | `24` |
| 25 | perf_event_open + tracefs/ftrace + ebpf programs running tracepoints | open | `27`,`37` |
| 26 | Core dump generation (sigaction SIGSEGV → ELF coredump in fs) | open | `27`,`16` |
| 27 | Dynamic linker (real ld-musl: PT_INTERP, DT_NEEDED, GOT/PLT, RELA/JMPREL, ld.so.cache, LD_LIBRARY_PATH, dlopen/dlsym) | open | `31`,`29a` |
| 28 | Standard userspace libc + NSS + PAM (musl-with-nss, /etc/{passwd,group,shadow}, pam_unix) | open | `29a`,`43` |
| 29 | System manager (real PID 1 — service supervision, dep order, journalctl on klog ring) | open | `29a` |
| 30 | Package manager (rpmbuild against our libc, dnf/microdnf, /var/lib/rpm) | open | `43`,`29a` |
| 31 | TTY + login flow (agetty per /dev/tty[0-N], terminfo/ncurses, motd/issue, real /dev/console termios) | open | `28`,`29a` |
| 32 | DRM/KMS framebuffer + virtio-gpu + input subsystem (evdev) | open | `35` |
| 33 | vDSO per-arch + glibc compat surface (FSGSBASE, set_thread_area i386, IFUNC) | open | `15` |
| 34 | USB stack | open | new spec |
| 35 | ACPI runtime + AML interpreter | open | new spec |
| 36 | KVM / hypervisor backend | open | new spec |
| 37 | NFS / CIFS / FUSE | open | new spec |
| 38 | SELinux / AppArmor / IMA — full LSM impls | open | `27` |
| 39 | DT overlays + full netfilter | open | new spec |
| 40 | Wayland + GNOME (graphical stack) | open | `35`, new spec |
| 41 | NUMA + hibernate/S3 + Memory Protection Keys | open | `10`,`11` |

### 3.1 Status snapshot

**Done:** phases 0-13 fully landed. Boot + login + interactive
busybox green on both arches.
**Open:** phases 14-41. No phase is "deferred"; ordering is
dependency-driven only.

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
- Orders 0..=20 (4KiB..4GiB). 1 zone now; NUMA per phase 41.
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
- No vmalloc-equivalent yet; added when drivers need >slab discontig-phys contig-virt.

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
- First-class: uart-{16550,pl011}, virtio-{blk,net,console,rng,vsock,input,gpu}, AHCI, NVMe, PS/2-keyboard (x86 console fallback). USB stack per phase 34. Detail: `35`.

## 9 Absolute exclusions

The only things this kernel will never ship:

| Item | Why |
|---|---|
| 32-bit anything; PAE / x86 segment tricks beyond long mode | architectural — long-mode only, 64-bit only |
| Big-endian | both target arches are little-endian; saves a register-shuffling tax |

Everything else listed in any prior "non-goals" table is in scope.
The ordering across phases (§3) is dependency-driven, not a priority
filter. Tempted to call something out of scope? It isn't — it's a
later phase.

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
3. Phases ordered by dependency; non-overlapping phases land in parallel.
4. Bug >2d to localize ⇒ stop, build the missing test infra that would have localized it. Don't just fix.
5. Every feature is in scope — there is no "next release" parking lot. Out-of-current-phase work goes into a later phase; it does not become "deferred indefinitely."

## 15 Release criterion

A release tag (`v1.0`, then `v1.1`, `v1.2`, …) ships when:
1. PR-time CI green on the tagged commit, both arches, both profiles.
2. Every `43§2` acceptance binary the phases-done-so-far cover runs end-to-end on QEMU (boot → login → run binary → exit clean).
3. Kernel-completeness audit `docs/kernel-audit.md` shows no stub regressions vs the previous tag.

That's it. No 168h soak, no duration-based wait — PR-time green + acceptance is the wall. AI-driven oracle proptests + miri + loom + QEMU differential are how bugs get found, not duration runs.

Artifact = `(commit, arch, sha256s of kernel + rootfs, acceptance-binary list with exit codes)`. When in repo → tag the next version.

## 16 Appendix A — spec list

See `MANIFEST.md`.

## 17 Changelog

- 2026-05-14: v1/v2/v2.x framing deleted wholesale. Single phase ladder; every Linux subsystem in scope. `docs/00-v2.md` and `docs/v2/` deleted. `§9 non-goals` collapsed to two architectural exclusions (32-bit, big-endian). `§15` re-framed as a generic release criterion that fires per tag, not a one-shot `v1.0` gate.
- 2026-05-08: `43§2` acceptance shrunk to busybox-only (R05).
- 2026-05-06: phase ladder gains explicit rows 10/11/12 for modules loader, PCI enumeration, virtio common infra. Spun out from "phase 9 + driver work backing phase 8" because each turned out to be a multi-PR slug deserving its own gate.
- 2026-05-06: phases 13–17 added covering the Linux-userspace integration arc — dynamic linker, libc/NSS/PAM, system manager, RPM toolchain, agetty/login flow. Each phase is a usable milestone (e.g. phase 13 alone unlocks running unmodified Fedora binaries with a small set of .so files staged).

## 18 OQ

Living doc. OQs handled by individual fixes in subsystem specs.
