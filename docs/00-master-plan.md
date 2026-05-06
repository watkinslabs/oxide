# 00 Master Plan: oxide2

DRAFT (living). Dep:`02`,`03`,`04`,`05`,`06`,`07`,`08`,`09`,`MANIFEST`.

Goal: self-hosting, multi-user, preemptive, SMP, virtual-memory OS in Rust. Targets `x86_64-unknown-oxide-kernel`, `aarch64-unknown-oxide-kernel` (`07§3`). HAL trait-based per-arch.

Rule: every subsystem ships with model + hosted oracle test + property suite. **Phase advance gated on PR-time CI** (≤5min): build both arches, 10M-op property tests, loom, miri, QEMU smoke, canary 1h, coverage ≥95%, bench within 5%. **Soak runs continuously on `main`; bugs file tickets, not phase walls.** Only v1 release gates on 168h soak.

## 0 Last-attempt failures (recorded so we don't repeat)

1. PMM/slab/VMM written before testable; corruption undebuggable from inside the kernel using the corruption.
2. Buddy split/merge never oracle-diffed; "tested by booting"; failed under fragmentation patterns after 90min.
3. PT walker by-hand vs no QEMU monitor cross-check; off-by-one PTE flags = 1wk each.
4. Ctxsw saved wrong reg set on less-tested arch; manifested only when preempt landed mid-syscall after a callee-saved clobber. Found via 2wk of register dumps.
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

## 3 Phases (effort estimates per `05§B1`)

Phase exit = PR-time gates green + canary 1h + bench within budget + coverage met. Sequential. No 24h soak wall (soak runs in background on `main`; bugs = tickets).

| # | Subsystem | Effort solo | Spec |
|---|---|---|---|
| 0 | Build infra (xtask, targets, hello-world boot, CI, Docker img) | 1–2wk | `07`,`39`,`40` |
| 1 | PMM (buddy + bitmap-truth + oracle) | 2–3wk | `10` |
| 2 | VMM + MMU bring-up + per-CPU areas + TLB shootdown | 4–6wk | `11`,`20`,`21` |
| 3 | Slab + GlobalAlloc | 1–2wk | `12` |
| 4 | Sched + ctxsw + preempt + SMP | 6–8wk | `13`,`14` |
| 5 | Syscalls + ELF loader + init + busybox-sh | 4–6wk | `15`,`31`,`29` |
| 5.5 | (deferred v1.x) io_uring | 3–4mo | `30` |
| 6 | VFS + tmpfs + procfs + sysfs + devtmpfs + ext4 RO | 3–4wk | `16`,`19` |
| 7a | Block layer + page cache | 2–3wk | `17` |
| 7b | ext4 RW + JBD2 | 4–7wk | `17` |
| 8 | Net (loopback + virtio-net + TCP must-run-binary subset) | 10–15wk | `25` |
| 9 | Hardening, observability, modules | ongoing | `27`,`37`,`18` |
| 10 | Modules loader (ELF ET_REL parse + relocator + section placement + symbol resolution + `init_module`/`finit_module`/`delete_module`/`/proc/modules`) | 2–3wk | `18`,`31` |
| 11 | PCI / PCIe bus enumeration (config space + `Bdf` + class-coded device list + boot-trace dump) | 1wk | `34` |
| 12 | virtio shared infrastructure (split virtqueue, status bits, common feature negotiation) — gates virtio-net (`8`), virtio-blk (`7a`/`7b`), virtio-console, virtio-rng | 2–3wk | `34`,`35` |
| 13 | Dynamic linker (ld-linux-x86-64.so.2 / ld-musl): PT_INTERP handler, shared-object load + GOT/PLT relocation, `dlopen`/`dlsym`, ld.so.cache, `LD_LIBRARY_PATH` resolution | 6–8wk | `31`,`29a` |
| 14 | Standard userspace libc + NSS + PAM: glibc-compatible (or musl-with-nss) shared libs in `/usr/lib64`, `getpwnam`/`getgrnam`/`getlogin` walking `/etc/{passwd,group,shadow}`, `pam_unix` for `login(1)` / `su` / `sudo` | 8–12wk | `29a`,`43` |
| 15 | System manager + service supervision: oxide-init re-implemented as a real PID 1 (cgroup-isolated services, dependency-ordered start/stop, socket activation, `journalctl`-equivalent reading the klog ring + per-service log streams). Sysvinit-shaped `/etc/init.d` rc-scripts for v1; systemd-compat unit files in v1.x. | 8–10wk | `29a` |
| 16 | Package manager: build a working `rpmbuild` against our libc + the `librpm` Berkeley-DB+sqlite stack; install pre-built RPMs from a local repo via `dnf` (or a thinner `microdnf`); `/var/lib/rpm` Berkeley-DB or sqlite-backed package db. | 10–14wk | `43`,`29a` |
| 17 | TTY + login flow: real /dev/tty[0-N] from kernel-side line-discipline (`28`), `agetty` spawning login per tty, `motd`/`issue` rendering, terminfo/ncurses installed as `/usr/share/terminfo/*`. | 4–6wk | `28`,`29a` |

Phases 10–12 were spun out from phase 9 + the driver work backing phase 8 because they each ended up large enough (and reusable enough across phases) to deserve their own gate. Phase 10 is the .ko runtime loader; phase 11 is the PCI bus enumeration that every PCIe device driver consumes; phase 12 is the virtio common layer that virtio-net (under phase 8) and virtio-blk (under phase 7a/7b) both drive off. Phase 9 stays "ongoing hardening + observability" — anything that doesn't fit the other named phases.

Phases 13–17 cover the journey from "static-musl single-shot binaries" (where v1 stops) to "build + install + run unmodified Fedora/RHEL RPMs":
- **13** — dynamic linking. Without this, `dnf install nginx` ends with a binary that wants `ld-linux-x86-64.so.2` and no userspace lookup chain. ld-musl has a much smaller surface than glibc's ld.so; v1 picks one (probably musl, since we already build static-pie userspace with musl-gcc) and the other comes in v1.x.
- **14** — libc/NSS/PAM. The glibc/musl userspace assumes /etc/passwd backs `getpwnam`. PAM is what `login(1)`, `su`, `sudo`, sshd all consult for "is this password valid". RHEL ships pam_unix.so by default; we need a port (or the upstream PAM source built against our libc).
- **15** — service supervisor. The lazy-respawn loop in `userspace/init/init.c` doesn't scale past one shell. Real Linux distros need cgroup-isolated services with dependency ordering. systemd is the de-facto standard but is heavyweight; sysvinit-shape rc scripts are tractable and Fedora still supports them via systemd's compat layer.
- **16** — RPM. `rpmbuild` itself is a glibc binary that depends on librpm + libdb (or rpm-sqlite) + libzstd + libpopt + libcap + libcrypt + lua + libmagic + python (for `%pre`/`%post` scriptlet runners). We can pre-build RPMs on a Fedora host and only need the `dnf install` side to work; that's still ~20 dynamic libs the dynamic linker resolves at runtime.
- **17** — interactive ttys. We currently run sh on stdin/stdout pinned to UART. `agetty` opens `/dev/tty1` and runs `login`; once 13+14 land we can wire it up.

Honest total v1 solo with phases 0-12 done: **10–16mo**. Adding 13–17 to reach "Fedora-class boot-to-`dnf install nginx` capability" pushes the realistic v1.x calendar to **22–30mo** — but each phase is a usable milestone. Phase 13 alone unlocks "run unmodified Fedora binaries" once the few critical .so files are in place.

Phase exit criteria detailed in each subsystem spec's §Test contract. PR-time CI is the wall.

## 4 Verification stack (`42` for patterns)

1. Oracle proptest — every algorithmic subsystem has stupid reference impl in `tools/oracle-*/`; lockstep diff per op. Single biggest change vs last attempt.
2. Loom — every lock-free / fine-grained-lock DS. Hosted, in CI, every PR.
3. Miri — hostable crates, unit tests in CI. Caveats `05§C7`.
4. QEMU+monitor differential — MMU: random map+`gva2gpa`+`info tlb`+`info mem` cross-check. We never wrote this last time.
5. Soak — CPU-hours not iterations. Signed artifact (build hash, duration, seed, exit). Subsystem not "done" without artifact in repo.
6. Boot-N-times — different RNG seeds; userspace probe OK. Catches early-init races. N=1000 by phase 3, 10000 by phase 5.
7. Coverage — pmm/slab/vmm/sched/vfs ≥95% hosted; HAL ≥80% asm trampoline coverage in QEMU. PR-blocking.
8. Static — `clippy::pedantic`, `cargo deny`, SAFETY comments enforced (`07§5`,`05§C6`).

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

## 9 Explicit non-goals v1 (each prevents 6mo tarpit)

No: 32-bit anything; PAE / x86 segment tricks beyond long mode; hibernate / S3; KVM/hypervisor; swap to disk; quotas; NFS/CIFS; FUSE; SELinux/AppArmor/IMA; DRM/KMS/GPU graphics (serial+EFI fb only); USB stack (HID-only via virtio); ACPI runtime / AML interp; DT overlays; iptables/netfilter (BPF hooks v1.x).

Tempted? `docs/v2/` it.

## 10 CI

PR (the phase gate): build both arches both profiles, `xtask test --hosted` (10M-op proptest), miri, loom, qemu smoke both arches, canary 1h, bench-vs-history, coverage gate, clippy `-D warnings`, deny, spec-lint. ≤5min for fast jobs; canary 1h runs concurrently. Detail `40§2`.
Background (continuous on `main`, NOT phase gate): 4h soak cycles, weighted workload rotation. Failures file tickets.
v1 release tag: requires 168h soak artifact, both arches, on tagged commit. Sole place we wait. Detail `40§4`.

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
| Slow CI killing momentum | hosted <2min, QEMU smoke <5min, soaks nightly (PR not blocked) |

## 14 The five rules

1. No subsystem merge until PR-time gates green (build, oracle proptest 10M ops, loom, miri, qemu smoke, canary 1h, coverage, bench). Soak is background diagnostic, not gate.
2. No `unsafe` ships without SAFETY naming invariant.
3. Phases sequential. No parallel-across-gate.
4. Bug >2d to localize ⇒ stop, build the missing test infra that would have localized it. Don't just fix.
5. Out-of-phase feature ⇒ `docs/v2/`. Keep going.

## 15 v1 exit criterion

Single 168h soak artifact on the soak box (no second machine — `05§G2`):
- 168h continuous uptime, 4-CPU QEMU each arch.
- Concurrent: kernel-build-self loop + iperf3 loopback ≥5GB/s + fs_mark ext4 + stress-ng `--cpu --vm --hdd`.
- Zero panics, zero oopses, zero silent corruption (SHA-256 reconciles fs_mark corpus).
- All v1 must-run binaries (`43§2`) pass acceptance scenarios.

Artifact = `(commit, arch, duration, seed, exit, sha256s)` signed by soak box's Ed25519 key. When in repo → ship v1.

## 16 Appendix A — spec list

See `MANIFEST.md`.

## 17 Changelog

- 2026-05-06: phase ladder gains explicit rows 10/11/12 for modules loader, PCI enumeration, virtio common infra. Spun out from "phase 9 + driver work backing phase 8" because each turned out to be a multi-PR slug deserving its own gate. Total v1 estimate widened from 9–14mo → 10–16mo to reflect the un-folded scope.
- 2026-05-06: phases 13–17 added covering the Linux-userspace integration arc — dynamic linker, libc/NSS/PAM, system manager, RPM toolchain, agetty/login flow. v1.x calendar to "Fedora-class boot-to-`dnf install nginx`" estimated 22–30mo total. Each phase is a usable milestone (e.g. phase 13 alone unlocks running unmodified Fedora binaries with a small set of .so files staged).

## 18 OQ

Living doc. OQs handled by individual fixes in subsystem specs.
