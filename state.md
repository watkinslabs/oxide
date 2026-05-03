# State 2026-05-03 (session 7 EOD)

Resumable checkpoint. Update at session exit. Next session reads this first along with `CLAUDE.md` and `docs/MANIFEST.md`.

## Phase

**Phase 1 substantially done. Cooperative scheduling end-to-end on both arches.** 131 PRs total; 463 hosted tests pass; both arches boot through Limine into `kernel_main`, parse ACPI, bring up PMM, splice kernel-device MMIO mappings into the live page tables (PMM-backed walker), enable LAPIC (x86) / GIC (arm), take real timer IRQs, and run a 4-kthread cooperative scheduler smoke driven by timer-set `NEED_RESCHED`. Per-subsystem `debug-{pmm,vmm,irq,acpi,sched,boot}` Cargo features gate every kernel-side `klog` call site so default builds emit zero log bytes.

Last verified-green at session-7 EOD:
```
$ cargo run -p xtask -- spec-lint            # → spec-lint: clean
$ cargo run -p xtask -- test                 # → 463 hosted tests, 0 failures
$ cargo run -p xtask -- kernel  --arch x86_64                   # builds clean
$ cargo run -p xtask -- kernel  --arch aarch64                  # builds clean
$ cargo run -p xtask -- kernel  --arch x86_64  --features debug-all
$ cargo run -p xtask -- kernel  --arch aarch64 --features debug-all
$ cargo run -p xtask -- qemu    --arch x86_64  --features debug-all
…
[INFO]  preempt: kthread 4 done
[INFO]  preempt: done yields=0 ticks=16
[…] [INFO]  boot: kernel ready, halting
$ cargo run -p xtask -- qemu    --arch aarch64 --features debug-all
… same trace, identical structure …
```

## What's done in session 7 (PRs #87 – #131, 45 PRs)

Session 7 was a long autonomous push. Highlights, oldest first:

| PR span | Subject |
|---|---|
| #87 – #91 | Bootloader integration: vendored Limine, GPT/ISO image build (`xtask image`), QEMU launcher (`xtask qemu`), Limine protocol crate `crates/limine-proto/` shared by both boot crates, magic-words pinned against upstream `limine.h`. |
| #92 | `B-` fix for the wrong HHDM/RSDP magic word in the request structs (4th word was `0x6342_8723_2167_8025` instead of `0x6398_4e95_9a98_244b`); bootloader was silently never writing the response. Pinning test now catches this. |
| #93 – #95 | `BootInfo` grows `hhdm_offset`; PMM stack bumped 16 K → 128 K; PMM init from `BootInfo` (`pmm_setup::HhdmBacking`, `init_from_boot_info`); per-vector x86 fault stubs (`oxide_vec_0..31`) with stack-aligned `call oxide_fault_print_rust`. |
| #96 – #105 | Stability + xtask polish: QEMU `-cpu Haswell-v4` baseline (default qemu64 traps `SHRX` → BMI2 needed), Cargo pinning, kalloc smoke, slab-cache stack overflow workaround. |
| #106 – #115 | ACPI fully decoded: RSDP parse, XSDT walk, MADT (LAPIC/IOAPIC/x2APIC/GICC/GICD/GICR), HPET, SPCR, MCFG, GTDT decoders. `BootInfo.rsdp_pa` plumbed. |
| #116 – #119 | Kernel device mapper: `hal_x86_64::vmm::map_device_4k` + `hal_aarch64::vmm::map_device_4k` splice 4 KiB Device-attr leaves into the live PML4 / TTBR1_EL1 using a caller-supplied PMM frame allocator. PL011 driver moves from semihost to real UART once PMM-backed mapping lands. |
| #120 – #123 | LAPIC enable + identity log + polled timer (x86); GICv2 enable + polled CNTV smoke (arm). |
| #124 – #125 | x86 IRQ entry stub for vec 0x40, IDT[0x40] hookup, LAPIC `timer_periodic` + STI; first real interrupt-driven kernel behaviour: `lapic: timer ticks=762`. |
| #126 | **ARM IRQ infrastructure** symmetric to x86 — VBAR slot 0x280 → asm GP-save → `oxide_arm_irq_dispatch` → IAR/EOIR + `TICK_COUNT++` + reload `CNTV_TVAL_EL0`. Same PR introduces R05 revision to `docs/04§3` adding per-subsystem `debug-{pmm,vmm,irq,acpi}` Cargo gates; every diagnostic call site now sits inside a `debug_<sub>!` macro pair so default builds elide. |
| #127 | First kernel-thread coroutine: build an arch `Context` via `new_kernel`, allocate a 16 KiB stack, `Context::switch` into it, kthread emits a klog line and switches back. |
| #128 | Three-way yield (boot → A → B → A → boot) — multi-frame stack discipline + arg-passing through trampoline. |
| #129 | 4-kthread cooperative round-robin scheduler smoke (`kernel/src/ksched.rs`). Tiny `KSched` with `Vec<KThread>` + `cur` cursor; each kthread yields N times then self-marks done; total 16 yields, returns to boot. |
| #130 | Timer-driven cooperative scheduling: timer ISRs set `NEED_RESCHED`; kthreads `hlt`/`wfi` until woken, observe the flag, cooperatively yield via `tick_yield`. Both arches identical: 4 kthreads, 3 ticks each, all done, 16 ticks total. **Honest scope note:** this is *cooperative-with-timer-wake*, not true preemption. True IRQ-exit preemption requires every task to carry a synthetic `iretq`/`eret` frame on its stack so the asm epilogue can iretq cleanly into a freshly-spawned task; that protocol change is tracked for a follow-up. |
| #131 | **R06 revision to `docs/04`**: every `klog::*` call site (level macros + byte-emit helpers + `set_byte_sink`) MUST be inside a per-subsystem `#[cfg(feature = "debug-<sub>")]` gate or a `debug_<sub>!` macro pair. Default builds emit zero log bytes; runtime per-target levels (§4.5) are not a substitute. Adds `debug-boot` feature for operational pulse (init started, pmm: ready, boot: kernel ready). Code sweep: `kernel/src/lib.rs` wraps every unconditional klog; `acpi`/`ksched`/`kthread` modules cfg-gated at declaration site. spec-lint check (`code/klog-ungated`) tracked for follow-up. |

## What's done overall

### Spec corpus (44 / 46 FROZEN)

Unchanged structurally. Two revisions added in session 7:
- **R05** (`docs/04§3`): per-subsystem `debug-{pmm,vmm,irq,acpi}` Cargo features.
- **R06** (`docs/04§3` + `§4.0` new): klog-must-be-gated invariant; adds `debug-boot`.

### Tooling

Unchanged plus:
- `crates/limine-proto/` — shared Limine protocol types + magic-words pinning test against upstream `limine.h`.
- `xtask kernel/qemu/image` accepts `--features <csv>` and forwards to cargo.
- `xtask qemu` real impl: GPT image + UEFI boot via Limine on x86; PL011 + virt machine on arm.

### Kernel + per-subsystem crates

| Path | Role | Status |
|---|---|---|
| `kernel/` | lib + `kernel_main(&BootInfo)` + `#[global_allocator]` + per-arch device-bringup smoke + cooperative scheduler smoke | builds host + both kernel targets; default builds emit zero kernel klog |
| `kernel/src/{acpi,kthread,ksched}.rs` | cfg-gated at module declaration to their respective `debug-{acpi,sched}` feature | only compiled when feature on |
| `kernel/src/{lapic,gic,arm_timer,pl011,pmm_setup,preempt}.rs` | always-on production bring-up modules | klog calls inside individually wrapped in `debug_<sub>!` |
| `crates/hal-{x86_64,aarch64}/` | + IDT/VBAR + IRQ asm stubs + device-VA mapper (`vmm::map_device_4k`) + Context + PtRegs + MMU + FPU | unchanged in surface; new mapper code added |
| `crates/limine-proto/` | shared protocol types + magic-words pinning | new in session 7 |
| `crates/boot-{x86_64,aarch64}/` | `_start` → UART sink → IDT/VBAR install → `kernel_main` | klog calls in these crates are NOT yet gated — flagged for follow-up sweep |
| Other crates | unchanged from session 6 EOD; same surface |

Workspace test count: **463 passed, 0 failed.**

### klog-gating invariant (R06, frozen 2026-05-03)

Every `klog::*` call site MUST be inside one of:
- `#[cfg(feature = "debug-<sub>")]` block, attribute on enclosing fn / mod, or
- a `debug_<sub>!` macro pair (cfg-on → body, cfg-off → empty).

Per-subsystem features in `kernel/Cargo.toml`:
- `debug-pmm` — PMM smoke + stress + memmap dump
- `debug-vmm` — device-map MMIO sanity reads (HPET cap, GICD typer)
- `debug-irq` — LAPIC/GIC enable diag + timer-IRQ soak + tick logs
- `debug-acpi` — RSDP/XSDT walk + per-table decoder traces
- `debug-sched` — first-kthread + RR + timer-driven smokes
- `debug-boot` — operational-pulse trace (init started, pmm: ready, boot: kernel ready, pl011 sink swap)
- `debug-all` — aggregate of all six

`fatal!` is the lone exception (§4.0). No spec-lint enforcement yet — `code/klog-ungated` tracked for follow-up.

## What's NOT done (pending tasks)

1. **Sweep `crates/boot-{x86_64,aarch64}/` for klog-gating** — pre-`kernel_main` lines (CPU vendor/MMU dump on x86, midr/mmu/ttbr on arm) are still ungated. R06 applies project-wide.
2. **`spec-lint` enforcement of `code/klog-ungated`** — the rule is in the spec, the lint check itself is not yet implemented.
3. **True IRQ-exit preemption** — requires every task to carry a synthetic iretq/eret frame on its stack so the IRQ asm epilogue can pop scratch + iretq into freshly-spawned tasks. Current scheduling is cooperative-with-timer-wake. The protocol change is per `14§4` — needs `Context::new_kernel` to pre-populate stack frames for IRQ exit, not just for `Context::switch` `ret`.
4. **First userspace `iretq`/`eret` smoke** (Phase 2 boundary) — `Context::new_user` exists in HAL crates but the actual transition to ring 3 / EL0 isn't wired. Needs user GDT + CS/SS (x86) or SPSR config (arm); user kernel-stack swap; syscall entry path; return-to-user path.
5. **Wire `crates/sched`'s real `RunqueueInner` into the kernel** — `kernel/src/ksched.rs` is a kernel-only Vec-based shim. The frozen spec (`13§5`) wants `Task` extended with `kernel_stack` + arch-context fields and the kernel using `RunqueueInner::pick_next_task`. Plumbing-heavy refactor; doesn't unblock anything immediately so deferred.
6. **MmuOps walker** (`20§5`/`21§5`) — PTE encoding ✓ from session 5; the walker still needs refactoring out of the inline `vmm::map_device_4k` and made arch-generic.
7. **Page-fault path** (`11§5` + `11§7`): COW, fork, TLB shootdown.
8. **Block writeback / procfs surface / VFS dentry cache / IPC bodies / userspace platform** — all unchanged from session 6 EOD pending list.
9. **CI matrix update** to exercise each `debug-<sub>` feature in addition to no-features and `debug-all` (per `04§3` "release no-features, release debug-all, dev each debug-* solo").
10. **Files over 500-line soft cap** (touch on next edit):
    - `kernel/src/lib.rs` ~640
    - `kernel/src/ksched.rs` ~430 (post-#130; reaching cap fast — split likely needed soon)

## Repo state

```
main (origin/main): 59cfaf5 Merge pull request #131 from watkinslabs/R02-klog-must-be-gated

131 PRs landed total. Branches preserved (no deletions).

Session 7 (PRs #87 – #131, 45 PRs): bootloader integration → ACPI → kernel device mapper → LAPIC/GIC enable
  → x86 + ARM IRQ infrastructure → first kthread → 3-way yield → 4-way RR → timer-driven cooperative
  → R05/R06 debug-feature gates.
```

Active local branches at EOD: `main` (working tree clean). Recent feature branches preserved: `P1-76-arm-irq-infra` through `R02-klog-must-be-gated`.

Remote: `origin = git@github.com:watkinslabs/oxide.git`.

## Active discipline (must hold)

- Branch-per-feature + PR-mandatory: `gh pr create` + `gh pr merge --merge --delete-branch=false`.
- Numbered branch scheme: `F/B/D/R/Z/C/P<n>-<NN>` + kebab title.
- AI-density per `08`. Cross-ref form: `<doc>§<sec>`.
- `cargo run -p xtask -- spec-lint` clean before commit.
- `panic = "abort"`, `kassert!` only, no `static mut`, no `dyn HAL`, `// SAFETY:` ≥30 chars.
- File length ≤ 1000 lines hard, 500 soft.
- **NEW (R06)**: every `klog::*` call site MUST be cfg-gated under a `debug-<sub>` feature. Default builds emit zero log bytes. The runtime per-target level filter is NOT a substitute — gating is at the call site, not inside the logger.
- Force-push to main: explicit user instruction only.
- No `Co-Authored-By:` trailers.

## Resume protocol next session

1. `cd /home/nd/oxide2 && git status` (clean, on `main`).
2. `git log --oneline -5` (HEAD = #131 merge or descendant).
3. Read this file (`state.md`).
4. Read `CLAUDE.md`.
5. Read `docs/MANIFEST.md`.
6. `cargo run -p xtask -- spec-lint` (`spec-lint: clean`).
7. `cargo run -p xtask -- test` (≥463 passed, 0 failed).
8. `cargo run -p xtask -- kernel --arch x86_64` then `--arch aarch64` (both build clean).
9. Optional sanity: `cargo run -p xtask -- qemu --arch x86_64 --features debug-all` and same for arm — should print the cooperative-scheduler smoke + reach `boot: kernel ready, halting`.

## Suggested next branches

| Option | Branch idea | Why pick this |
|---|---|---|
| **Boot-crate klog sweep** | `R03-klog-gate-boot-crates` | Apply R06 invariant to `crates/boot-x86_64/` + `crates/boot-aarch64/`. Small, mechanical, completes the rule project-wide. |
| **spec-lint `code/klog-ungated`** | `C20-spec-lint-klog-ungated` | Implement the lint check that R06 mandates. Treats any `klog::*` use whose enclosing scope isn't under one of the allowed cfg forms as a build failure. |
| **True IRQ-exit preemption** | `P1-81-preempt-iret-frames` | Extend `Context::new_kernel` so a fresh kthread's stack has a synthetic iretq/eret frame; flip the IRQ dispatcher tail to drain `NEED_RESCHED` + `Context::switch` directly (not deferred). The big architectural step; ~400-600 LOC plus careful asm. |
| **First userspace `eret` smoke** | `P1-82-userspace-first-eret` | Cross the Phase 1→2 line. Build a minimum ELF, set up user GDT (x86) / SPSR config (arm), eret to ring 3 / EL0, handle a single syscall, return. Largest single jump; needs preempt landed first or accepts no scheduling. |

If unsure: **boot-crate klog sweep** + **spec-lint enforcement**, in that order. Both are small, mechanical, and close out R06 cleanly. Then either preemption or userspace as the user's call.

## Open questions for user (deferred)

- README.md CI status badge.
- Atomic cookie CAS in slab (cross-CPU double-free).
- Whether the cooperative-with-timer-wake scheduling form is acceptable for the rest of Phase 1, or whether true preemption is the gating milestone for Phase 2.
- Whether to move `kernel/src/ksched.rs` logic into `crates/sched/` (extending `Task` per `13§5`) before Phase 2, or after the userspace `eret` lands.
