# State 2026-05-03 (session 20 EOD)

Resumable checkpoint — current snapshot only. Update at session exit. Next session reads this first along with `CLAUDE.md` and `docs/MANIFEST.md`. **For per-session history of what landed see `CHANGELOG.md`** — this file is no longer the historical log.

## Phase

**Phase 2 substantially landed. Both arches cross Phase 1→2 boundary; x86_64 has full userspace round-trip via syscall+sysretq with 11 syscall slots bound; arm has eret-to-EL0 + return via BRK validated.** 183 PRs total; 516 hosted tests. x86_64 kernel runs `mov $0x42,%eax; mov $1,%edi; mov $0x400100,%esi; mov $3,%edx; syscall; mov $60,%eax; xor %edi,%edi; syscall; ud2` at CPL=3 — bytes flow to UART, kernel logs proper Linux-style return values (rax=3 for write, 0 for exit, -ENOSYS for unbound), sysretq lands user back in ring 3 cleanly, ud2 fires the terminal #UD that the smoke handler logs. aarch64 kernel runs `brk #0` at EL0 and traps back via VBAR_EL1+0x400 with ESR.EC=0x3C decoded. Every spec-listed `klog::*` call site still sits inside a `#[cfg(feature = "debug-<sub>")]` or `debug_<sub>!` scope; default builds emit zero log bytes. `spec-lint code/klog-ungated` enforces project-wide. The R06 "user console output is not diagnostic" carve-out is documented at `crates/syscall/src/dispatch.rs` (use-aliased import bypasses the literal-prefix lint with intent-signaling alias name).

Last verified-green at session-20 EOD:
```
$ cargo run -p xtask -- spec-lint            # → spec-lint: clean
$ cargo run -p xtask -- test                 # → 516 hosted tests, 0 failures
$ cargo run -p xtask -- kernel  --arch x86_64                   # builds clean
$ cargo run -p xtask -- kernel  --arch aarch64                  # builds clean
$ cargo run -p xtask -- qemu    --arch x86_64  --features debug-all
…
[INFO]  pf-recover: ok pa=… magic=00c0ffeedeadbeef
[INFO]  user-map-smoke: ok pa=… flags=0x0d
[INFO]  boot: kernel ready, halting
[INFO]  userspace-eret-smoke: about to iretq cs=0x4b rip=0x400000 ss=0x43 rsp=0x501000
hi
[INFO]  syscall: nr=0x1  rv=0x3
[INFO]  syscall: nr=0x3c rv=0x0
[FAULT] vec=6 (#UD) err=0 rip=0x40001f
[INFO]  userspace-sysret-smoke: ok ring3 #UD rip=0x40001f

$ cargo run -p xtask -- qemu    --arch aarch64 --features debug-all
…
[INFO]  user-map-smoke: ok pa=… flags=0x0d
[INFO]  boot: kernel ready, halting
[INFO]  userspace-eret-smoke-arm: about to eret elr=0x400000 sp_el0=0x501000
[FAULT] esr=0xf2000000 ec=0x3c (brk) elr=0x400000
[INFO]  userspace-eret-smoke-arm: ok EL0 BRK elr=0x400000 esr=0xf2000000
```

`make ci` mirrors the full PR gate (lint + test + build + build-debug, both arches).

## What landed since previous EOD

See `CHANGELOG.md § Session 20` for the per-PR table. 18 PRs landed
this session (#166 – #183), crossing Phase 1→2 on both arches,
landing the full x86_64 syscall+sysretq round-trip, binding 11
syscall slots, fixing the caller-saved-GPR class of bug on both
fault dispatchers, and replumbing the arm walker to pick TTBR0/TTBR1
by VA.

Major landmarks:
- **#166-#170** Phase 1→2 boundary on x86 (kernel-owned GDT, TSS,
  interior-U=1, user-page smoke, first iretq).
- **#172** caller-saved GPR fix in x86 fault dispatcher; PF-recovery
  smoke. Audit later mirrored on arm in **#177**.
- **#173-#176** syscall MSRs + sysretq + dispatch glue + sys_write +
  sys_exit. User code now prints "hi" to UART then exits cleanly.
- **#178-#179** trivial syscalls (getpid/uid/gid/tid family) +
  sys_arch_prctl(ARCH_SET_FS) — gate to libc TLS.
- **#181-#182** arm walker TTBR0/TTBR1 selector + arm userspace
  eret smoke (BRK round-trip).
- **#183** sys_set_tid_address + sys_set_robust_list (musl/glibc
  startup needs these).

11 syscall slots bound: 1 (write), 39 (getpid), 60 (exit), 102/104/
107/108 (uid/gid family), 158 (arch_prctl), 186 (gettid), 218
(set_tid_address), 273 (set_robust_list).

- **#166** (`P1-93-kernel-owned-gdt`): kernel-owned GDT in BSS replaces Limine's. Selector offsets mirror Limine v6 layout (`KERNEL_CS=0x28` / `KERNEL_DS=0x30` keep working unchanged); adds `USER_CS=0x3B` / `USER_DS=0x43` (DPL=3) for Phase 2. Far return uses `.byte 0x48, 0xCB` (REX.W + retf) — long-mode `lret` defaults to 32-bit which would have hung the prior abandoned attempt. Validated under qemu-mcp by stepping through `lgdt` + segment reloads + `lretq`. +8 hosted tests.
- **#167** (`P1-94-tss-install`): 64-bit TSS in BSS + 16-byte system descriptor at GDT[9..11] (selector 0x48). Boot path issues `ltr 0x48` after GDT install. `set_rsp0()` exposed for per-task switch-in. RSP0/IST stay zero pre-userspace; iomap_base = sizeof(TSS) so no IO bitmap. +9 hosted tests.
- **#168** (`P1-95-user-mapping`): `pack_table` sets U/S=1 unconditionally on interior PT entries. Per Intel SDM §4.6 every interior entry on a CPL=3 walk must have U/S=1; leaf U bit alone gates accessibility. ARM walker untouched (AP[2:1] gates per-leaf). +3 hosted tests.
- **#169** (`P1-96-user-page-smoke`): runtime smoke maps a 4 KiB user VA at 0x40_0000 with `USER|EXEC|READ` and translates back, asserting USER+EXEC round-trip on real CR3/TTBR0 walks. Validates the P1-95 fix end-to-end on both arches.
- **#170** (`P1-82-userspace-first-iretq`): drops to CPL=3 by building a synthetic IRET frame and executing `iretq`. User code is `int3`; CPU vectors back through IDT[3] (DPL=3 gate) → fault dispatcher → custom handler logs `userspace-eret-smoke: ok`. Bug surfaced + fixed: IDT[3]/IDT[4] gates now use `GATE_INT64_USER` (0xEE, DPL=3); previously a CPL=3 `int3` produced `#GP(IDT, vec=3)`. **Phase 1→2 boundary crossed.**

- **#159** (`C36-readme-ci-badge`): README updated from Phase-0 placeholder. CI badge wired to `pr.yml`; status section reflects current state; `make` quick-start; pointers to `state.md` / `CHANGELOG.md`.
- **#160** (`P1-86a-fault-decode`): per-arch fault printer decodes vectors + PFEC/ESR/DFSC labels. x86 emits `[FAULT] vec=0xe (#PF) … pf=NP-W-K`; arm emits `ec=0x25 (data-abort-same-el) … dfsc=permission-l3 W`. +8 hosted tests.
- **#161** (`P1-84-task-arch-ctx-buffer`): `crates/sched::Task` now carries `kernel_stack: AtomicPtr<u8>` + `arch_ctx: UnsafeCell<ArchCtxBuf>` (128 B opaque buffer per `13§5`). `Task::arch_ctx_ptr<C>()` cast helper with const size assert; compile-time fits-check in kernel for `ContextX86_64` / `ContextAArch64`. +3 hosted tests (489 total).
- **#162** (`P1-86b-fault-recover`): per-arch fault stub now branches on the dispatcher's bool return — handled → `iretq`/`eret` retry; not handled → halt as before. New `pub type FaultHandler` + `pub unsafe fn install_fault_handler(h)` per arch. Default handler returns false, behaviour preserved.
- **#163** (`B07-debug-irq-feature-chain`): latent fix. xtask `--features debug-all` only applies to its `-p`-selected packages; `hal-{x86_64,aarch64}/debug-irq` was unreachable since #160. Chain through `boot-{arch}/Cargo.toml::debug-irq = ["hal-<arch>/debug-irq"]` so the fault decoder is actually live in production builds.
- **#164** (`C37-qemu-mcp-server`): interactive QEMU+GDB control surface as an MCP server (`tools/qemu-mcp/server.py`). 13 tools (`qemu_start`/`break`/`continue`/`stepi`/`step`/`finish`/`regs`/`mem`/`disasm`/`backtrace`/`info`/`serial`/`stop`). Pure stdlib + `mcp` package; spawns QEMU with `-s -S` + `gdb --interpreter=mi3`. `.mcp.json` at repo root registers it for Claude Code auto-load on next session start.

### Abandoned-then-recovered

- **P1-93 kernel-owned GDT** ✅ landed as #166. Root cause of prior hang likely 32-bit `lret` operand-size; new asm uses explicit REX.W.
- **P1-86c page-fault recovery smoke** — still abandoned. Lower priority post-Phase 1→2 cross; re-attempt with the userspace path intact would let us deliberate-fault from CPL=3 instead of CPL=0, which is closer to the real demand-paging shape.

## What's done overall

### Spec corpus (44 / 46 FROZEN)

Unchanged structurally. R07 added in session 9:
- **R07** (`docs/14`): `Context::new_kernel_with_irq_frame` per arch + scaffold layout (x86: 136 B; arm: 192 B); `oxide_irq_resume_user` shared epilogue; `oxide_preempt_{cur,next}_ctx` plumbing.

### Tooling

Unchanged plus root `Makefile` (`make ci` mirrors PR gate).

### Kernel + per-subsystem crates

| Path | Role | Status |
|---|---|---|
| `kernel/` | lib + `kernel_main(&BootInfo)` + `#[global_allocator]` + per-arch device-bringup smoke + preempt + canary smoke | builds host + both kernel targets; default builds emit zero kernel klog |
| `kernel/src/{acpi,kthread,ksched,preempt_smoke,canary}.rs` | cfg-gated at module declaration (`debug-acpi`/`debug-sched`) | `preempt_smoke` + `canary` new in session 10 |
| `kernel/src/preempt.rs` | `NEED_RESCHED` flag + `oxide_preempt_{cur,next}_ctx` + `tick_pick_next` hook | unchanged from session 9 |
| `kernel/src/{lapic,gic}.rs` | dispatchers call `preempt::tick_pick_next` after EOI | unchanged from session 9 |
| `crates/hal-{x86_64,aarch64}/src/{context,irq,vbar}.rs` | `new_kernel_with_irq_frame` + `oxide_irq_resume_user` + schedule-on-exit asm; ARM frame 192 B saving ELR/SPSR | unchanged from session 9 |
| `crates/hal/src/pt_walker.rs` | arch-generic `PtWalker` trait + `map_device_4k`/`map_4k`/`translate_4k`/`unmap_4k` drivers | session 11 + extended session 14 |
| `crates/hal-{x86_64,aarch64}/src/vmm.rs` | `PtWalkerX86`/`PtWalkerArm` impls + thin `map_device_4k` shims; new `pack_4k_leaf` for arch-neutral flags | session 11 + session 14 |
| `crates/hal-{x86_64,aarch64}/src/mmu_ops.rs` | `X86Mmu`/`ArmMmu` markers + `MmuOps` trait impl (4K only) + static-atomic state + setup APIs | new session 14 |
| `kernel/src/pmm_setup.rs` | `pmm_static()` + `alloc_one_frame()` bare-fn for MmuOps frame allocator | extended session 14 |
| `kernel/src/device_map_smoke.rs` | uses `<X86Mmu/ArmMmu as MmuOps>::map` | migrated session 14 |
| `kernel/src/mmuops_smoke.rs` | end-to-end MmuOps roundtrip smoke for 4 KiB + 2 MiB leaves | new sessions 16/17 |
| `crates/sched/src/task.rs` | `Task` carries `kernel_stack: AtomicPtr<u8>` + `arch_ctx: UnsafeCell<ArchCtxBuf>` (128 B opaque) per `13§5` | extended session 18 (#161) |
| `crates/hal-{x86_64,aarch64}/src/fault.rs` | `FaultHandler` + `install_fault_handler` registry; bool-return dispatch; vector + PFEC/ESR/DFSC label decoders | extended session 18 (#160, #162) |
| `tools/qemu-mcp/server.py` | 13-tool MCP server for QEMU+GDB control (Claude-side dev only) | new session 18 (#164) |
| `crates/hal-{x86_64,aarch64}/src/fault.rs` | exception printer body under `debug-irq` | unchanged |
| `crates/boot-{x86_64,aarch64}/` | per-crate `debug-boot` gate | unchanged |
| `crates/limine-proto/` | shared protocol types + magic-words pinning | unchanged |
| Other crates | unchanged from session 8 EOD |

Workspace test count: **489 passed, 0 failed.** (+24 over session 10: pt_walker driver, per-arch pack/unpack roundtrips, MmuOps round-trip per arch, 2M + 1G `map_at_level`, translate/unmap_at_va huge-leaf tests, fault-vector + PFEC/ESR/DFSC decoders, Task arch_ctx round-trip.)

### IRQ-exit preemption (R07 — fully implemented)

Per-vector IRQ stub flow (both arches):
1. CPU pushes iretq/eret frame; stub pushes scratch GPs + (x86) vec/err pad + (arm) ELR/SPSR.
2. `bl/call oxide_irq_dispatch` → Rust dispatcher (lapic/gic) bumps tick + EOI, then calls `preempt::tick_pick_next`.
3. Picker (`ksched::tick_pick_next_for_irq_exit`, gated `debug-sched`) picks next not-`done` kthread, stages `(prev,next)` in `oxide_preempt_{cur,next}_ctx`.
4. Asm reads `oxide_preempt_next_ctx`; if non-null, calls `oxide_context_switch(cur,next)`. Both paths fall through to `oxide_irq_resume_user`.
5. Resume label pops scratch + restores ELR/SPSR (arm) + iretq/eret. Fresh kthreads enter via the synthetic IRQ frame; previously-preempted kthreads return to where they were interrupted.

`fatal!` is the lone exception. Cooperative `tick_yield` voluntary path retained for the kthread "I'm done, give boot back" edge.

## What's NOT done (pending tasks)

1. **64-task 1h canary soak** (`docs/14§8`) — bounded version landed (#139). The full 64 × 1ms × 1h soak requires the background CI infra per `40§3` which is still spec-only.
2. **First userspace `iretq`/`eret` smoke** (Phase 2 boundary) — `Context::new_user` exists in HAL crates but the actual transition to ring 3 / EL0 isn't wired. Needs a kernel-owned GDT (Limine's GDT lacks user descriptors), user CS/SS for x86 / SPSR config for arm, user kernel-stack swap, syscall entry path, return-to-user path. Largest single jump.
3. **Wire `crates/sched`'s real `RunqueueInner` into the kernel** — `kernel/src/ksched.rs` is a kernel-only Vec-based shim. Frozen spec (`13§5`) wants `Task` extended with `kernel_stack` + arch-context fields and the kernel using `RunqueueInner::pick_next_task`. Plumbing-heavy refactor.
4. **MmuOps full huge-page surface complete.** `MmuOps::{map,translate,unmap}` handle 4K/2M/1G (#152, #154). `flush_va` + `flush_all_local` arch-native. Today's only caller is the device-MMIO mapper (4K-only); broader callers land with the page-fault handler / userspace mmap path.
5. **Page-fault path** (`11§5` + `11§7`): COW, fork, TLB shootdown.
6. **Block writeback / procfs surface / VFS dentry cache / IPC bodies / userspace platform** — unchanged from session 8 EOD pending list.
7. **CI matrix update** to exercise each `debug-<sub>` feature solo (per `04§3` recipe). Presupposes a real CI workflow file exists; that's still spec-only at `docs/40`.
8. **Files over 500-line soft cap** (deferred — non-kernel code or test files):
    - `crates/pmm/src/tests.rs` (751) — split candidate per CLAUDE.md test-file rule.
    - `crates/pmm/src/lib.rs` (626).
    - `crates/slab/src/lib.rs` (508).
   All kernel-side code files now under cap. Recent splits: `ksched.rs` (367), `kernel/src/lib.rs` (423), `tools/xtask/src/main.rs` (184).

## Repo state

```
main (origin/main): <session-18 docs merge>

164 PRs landed total. Branches preserved (no deletions).

Session 9  (PRs #136 – #138):
  C22-makefile               — make wrapper
  P1-81-preempt-iret-frames  — true IRQ-exit preemption (R07)
  C23-state-eod-session-9    — session-9 docs

Session 10 (PRs #139 – #140):
  P1-83-ctxsw-canary         — 64-task ctxsw register canary
  C24-ksched-split           — split ksched.rs into shared core + preempt_smoke

Session 11 (PR #141):
  P1-85-mmu-walker-generic   — arch-generic 4-level page-table walker

Session 12 (PRs #142 – #143):
  C25-state-eod-session-11   — session-11 docs
  C26-device-map-smoke-split — split lib.rs (700 → 423) into debug_macros + device_map_smoke

Session 13 (PRs #144 – #147):
  C27-state-eod-session-12   — session-12 docs
  C28-spec-lint-no-dyn-hal   — lint dyn HAL traits
  C29-ci-debug-all-matrix    — CI matrix default + debug-all per arch
  C30-xtask-qemu-split       — split xtask main.rs (576 → 184) into image_qemu module

Session 14 (PRs #148 – #151):
  C31-state-eod-session-13   — session-13 docs
  P1-87-mmuops-impl-4k       — MmuOps trait impl per arch (4 KiB)
  P1-88-mmuops-wire-pmm      — wire MmuOps to PMM + migrate device-map smoke
  C32-state-eod-session-14   — session-14 docs

Session 15 (PRs #152 – #153):
  P1-89-mmu-huge-pages       — MmuOps huge-page support (2 MiB / 1 GiB)
  C33-state-eod-session-15   — session-15 docs

Session 16 (PRs #154 – #155):
  P1-90-mmu-huge-translate   — MmuOps translate/unmap recognise huge leaves
  C34-state-eod-session-16   — session-16 docs

Session 17 (PRs #156 – #158):
  P1-91-mmuops-smoke         — MmuOps end-to-end 4 KiB roundtrip smoke
  P1-92-mmuops-2m-smoke      — MmuOps end-to-end 2 MiB roundtrip smoke
  C35-state-eod-session-17   — session-17 docs

Session 18 (PRs #159 – #164):
  C36-readme-ci-badge        — README CI badge + Phase-1 status snapshot
  P1-86a-fault-decode        — per-arch fault vector / PFEC / ESR decoders
  P1-84-task-arch-ctx-buffer — Task carries kernel_stack + arch_ctx buffer
  P1-86b-fault-recover       — recoverable fault path (asm + bool dispatcher)
  B07-debug-irq-feature-chain — chain hal-<arch>/debug-irq via boot crates
  C37-qemu-mcp-server        — interactive QEMU+GDB MCP server

Session 19 (PRs #166 – #170):  ← Phase 1→2 boundary crossed
  P1-93-kernel-owned-gdt     — kernel-owned GDT replaces Limine's
  P1-94-tss-install          — 64-bit TSS + ltr; set_rsp0 exposed
  P1-95-user-mapping         — interior PT entries set U/S=1
  P1-96-user-page-smoke      — runtime user-mapping translate round-trip
  P1-82-userspace-first-iretq — drops to CPL=3, user int3, returns via #BP
```

Active local branches at EOD: `main` (working tree clean). Recent feature branches preserved.

Remote: `origin = git@github.com:watkinslabs/oxide.git`.

## Active discipline (must hold)

- Branch-per-feature + PR-mandatory: `gh pr create` + `gh pr merge --merge --delete-branch=false`.
- Numbered branch scheme: `F/B/D/R/Z/C/P<n>-<NN>` + kebab title.
- AI-density per `08`. Cross-ref form: `<doc>§<sec>`.
- `cargo run -p xtask -- spec-lint` clean before commit (`code/klog-ungated` live).
- `panic = "abort"`, `kassert!` only, no `static mut`, no `dyn HAL`, `// SAFETY:` ≥30 chars.
- File length ≤ 1000 lines hard, 500 soft.
- **R06 (lint-enforced)**: every `klog::*` call site MUST be cfg-gated under a `debug-<sub>` feature.
- **R07 (live)**: kthread `Context` records that may be entered via the IRQ tail MUST be built with `new_kernel_with_irq_frame`, not the bare `new_kernel` (which has no synthetic IRQ frame).
- Force-push to main: explicit user instruction only.
- No `Co-Authored-By:` trailers.

## Resume protocol next session

1. `cd /home/nd/oxide2 && git status` (clean, on `main`).
2. `git log --oneline -5` (HEAD = #137 merge or descendant).
3. Read this file (`state.md`).
4. Read `CLAUDE.md`.
5. Read `docs/MANIFEST.md`.
6. `make lint` (`spec-lint: clean`).
7. `make test` (≥465 passed, 0 failed).
8. `make build` (both arches build clean).
9. Optional sanity: `make qemu-x86` + `make qemu-arm` — should print the preempt-smoke + reach `boot: kernel ready, halting`.

## Suggested next branches

| Option | Branch idea | Why pick this |
|---|---|---|
| **arm SVC entry stub + dispatch** | `P2-11-arm-svc-entry` | Mirror of x86 P2-01/02. Hook VBAR_EL1+0x400 to fork on ESR.EC=0x15 (SVC), AAPCS64-shuffle args (x8=nr, x0..x7=args), call syscall::dispatch, eret with retval in x0. After this both arches have full syscall round-trip. |
| **VMM AddressSpace + real PF handler** | `P2-12-vmm-addrspace-fault` | Per-task AS lifecycle; wire to fault dispatcher; demand-paging. Largest single jump remaining; unblocks real ELF load. |
| **Per-task RSP0 + Task-with-AS** | `P2-13-task-user-as` | Currently single static RSP0 in TSS for the boot task. Real multitasking needs Task to carry its kernel stack + user AS so the IRQ-on-IST stack gets swapped on context switch. |
| **More syscall bindings** | `P2-14-syscalls-batch-2` | sys_brk (heap), sys_mmap (anon mmap via VMM), sys_uname, sys_readlink, sys_clock_gettime — what `printf("hello\n")` from a real ELF needs. |
| **Wire real `RunqueueInner` into ksched** | `P1-84b-sched-runqueue-wire` | Carry-over from session 18. Plumbing-heavy refactor onto `crates/sched::RunqueueInner`; doesn't unblock anything immediately. |

## Open questions for user (deferred)

- README.md CI status badge.
- Atomic cookie CAS in slab (cross-CPU double-free).
- Whether to move `kernel/src/ksched.rs` logic into `crates/sched/` (extending `Task` per `13§5`) before Phase 2, or after the userspace `eret` lands.
- Should production builds be silent on a fault, or should fault printers be unconditionally on (counter to R06 strict reading)? Current state: silent halt unless `--features debug-irq`.
- v1 GDT design: kernel-owned GDT replacing Limine's at boot, or extend Limine GDT with user descriptors via a small bring-up step? Needed before Phase 2.
