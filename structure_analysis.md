# Structure Analysis: Repo Layout, Crate Boundaries, and Naming

Date: 2026-05-10

## Direct answers to your core questions

1. Keep most implementation logic in crates, not in `kernel/src`.
2. Do not move everything into one giant `kernel` crate.
3. Yes, `kernel` should absolutely be a crate, but it should be a thin integration/orchestration crate.
4. Your read on "glue" is correct: many `syscall_glue_*` files currently contain real implementation, so the name is misleading.

## What the repo looks like right now

- Workspace members: 55.
- `kernel/src`: 119 Rust files, 34,089 LOC.
- Largest non-kernel crates are much smaller (for example `hal-x86_64` 4,085 LOC, `net` 3,906 LOC, `vmm` 3,661 LOC).
- `kernel/src` has:
  - 30 files named `syscall_glue*`
  - 19 files named `dev_*`
  - large subsystem files (`syscall_glue_proc.rs` 1000 LOC, `syscall_glue.rs` 999 LOC, `procfs.rs` 999 LOC, `user_as.rs` 994 LOC)

## Main structural problems

1. Boundary inversion
- Many subsystem crates exist (`procfs`, `tty`, `iouring`, etc.), but major behavior still lives in `kernel/src`.
- This creates duplicate "homes" for the same domain.

2. Misleading naming
- `syscall_glue_*` sounds like adapter/wiring code, but contains real syscall semantics and policy.
- `dev_*` mixes device models, VFS integration, and syscall behavior in kernel-local files.

3. Flat crate namespace sprawl
- Top-level `crates/*` mixes kernel subsystems, arch boot pieces, tooling-ish primitives, and planned userspace libs.
- Short names like `dl`, `svc`, `pkg`, `nscg`, `obs` are hard to scan and classify.

4. Integration crate is too heavy
- `kernel` is acting as orchestrator + implementation dumping ground.
- This reduces testability and makes architecture decisions ambiguous.

## Recommended professional target model

Use a strict layering model:

1. `kernel` crate
- Responsibility: boot sequencing, top-level init order, feature wiring, and final syscall dispatch table registration.
- Target size: small relative to subsystem crates; no large domain logic.

2. Domain crates (real implementation)
- Responsibility: all subsystem behavior.
- Examples: mm, sched, vfs, net, procfs, tty, ipc, security, drivers.

3. Arch crates
- Responsibility: architecture-specific hardware/runtime code only.
- Examples: `hal-x86_64`, `hal-aarch64`, boot crates, arch interrupt/timer glue.

4. Tools and userspace kept separate by directory
- Keep build/test tooling under `tools/`.
- Keep userspace/runtime libraries grouped separately from kernel internals.

## Proposed filesystem layout (pragmatic, cargo-friendly)

```text
oxide2/
  kernel/                       # thin integration crate only
  crates/
    kernel/
      mm-pmm/
      mm-vmm/
      sched/
      syscall/
      vfs/
      procfs/
      tty/
      net/
      ipc/
      security/
      modules/
    drivers/
      core/
      virtio/
      virtio-gpu/
      virtio-input/
      drm/
      fbdev/
      fbcon/
      vt/
    arch/
      hal/
      hal-x86_64/
      hal-aarch64/
      boot-x86_64/
      boot-aarch64/
      kernel-bin-x86_64/
      kernel-bin-aarch64/
    shared/
      sync/
      klog/
      err/
      crc/
      elf/
      cpio/
      inflate/
    user/
      dl/
      nss/
      pam/
      pkg/
      rpm/
      svc/
  userspace/
  tools/
  docs/
  tests/
```

## Naming convention recommendation

1. Path-based grouping first, crate rename second
- Move paths into domain folders first.
- Keep package names temporarily to avoid breaking everything at once.

2. Replace ambiguous names over time
- `syscall_glue_*` -> `syscalls/*` (or `syscall_handlers/*`) based on domain.
- `dev_*` -> move into owning subsystem crate with explicit module names.
- Ambiguous crate names (`dl`, `svc`, `pkg`, `obs`, `nscg`) should get expanded names eventually.

3. Define "glue" precisely
- "Glue" should mean tiny adapters only: argument conversion, trait bridging, registration calls.
- Rule of thumb: if a file owns policy, state transitions, or complex error semantics, it is not glue.

## Concrete migration plan

Phase 1: naming and ownership map
- Create a `STRUCTURE_OWNERSHIP.md` table mapping each `kernel/src/*.rs` file to an owning crate.
- Rename `syscall_glue_*` directory/module names in place to reduce confusion immediately.

Phase 2: move real implementations out of `kernel`
- Extract syscall handlers into `crates/kernel/syscall` by domain (`fs.rs`, `net.rs`, `proc.rs`, `signal.rs`, etc.).
- Extract procfs/tty/io_uring implementations into their existing crates so kernel calls crate APIs only.

Phase 3: trim kernel to orchestration
- Keep only boot entry, init sequencing, registration, and cross-crate wiring in `kernel`.
- Remove duplicated domain logic from `kernel/src`.

Phase 4: enforce with CI
- Add lint/check: fail if new `kernel/src/syscall_glue_*` files exceed a small LOC threshold or contain domain state machines.
- Add architecture doc showing allowed dependency directions.

## Bottom line

Your instinct is correct: the current layout is functionally working but structurally inconsistent.  
The professional direction is not "everything in kernel" and not "crates for show."  
It is: `kernel` as a thin integration crate, with real subsystem logic living in well-owned domain crates and consistently named paths.
