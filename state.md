# State 2026-05-02 (reconciled)

Resumable checkpoint. Update at session exit. Next session reads this first along with `CLAUDE.md` and `docs/MANIFEST.md`.

## Phase

**Spec corpus FROZEN. Build infra + skeleton crates landed. Boot crate _shells_ landed (no asm yet). pmm public API surface landed (no bodies). GHA + Docker + LICENSE landed.** Workspace compiles for host + both kernel targets; spec-lint clean; 33 hosted tests pass.

## What's done

### Spec corpus (44 / 46 FROZEN)

- 9 charters: `02`, `08`, `09`, `01`, `06`, `07`, `04`, `03`, `38`.
- 5 leaves co-frozen: `14`, `22`, `23`, `33`, `36`.
- 2 HAL co-frozen: `20`, `21`.
- 5 mid co-frozen: `10`, `12`, `11`, `13`, `15`.
- 4 upper-FS co-frozen: `16`, `17`, `18`, `19`.
- 5 upper-comm co-frozen: `24`, `27`, `26`, `25`, `28`.
- 6 upper-misc co-frozen: `30`, `31`, `32`, `34`, `35`, `37`.
- 2 init/userspace co-frozen: `29`, `29a`.
- 2 build/CI co-frozen: `39`, `40`.
- 4 meta co-frozen: `41`, `42`, `43`, `boot-flow`.
- DRAFT-living: `00`, `05` (per MANIFEST§"Freeze order").

Every spec's OQ section was either resolved inline or moved to `docs/v2/<file>.md` per `02§9.8`. 44 files in `docs/v2/`.

### Tooling

- `tools/spec-lint/`: `docs|code|manifest|xref|all`. **`spec-lint all` clean.**
- `tools/xtask/`: `kernel|user|image|test|qemu|soak|bench|spec-lint|doc-check`. Real impls: `spec-lint`, `doc-check`, `kernel` build (-Z build-std + target JSON), `test --hosted`. Stubs return `64 ENOSYS`-style for the rest.
- `Cargo.toml` (workspace) + `rust-toolchain.toml` (`nightly-2026-05-01`) + workspace profiles per `07§2`.
- `.github/workflows/pr.yml` — spec-lint + workspace tests + matrix kernel build (PR #39).
- `tools/docker/Dockerfile.{build,soak}` — digest-pinned per `40§5` (PR #39).
- `LICENSE` (MIT) — PR #40.

### Kernel + per-subsystem crates

| Path | Role | Status |
|---|---|---|
| `kernel/` | lib; `kernel_main(&BootInfo)` entry; emits "init started" via klog; halt loop | builds host + both kernel targets |
| `crates/hal/` | trait-only: `MmuOps`, `CpuOps`, `Context`, `IrqOps`, `TimerOps` per `14`/`20`/`21` | builds; hosted tests |
| `crates/klog/` | macros emit into `.klog_strings`; `Uart` trait; 5 levels | builds; hosted tests |
| `crates/boot-x86_64/` | `_start` shell, `UnsafeCell` BSS stack, stub `BootInfo` (PR #38) | **shell only — no asm, no Limine handoff** |
| `crates/boot-aarch64/` | `_start` shell, `UnsafeCell` BSS stack, stub `BootInfo` (PR #38) | **shell only — no asm, no EDK2/U-Boot/DTB handoff** |
| `crates/pmm/` | full `10§4` public API (175 lines): `Pmm`, `Order`, `Error`/`KResult`, `UsableRegion`, invariants I1–I8 documented (PR #41) | **API surface only — bodies pending** |
| `crates/{slab,vmm,sched,syscall,vfs,block,modules,procfs,ipc,security,nscg,net,tty,iouring,elf,power,firmware,pci,drv,obs,err}/` | one no_std crate per frozen spec; `Error`/`KResult`/`init() -> NotImplemented` stub + 1 hosted test each | all build |
| `targets/{x86_64,aarch64}-unknown-oxide-kernel.json` | rustc target specs (R02-fixed) | both produce `libkernel.rlib` |
| `link/{x86_64,aarch64}-kernel.ld` | linker scripts per `07§6` | not yet exercised (no boot binary) |

Workspace test count: **33 passed, 0 failed**.

### Discipline + workflow

- **PR-mandatory** (CLAUDE.md§Git workflow): every branch via `gh pr create` + `gh pr merge --merge --delete-branch=false`. **41 PRs landed.**
- **Numbered branch scheme** (CLAUDE.md): `F<NN>/B<NN>/D<NN>/R<NN>/Z<NN>/C<NN>/P<n>-<NN>`. All pre-existing branches renamed; main history rewritten so merge subjects use new names.
- **Auto-allow lists** in `.claude/settings.json`: `gh pr/issue/run/workflow/api*`, `git push:*`.
- All commits authored as `Ablative Personality <chris@watkinslabs.com>`. No co-authors. No AI attribution.

## Repo state

```
main (origin/main): 0e6a906 Merge pull request #41 from watkinslabs/P1-02-pmm-api-surface

41 PRs landed. 101 branches preserved (no deletions).

Most recent merges:
  #41 P1-02-pmm-api-surface       — pmm public API per 10§4
  #40 D03-license-mit             — MIT LICENSE
  #39 P0-09-gha-and-dockerfile    — pr.yml + Dockerfile.{build,soak}
  #38 P0-07-boot-x86_64           — boot-x86_64 + boot-aarch64 skeletons
  #37 C12-state-md-eod-session    — (this file's prior checkpoint — now stale)
  #36 P1-01-subsystem-skeletons   — 22 subsystem crates
```

Remote: `origin = git@github.com:watkinslabs/oxide.git`.

## What's NOT done (pending tasks)

In rough order:

1. **Boot crates — real bodies.** Shells exist (`crates/boot-{x86_64,aarch64}`); need:
   - x86_64: `_start` asm (naked fn, `.text.boot`), Limine protocol parse, paging + GDT/IDT setup, percpu base, kernel stack switch, tail-call to `kernel::kernel_main`.
   - aarch64: `_start` asm, EDK2 or U-Boot + DTB handoff parse, MMU + EL1 setup, kernel stack, tail-call.
   - **Days each. Significant per-arch asm.**

2. **Real UART backends** for `klog::Uart`. 16550A on x86 (port I/O); PL011 on aarch64 (MMIO at QEMU `virt` 0x09000000). Wired via boot crate before `kernel_main`.

3. **HAL impls**: `hal-x86_64`, `hal-aarch64` crates implementing `MmuOps`/`CpuOps`/`Context`/`IrqOps`/`TimerOps`. Significant asm (ctx-switch `14§5`/`14§6`, IRQ entry, MSR/sys-reg).

4. **pmm bodies**: API surface in place; need buddy + bitmap-truth bodies meeting invariants I1–I8 + `10` test contract. **Highest-leverage first subsystem (dep root).**

5. **Subsystem implementations** in dependency order per `boot-flow.md`:
   - `slab` (12), `vmm` (11), `sched` (13), `syscall` (15).
   - `vfs` (16) → `block` (17) → `procfs` (19) → `ipc` (24) → `security` (27) → `nscg` (26) → `net` (25) → `tty` (28) → `iouring` (30) → `elf` (31) → `pci` (34) → `drv` (35) → `firmware` (33) → `power` (32) → `obs` (37) → `modules` (18) → `err` (38) → `init` (29).
   - Each spec's test contract is the bar.

6. **Userspace platform** per `29a`: musl 1.2.5 fork (`ld-oxide.so.1`), init, busybox-equivalent, demo dynamically-linked binary.

7. **Phase 0 finishing pieces**:
   - `xtask qemu` real impl: spawn QEMU with built kernel + initramfs; expect `"init started"` on UART + clean exit.
   - `.github/workflows/{bg-soak,release,dockerfile,weekly}.yml` per `40§2` (only `pr.yml` exists today).
   - **Phase 0 exit gate**: hello-world boots both arches via QEMU, prints "init started", exits cleanly. Gated on items 1+2.

8. **Bench history + soak runner** per `40`.

## Active discipline (must hold)

- Spec-before-code: cleared (all subsystem specs FROZEN).
- Branch-per-feature + PR-mandatory: `gh pr create` + `gh pr merge --merge --delete-branch=false`. **No local `--no-ff` merges to main.**
- Numbered branch scheme: `F/B/D/R/Z/C/P<n>-<NN>` + kebab title.
- Cool-off: ≥48h default; solo waiver per `02§1.4` is in active use.
- AI-density: dense form for new content; existing slack trims on next revision touching it.
- Lean-mode CI: PR-time = wall; soak = bg diagnostic; no 24h gate.
- Cross-ref form: `<doc>§<sec>`. **Always `cargo run -p spec-lint -- all` before commit; abort on findings.**
- `panic = "abort"`, `kassert!` only, no `static mut`, no `dyn HAL`, `// SAFETY:` ≥30 chars.
- Force-push to main: explicit user instruction only.

## Resume protocol next session

1. Read `state.md` (this file).
2. Read `CLAUDE.md`.
3. Read `docs/MANIFEST.md`.
4. Check `git log --oneline --graph -10` and `git status`.
5. `cargo run -p spec-lint -- all` — should be clean.
6. `cargo test --workspace` — should pass (33 tests).
7. `cargo run -p xtask -- kernel --arch x86_64 --profile dev` — should produce `libkernel.rlib`.
8. Pick next pending task. Two highest-leverage options:
   - **pmm bodies (P1-02 continuation)** — buddy + bitmap-truth, exercises spec-lint code rules in anger, dep root for everything above.
   - **Boot crate asm (P0-07/P0-08 real bodies)** — chases Phase 0 exit gate (QEMU hello-world).

## Open questions for user (deferred)

- CI status badge in README.md once GHA is fully exercised.
- Whether to ship `target/` artifacts in git (currently ignored; bench/soak intentionally tracked).
- LICENSE: MIT decided + landed 2026-05-02.
