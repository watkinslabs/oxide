# State 2026-05-02

Resumable checkpoint. Update at session exit. Next session reads this first along with `CLAUDE.md` and `docs/MANIFEST.md`.

## Phase

**Spec corpus FROZEN. Build infra + skeleton crates landed. Boot wiring + real implementations pending.** All 44 spec docs are FROZEN as of 2026-05-02 (cool-off waiver per `02§1.4`); only `00 master plan` and `05 pre-mortem` stay DRAFT permanently as living docs. Workspace compiles for host + both kernel targets.

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

- `tools/spec-lint/`: `docs|code|manifest|xref|all`. Doc rules (status-line, header form, forbidden phrases), MANIFEST presence/status mismatch, xref resolver (every `<doc>§<sec>` resolves), code rules (`#![no_std]`, no `extern crate std`, no `static mut` outside test, no `panic!(fmt)`, `// SAFETY:` ≥30 chars, `# C:` on every `pub fn`). **`spec-lint all` clean across the corpus + every crate.**
- `tools/xtask/`: `kernel|user|image|test|qemu|soak|bench|spec-lint|doc-check`. Real impls: `spec-lint`, `doc-check`, `kernel` build (-Z build-std + target JSON + softfloat ABIs), `test --hosted`. Stubs return `64 ENOSYS`-style for the rest.
- `Cargo.toml` (workspace) + `rust-toolchain.toml` (`nightly-2026-05-01`) + workspace profiles per `07§2`.

### Kernel + per-subsystem crates

| Path | Role | Status |
|---|---|---|
| `kernel/` | lib; `kernel_main(&BootInfo)` entry; emits "init started" via klog; halt loop | builds host + both kernel targets |
| `crates/hal/` | trait-only: `MmuOps`, `CpuOps`, `Context`, `IrqOps`, `TimerOps` per `14`/`20`/`21` | builds; 2 hosted tests |
| `crates/klog/` | macros emit into `.klog_strings`; `Uart` trait; 5 levels | builds; 3 hosted tests |
| `crates/{pmm,slab,vmm,sched,syscall,vfs,block,modules,procfs,ipc,security,nscg,net,tty,iouring,elf,power,firmware,pci,drv,obs,err}/` | one no_std crate per frozen spec; `Error`/`KResult`/`init() -> NotImplemented` stub; 1 hosted test each | all build; 22 tests pass |
| `targets/{x86_64,aarch64}-unknown-oxide-kernel.json` | rustc target specs (R02-fixed for current rustc) | both produce `libkernel.rlib` |
| `link/{x86_64,aarch64}-kernel.ld` | linker scripts per `07§6`; sections `.text.boot/.text/.rodata/.data/.bss/.percpu/.klog_strings/.init_array` | not yet exercised (no boot binary) |

### Discipline + workflow

- **PR-mandatory** (CLAUDE.md§Git workflow updated): every branch goes through `gh pr create` + `gh pr merge --merge --delete-branch=false`. 36 PRs landed this session.
- **Numbered branch scheme** (CLAUDE.md updated): `F<NN>/B<NN>/D<NN>/R<NN>/Z<NN>/C<NN>/P<n>-<NN>`. All pre-existing branches renamed; main history rewritten so merge subjects use new names.
- **Auto-allow lists** updated in `.claude/settings.json`: `gh pr/issue/run/workflow/api*`, `git push:*` no longer prompt.
- All commits authored as `Ablative Personality <chris@watkinslabs.com>`. No co-authors. No AI attribution.

## Repo state

```
main (origin/main): fb440f5 Merge pull request #36 from watkinslabs/P1-01-subsystem-skeletons

36 PRs landed. Branches preserved (no deletions).

Branch list (sortable):
  B01-branch-retention-rule
  B02-fix-broken-xref-01-freeze
  B03-fix-30-status-line
  B04-fix-07-revision-forbidden-phrases
  C01-workspace-setup
  C02-state-checkpoint
  C03-strip-coauthor
  C04-state-update-after-coauthor-strip
  C05-spec-lint
  C06-branch-naming-and-pr-workflow
  C07-state-md-after-rename
  C08-allow-gh-pr-and-push
  C09-spec-lint-xref
  C10-state-md-session-progress
  C11-state-md-after-freeze-chain
  D01-initial-spec-corpus
  D02-status-line-sweep
  P0-01-target-jsons
  P0-02-linker-scripts
  P0-03-xtask-skeleton
  P0-04-hal-traits
  P0-05-klog-skeleton
  P0-06-kernel-binary
  P1-01-subsystem-skeletons
  R01-spec-discipline-dep-cycles
  R02-target-spec-c-int-width
  Z01-spec-discipline ... Z18-meta-and-acceptance (9 freezes)
```

Remote: `origin = git@github.com:watkinslabs/oxide.git`.

## What's NOT done (pending tasks)

In rough order:

1. **Boot crates** `crates/boot-x86_64`, `crates/boot-aarch64`. Provide arch-specific `_start` (asm, naked fn, link section `.text.boot`), parse bootloader handoff (Limine on x86; EDK2/U-Boot/DTB on arm), set up minimal env (paging, percpu base, kernel stack), then tail-call `kernel::kernel_main`. **Significant per-arch asm + bootloader integration; expect days each.**

2. **Real UART backends** for `klog::Uart`. 16550A on x86 (port I/O via `inb`/`outb` asm); PL011 on aarch64 (MMIO at QEMU `virt` 0x09000000). Wire via boot crate before calling `kernel_main`.

3. **HAL impls**: `hal-x86_64`, `hal-aarch64` crates implementing `MmuOps`/`CpuOps`/`Context`/`IrqOps`/`TimerOps`. Significant asm (ctx-switch in `14§5`/`14§6`, IRQ entry, MSR/sys-reg reads/writes).

4. **Subsystem implementations** in dependency order per `boot-flow.md`:
   - `pmm` (10): buddy + bitmap truth.
   - `slab` (12): magazines + caches.
   - `vmm` (11): VMA tree + page-fault handler + COW.
   - `sched` (13): 3-class + cgroup quota.
   - `syscall` (15): dispatch table + ABI shapes.
   - `vfs` (16) → `block` (17) → `procfs` (19) → `ipc` (24) → `security` (27) → `nscg` (26) → `net` (25) → `tty` (28) → `iouring` (30) → `elf` (31) → `pci` (34) → `drv` (35) → `firmware` (33) → `power` (32) → `obs` (37) → `modules` (18) → `err` (38) → `init` (29).
   - Each spec carries the test contract; meet it before considering the crate done.

5. **Userspace platform** per `29a`: musl 1.2.5 fork (`ld-oxide.so.1`), init, busybox-equivalent, demo dynamically-linked binary.

6. **Phase 0 finishing pieces**:
   - `tools/docker/Dockerfile.{build,soak}` per `40§5`.
   - `.github/workflows/{pr,bg-soak,release,dockerfile,weekly}.yml` per `40§2`. PR-time gate runs `xtask spec-lint` + `cargo test --workspace` + `xtask kernel --arch x86_64` + same for aarch64.
   - `xtask qemu` real impl: spawn QEMU with built kernel + initramfs; expect `"init started"` + clean exit.
   - **Phase 0 exit gate**: hello-world boots both arches via QEMU, prints "init started" on UART, exits cleanly. Mostly gated on items 1+2.

7. **Bench history + soak runner** per `40`.

8. **`LICENSE` file** (MIT chosen).

## Active discipline (must hold)

- Spec-before-code: subsystem code only after that spec freezes. (All subsystem specs FROZEN now; cleared.)
- Branch-per-feature + PR-mandatory: `gh pr create` + `gh pr merge --merge --delete-branch=false`. **No local `--no-ff` merges to main.**
- Numbered branch scheme: `F/B/D/R/Z/C/P<n>-<NN>` + kebab title.
- Cool-off: ≥48h default; solo waiver per `02§1.4` is in active use.
- AI-density: dense form for new content; existing slack trims on next revision touching it.
- Lean-mode CI: PR-time = wall; soak = bg diagnostic; no 24h gate.
- Cross-ref form: `<doc>§<sec>`. `spec-lint xref` enforces; **always run `cargo run -p spec-lint -- all` before commit and abort on findings.** (Two near-misses this session — B02 + B03 + B04 fix-up PRs.)
- `panic = "abort"`, `kassert!` only, no `static mut`, no `dyn HAL`, `// SAFETY:` ≥30 chars.
- Force-push to main: explicit user instruction only.

## Resume protocol next session

1. Read `state.md` (this file).
2. Read `CLAUDE.md`.
3. Read `docs/MANIFEST.md`.
4. Check `git log --oneline --graph -10` and `git status`.
5. Run `cargo run -p spec-lint -- all` — should be clean.
6. Run `cargo test --workspace` — should pass (~25 tests).
7. Run `cargo run -p xtask -- kernel --arch x86_64 --profile dev` — should produce `libkernel.rlib`.
8. Pick the next pending task. Highest-value next step is either:
   - **Boot crate skeletons (P0-07/P0-08)** to get to QEMU-bootable hello-world, or
   - **`pmm` first real subsystem** (P1-02) — concrete implementation work, dep chain root, exercises spec-lint code rules in anger.

## Open questions for user (deferred)

- LICENSE = MIT (decided 2026-05-02). `LICENSE` file pending.
- CI status badge in README.md once GHA is up.
- Whether to ship the live-state of `target/` artifacts in git (currently ignored; bench/soak intentionally tracked).
