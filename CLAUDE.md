# oxide2

Linux-class kernel + minimal userspace, in Rust. Targets `x86_64-unknown-oxide-kernel` and `aarch64-unknown-oxide-kernel`. Userspace targets upstream `*-unknown-linux-musl` per `docs/29a§2`.

## Status

Pre-code. 46 specs in `docs/`, all DRAFT. Spec-lint tool (`tools/spec-lint/`) and Phase 0 build infra are next.

## Discipline (READ BEFORE EDITING)

1. **Spec-before-code** (`docs/02`): subsystem code may not be written while its spec is DRAFT. Charters (`02`,`08`,`09`,`01`,`06`,`07`) gate everything below.
2. **Cool-off**: spec freezes after 48h of no edits + cold re-read. Edits reset the clock.
3. **AI-density** (`docs/08`): docs and code optimized for AI re-reading. Drop articles, prose intros, restated section titles, redundant doc-comments. Keep frozen invariants, ABI tables, test contracts, OQ at full fidelity.
4. **Lean-mode calendar**: phase advance gated on PR-time CI (≤5min + canary 1h + paranoid-ci build). Background soak files tickets, never blocks. Single soak box. v1 = 9–14mo solo. No 24h-soak-gate-per-phase. No second-machine repro for v1.
5. **MANIFEST authoritative** (`docs/MANIFEST.md`): every spec listed; status matches file's status line.

## Cross-references

Form: `<doc>§<sec>` (e.g., `13§4`, `02§1`, `04§1.1`). Every reference must resolve to a section in the cited doc.

When user says `<doc>§<sec>`, **read that section first** before responding.

## Code style hard rules (`docs/07§5`)

- `panic = "abort"` every kernel profile.
- `kassert!(cond, "literal")` only — no `panic!(fmt)`.
- No `static mut` outside `#[cfg(test)]`.
- No `dyn` on HAL traits (CI vtable grep).
- `#![no_std]` every kernel crate; `extern crate std` = build fail.
- `// SAFETY: <text ≥30 chars naming fn or state>` on every `unsafe { }`.
- `# C: <expr>` doc-comment on every `pub fn` in kernel crates.
- `# Lk:`, `# Ctx:`, `# Sleeps:` markers per `09§6` where applicable.
- klog macros only accept `&'static str` format strings (compile-time interned).
- Names short within scope (`pfn`,`pa`,`va`,`sb`,`ino`,`tid`) per `09`.

## Doc style hard rules (`docs/08`)

- Section headers: `## N` (number only) outside charters `00`–`09`.
- One-line bullets unless second sentence carries an invariant.
- Tables > lists > sentences. Schemas > prose definitions.
- Cite by `<doc>§<sec>`; never restate.
- No "This document defines", "Note that", "In this section we will", "It should be noted", "simply", "really", "actually", "very".
- No closing summaries.
- Status line: `DRAFT|FROZEN <date>. Dep:<csv>.` at top.

## Forbidden patterns (CI-enforced when spec-lint exists)

- `static mut` outside test
- `panic!(fmt)` in kernel
- `format!()` results into klog macros
- `dyn HAL` traits in compiled kernel
- doc-comment that restates the function name
- `unsafe { ... }` without `// SAFETY:` ≥30 chars
- Forbidden phrases in docs (per `08§4`)

## Where things live

| Concept | Doc |
|---|---|
| Glossary, types, errno table | `01` |
| Spec lifecycle, freeze gate | `02` |
| Modernity charter (Linux compat surface) | `03` |
| Performance budgets, debug Cargo features, klog | `04` |
| Pre-mortem (named failure modes) | `05` |
| Memory model, locks, RCU, PerCpu | `06` |
| Toolchain pin, target JSONs, build profiles | `07` |
| AI-density rules | `08` |
| Abbreviations | `09` |
| PMM, VMM, slab, sched, ctxsw, syscall ABI | `10`–`15` |
| VFS, block, modules, dev/proc/sysfs | `16`–`19` |
| HAL x86/arm, IRQ, time | `20`–`23` |
| IPC, net, namespaces+cgroup, security, tty | `24`–`28` |
| init+userspace, userspace platform, io_uring | `29`,`29a`,`30` |
| ELF loader, power, firmware, PCI, drivers | `31`–`35` |
| Bootloader handoff, observability, error handling | `36`–`38` |
| Build+image, CI+soak, debug catalog, tests, acceptance | `39`–`43` |
| Boot flow Mermaid | `boot-flow.md` |

When user asks about a concept: check this table → read that spec → answer. Don't guess; read.

## Toolchain (`docs/07`)

- Pinned nightly Rust via `rust-toolchain.toml`.
- `-Zbuild-std=core,compiler_builtins,alloc` for kernel targets.
- `rust-lld` linker both arches.
- Custom JSONs in `targets/` (kernel only; userspace uses upstream `*-unknown-linux-musl`).
- Limine (x86_64) / EDK2 or U-Boot (aarch64) bootloaders.

## CI (`docs/40`)

- PR-time gate: build both arches, hosted unit tests with 10M-op proptests, miri, loom, qemu smoke, canary 1h, bench-vs-history, coverage, clippy, deny, spec-lint.
- Background soak: continuous on `main`, 4h cycles, files tickets on failure.
- v1 release: requires 168h soak artifact each arch.
- Docker images: `Dockerfile.{build,soak}`, digest-pinned base, ghcr.io.
- Runners: GHA hosted (PR), 1 self-hosted box (soak).

## Don't (common future-session mistakes)

- Don't write subsystem code while its spec is DRAFT. The work is spec-discipline now.
- Don't add a `dyn` to a HAL trait "just here." Always generic + monomorphized.
- Don't use `panic!("fmt {}", x)` — only `kassert!(cond, "literal")`.
- Don't restate spec content in CLAUDE.md or in code comments. Cite `<doc>§<sec>`.
- Don't add MCP servers without asking. Project intentionally minimal.
- Don't move docs to `docs/v1/`. Versioning is git tags, not directories.
- Don't introduce a 24h soak gate. Background only; PR-time + canary 1h is the wall.
- Don't second-machine-reproduce for v1 exit. Single signed soak artifact.

## Git workflow (mandatory)

**Branch per change.** Never commit directly to `main`. Branch names:

| Prefix | Use |
|---|---|
| `feature/<name>` | new functionality |
| `fix/<name>` | bug fix |
| `doc/<name>` | spec edits only (no code) |
| `revise/<spec>` | revision block on FROZEN spec |
| `freeze/<spec>` | freeze a DRAFT spec |
| `chore/<name>` | tooling, deps, CI plumbing |
| `phase-<n>/<name>` | work on phase N (e.g., `phase-1/pmm-buddy`) |

**Commits.** Small, focused, one logical change per commit. Conventional message form:

```
<type>: <subject>

<body — why, not what>
```

`<type>` ∈ `feat|fix|doc|spec|refactor|test|bench|chore|ci|build|revise|freeze`.

Examples:
- `spec: tighten 02 cool-off rule to text-only`
- `feat(pmm): bitmap-truth merge path`
- `freeze: 02 spec-discipline charter`
- `revise: 03 modernity — drop FAT16/12`

**PRs.** Every branch merges to `main` via PR. PR-time CI per `docs/40§2` is the gate. PR cannot merge if any check fails.

**Never:**
- `git push --force` to `main`. Period.
- `git push --force-with-lease` to anyone else's branch.
- `git rebase main` on a branch others might be reviewing.
- `git commit --amend` on a pushed commit (start a new commit).
- Skip hooks (`--no-verify`).
- Skip signing (`--no-gpg-sign`) if signing is configured.
- Direct commits to `main` outside an explicit emergency-fix-then-PR cycle.

**Tags.**
- `v1.0`, `v1.1`, `v2.0` — release tags. Require soak artifact per `40§4`.
- `v0.<n>-phase-<m>` — internal milestone tags between releases.
- Tags signed (`git tag -s`) once we have a key.

**Reverting.** Always `git revert <sha>` to undo merged work. Never delete history on `main`.

**Local Cleanup.** `git branch -d <branch>` only after PR merged. Never `-D` on a branch with unique work that hasn't been merged.

## When in doubt

- Read `docs/MANIFEST.md` first.
- Then read the spec your work touches.
- Then ask the user before deviating.

## Communication

- User prefers terse. Skip preamble.
- User wants honest opinion before action when stakes are non-trivial. "Advise then act" not "ask then act."
- When proposing changes that affect multiple specs, list the touched specs first, action second.
- When something is uncertain, say so. Don't smooth-talk.
