# oxide2

Linux-class kernel + minimal userspace, in Rust. Targets `x86_64-unknown-oxide-kernel` and `aarch64-unknown-oxide-kernel`. Userspace targets upstream `*-unknown-linux-musl` per `docs/29a§2`.

## Status

Pre-code. 46 specs in `docs/`, all DRAFT. Spec-lint tool (`tools/spec-lint/`) and Phase 0 build infra are next.

## Discipline (READ BEFORE EDITING)

1. **Spec-before-code** (`docs/02`): subsystem code may not be written while its spec is DRAFT. Charters (`02`,`08`,`09`,`01`,`06`,`07`) gate everything below.
2. **Cool-off**: spec freezes after 48h of no edits + cold re-read. Edits reset the clock.
3. **AI-density** (`docs/08`): docs and code optimized for AI re-reading. Drop articles, prose intros, restated section titles, redundant doc-comments. Keep frozen invariants, ABI tables, test contracts, OQ at full fidelity.
4. **Lean-mode calendar**: phase advance gated on PR-time CI (≤5min + paranoid-ci build) + QEMU smoke for the affected subsystem. v1 = 9–14mo solo.
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

## File length cap (`docs/08§7`)

- Hard cap: **1000 lines** per `.rs` or `.md` file. CI fail above. Applies to `crates/**`, `kernel/**`, `tools/**`, `docs/**` (excluding `docs/v2/`).
- Soft target: **500 lines**. Above 500 → consider splitting at next touch.
- Split big files into submodules: Rust `mod foo; foo/{a.rs,b.rs}`; markdown into sister docs cross-referenced via `<doc>§<sec>`.
- Tests count toward the cap — split `tests.rs` into `tests/<feature>.rs` once it grows.

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
| Build+image, CI, debug catalog, tests, acceptance | `39`–`43` |
| Boot flow Mermaid | `boot-flow.md` |

When user asks about a concept: check this table → read that spec → answer. Don't guess; read.

## Toolchain (`docs/07`)

- Pinned nightly Rust via `rust-toolchain.toml`.
- `-Zbuild-std=core,compiler_builtins,alloc` for kernel targets.
- `rust-lld` linker both arches.
- Custom JSONs in `targets/` (kernel only; userspace uses upstream `*-unknown-linux-musl`).
- Limine (x86_64) / EDK2 or U-Boot (aarch64) bootloaders.

## CI (`docs/40`)

- PR-time gate: build both arches, hosted unit tests with 10M-op proptests, miri, loom, qemu smoke, bench-vs-history, coverage, clippy, deny, spec-lint.
- Docker images: `Dockerfile.build`, digest-pinned base, ghcr.io.
- Runners: GHA hosted (PR).
- Local QEMU: use the qemu MCP (`mcp__qemu__qemu_start`, `qemu_serial`, `qemu_break`, `qemu_step`, `qemu_regs`, `qemu_mem`, `qemu_backtrace`) to boot + step + inspect during development. Don't claim "needs human-driven QEMU iteration" — drive it directly.

## Don't (common future-session mistakes)

- Don't write subsystem code while its spec is DRAFT. The work is spec-discipline now.
- Don't add a `dyn` to a HAL trait "just here." Always generic + monomorphized.
- Don't use `panic!("fmt {}", x)` — only `kassert!(cond, "literal")`.
- Don't restate spec content in CLAUDE.md or in code comments. Cite `<doc>§<sec>`.
- Don't add MCP servers without asking. Project intentionally minimal.
- Don't move docs to `docs/v1/`. Versioning is git tags, not directories.
- Don't claim work needs human-in-the-loop QEMU testing. Use the qemu MCP directly.

## Git workflow (mandatory)

**Branch per change.** Never commit directly to `main`. Branch names use a single-letter type + zero-padded counter + kebab-case title, sortable globally and within type:

| Prefix | Use | Example |
|---|---|---|
| `F<NN>-<title>` | new functionality | `F01-pmm-buddy` |
| `B<NN>-<title>` | bug fix | `B01-branch-retention-rule` |
| `D<NN>-<title>` | spec edits only (no code) | `D02-status-line-sweep` |
| `R<NN>-<title>` | revision block on FROZEN spec | `R01-modernity-drop-fat` |
| `Z<NN>-<title>` | freeze a DRAFT spec | `Z01-spec-discipline` |
| `C<NN>-<title>` | tooling, deps, CI plumbing | `C04-spec-lint` |
| `P<n>-<NN>-<title>` | phase-N work | `P1-01-pmm-buddy` |

Counter is per-type, monotonically increasing, never reused. Two-digit minimum (`NN`); widen to three (`NNN`) once any single type passes 99. Title is kebab-case, ≤40 chars, no trailing slashes. Old `feature/`, `fix/`, etc. branches predate this scheme and are kept as-is for history.

**Phase prefix MUST match `00§3` master-plan phase.** `P<n>-` means phase-`n` per the master-plan §3 table (0=build infra, 1=PMM, 2=VMM+MMU, 3=slab, 4=sched+ctxsw+preempt+SMP, 5=syscalls+ELF+init+busybox-sh, 6=VFS+ext4 RO, 7a=block+pagecache, 7b=ext4 RW, 8=net, 9=hardening, 10=modules loader, 11=PCI enumeration, 12=virtio common, 13=dynamic linker, 14=libc/NSS/PAM, 15=system manager, 16=RPM toolchain, 17=tty + login). Rotate the prefix when crossing a phase boundary; do **not** keep using the old phase number as a generic counter. Counter resets to `01` per phase. Example: when phase 4 work begins, branches restart at `P4-01-...`, regardless of how high the `P3-` counter went.

**Phases are sequential (`00§3`, `00§14` rule 3): no parallel-across-gate.** Don't start phase-`n+1` work while phase-`n` exit gates aren't met. Phase exit = PR-time CI green + canary 1h + bench within budget + coverage met + the per-spec §Test-contract gate. Out-of-phase work belongs in `docs/v2/` per `00§14` rule 5. Auditing "what phase are we actually in" before starting a branch is mandatory; pick the lowest unfinished phase.

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

**Push policy.** Auto-push merged commits to `origin/main` after each merge without asking. Auto-push feature branches with `-u` on first push without asking. Force-push remains forbidden per the Never list below.

**PRs (mandatory).** Every branch merges to `main` via `gh pr create` then `gh pr merge --merge --delete-branch=false`. No local `--no-ff` merges to `main`. PR-time CI per `docs/40§2` is the gate; until CI exists, manual review then merge. Branch retention rule still applies: `--delete-branch=false`.

**Never (without explicit user confirmation):**
- `git push --force` / `--force-with-lease` to `main`. Permitted only on explicit user instruction (e.g., history rewrite for branch-rename or trailer-strip). Default = forbidden.
- `git push --force-with-lease` to anyone else's branch.
- `git rebase main` on a branch under review by others.
- `git commit --amend` on a pushed commit (start a new commit).
- Skip hooks (`--no-verify`).
- Skip signing (`--no-gpg-sign`) if signing is configured.
- Direct commits to `main` outside an explicit emergency-fix-then-PR cycle.
- **Add `Co-Authored-By:` trailer of any kind to any commit, ever.** Author is the human committer; period. No `Co-Authored-By: Claude`, no `Co-Authored-By: <model>`, no AI attribution trailers. CI lint rejects commits with `Co-Authored-By:` lines.

**Tags.**
- `v1.0`, `v1.1`, `v2.0` — release tags.
- `v0.<n>-phase-<m>` — internal milestone tags between releases.
- Tags signed (`git tag -s`) once we have a key.

**Reverting.** Always `git revert <sha>` to undo merged work. Never delete history on `main`.

**Branch retention.** Do NOT delete merged branches. Keep feature branches around even after merge for recoverable history. `git branch -d`/`-D` only when user explicitly says delete. Default = preserve.

## When in doubt

- Read `docs/MANIFEST.md` first.
- Then read the spec your work touches.
- Then ask the user before deviating.

## Communication

- User prefers terse. Skip preamble.
- User wants honest opinion before action when stakes are non-trivial. "Advise then act" not "ask then act."
- When proposing changes that affect multiple specs, list the touched specs first, action second.
- When something is uncertain, say so. Don't smooth-talk.

## Autonomous-run discipline (HARD RULE)

When the user kicks off an autonomous run (variants of "continue / keep going / work through everything / don't stop"), the contract is:

1. **Do not stop until the project is done.** "Phase X closed" is not a stopping point. The next phase is. The phase after that is. Until the master plan in `00§3` is exhausted *or* a hard blocker (compile fail you can't resolve, missing external resource, destructive op needing confirmation) appears, keep shipping PRs.
2. **Do not announce intermediate stopping points.** No "natural seam reached", no "this is a clean place to pause", no "future-you has the handoff". These announcements cost the user hours of wall-clock when they assume work is continuing in the background. Just start the next phase.
3. **No EOD-style summaries between phases.** State.md + CHANGELOG updates are checkpoint commits, not user-facing speeches. Update the docs, push the PR, start the next branch — silently.
4. **Phase 8 (net) being long is not an excuse.** 10–15 weeks of spec budget translates to many small PRs in autonomous mode. Land them one at a time. Same for phase 9 hardening.
5. **If you find yourself writing "I've delivered enormously this session" or "this is a natural stopping point" — STOP that sentence and start the next branch instead.**
6. The only things that justify stopping mid-run: (a) explicit user instruction, (b) genuine blocker, (c) tests/build red and root cause not identified within ~3 attempts. Otherwise, keep going.
