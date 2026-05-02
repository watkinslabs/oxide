# State 2026-05-02

Resumable checkpoint. Update at session exit. Next session reads this first along with `CLAUDE.md` and `docs/MANIFEST.md`.

## Phase

**Pre-code.** Spec corpus complete. Workspace + Claude config in place. Pushed to origin.

## What's done

- `docs/` — 46 specs all DRAFT, lean-mode applied, cross-refs audited (117 refs all resolve), MANIFEST current.
- `CLAUDE.md` — project rules (discipline, code style, doc style, git workflow, forbidden patterns, where-things-live).
- `.gitignore` — Rust/QEMU/IDE noise; `bench-history`/`soak-artifacts` intentionally tracked.
- `README.md` — entry points.
- `.claude/settings.json` — Bash allowlist (cargo/qemu/git read+commit+merge/gh read-only/file ops/image tools), deny (force-push, rm -rf $HOME, sudo, network curl/wget), ask (push/pr-create/docker-push/cargo-install).
- Memory: `~/.claude/projects/-home-nd-oxide2/memory/` — 9 entries (project, spec corpus index, lean-mode, AI-density, advise-then-act, no-ceremony, git workflow, toolchain, CI strategy, repo remote).
- Git: 4 commits on `main`; 3 feature branches preserved; pushed to `watkinslabs/oxide`.

## Repo state

```
main (origin/main): 2922776 merge: branch-retention rule fix
├── fix/branch-retention-rule  (e5e76d7) — preserved
├── chore/workspace-setup      (85da35d) — preserved
└── doc/initial-spec-corpus    (c1eb07a) — preserved
```

Remote `origin = git@github.com:watkinslabs/oxide.git`. Old project (read-only ref) was `chris17453/oxide` at `~/repos/Projects/oxide_os/`.

## What's NOT done (pending tasks)

In execution order:

1. `chore/spec-lint` — `tools/spec-lint/` Cargo crate. Workspace's first Rust code. Enforces:
   - Doc rules: status line, FROZEN-revision-block-on-edit, MANIFEST sync, forbidden phrases (`08§4`), `## N` numbering outside charters.
   - Code rules: `# C:` on every `pub fn`, `// SAFETY:` ≥30ch, `static mut` ban, `panic!(fmt)` ban, klog format-string interning, no `dyn HAL` (post-build symbol grep), `#![no_std]` every kernel crate.
   - Subcommands: `spec-lint docs|code|manifest|all`.
   - **Prerequisite for any FROZEN spec.**

2. **Charter cool-off + freeze**: 48h cool-off on text per `02§1`, then freeze in dependency order: `02` → `08` → `09` → `01` → `06` → `07` → `04` → `03` → `38`. Living docs (`00`, `05`) stay DRAFT.

3. `phase-0/build-infra` — Phase 0 deliverables per `00§3`:
   - Workspace `Cargo.toml`.
   - `rust-toolchain.toml` (pinned nightly).
   - 2 kernel target JSONs (`targets/x86_64-unknown-oxide-kernel.json`, `targets/aarch64-unknown-oxide-kernel.json`).
   - 2 linker scripts (`link/{x86_64,aarch64}-kernel.ld`).
   - `tools/xtask/` Cargo crate (host binary; subcommands per `07§8`).
   - `crates/hal/` (trait definitions only).
   - `crates/klog/` (minimal UART writer; no decoder yet).
   - `crates/boot-x86_64/`, `crates/boot-aarch64/` — bootloader handoff stubs.
   - `kernel/src/main.rs` — hello-world.
   - `tools/docker/Dockerfile.{build,soak}`.
   - `.github/workflows/{pr,bg-soak,release,dockerfile,weekly}.yml`.
   - **Phase 0 exit**: hello-world boots both arches via QEMU, prints "init started" on UART, exits cleanly. PR-time CI green. Docker image published to ghcr.

4. `phase-1/pmm-buddy` — first real subsystem.

## Doc gaps still acceptable v1

- `CONTRIBUTING.md` — defer until external contributors exist.
- `LICENSE` — TBD (lean MIT/Apache-2.0 dual). v1 issue.
- Bench-artifact + soak-artifact JSON schemas — spec on first artifact write.
- GHA issue/PR templates — defer.

## Active discipline (must hold)

- Spec-before-code: subsystem code only after that spec freezes.
- Branch-per-feature: never commit to `main` directly. `--no-ff` merges. **Don't delete merged branches** — preserve as recoverable history.
- Cool-off: 48h on text before freeze.
- AI-density: dense form for new content; existing slack trims on next revision touching it.
- Lean-mode CI: PR-time = wall; soak = bg diagnostic; no 24h gate.
- Cross-ref form: `<doc>§<sec>`. Every ref resolves to a real section.
- `panic = "abort"`, `kassert!` only, no `static mut`, no `dyn HAL`, `// SAFETY:` ≥30ch.

## Resume protocol next session

1. Read `state.md` (this file).
2. Read `CLAUDE.md`.
3. Read `docs/MANIFEST.md`.
4. Check `git log --oneline --graph -10` and `git status`.
5. Pick up at "What's NOT done" item 1 (`chore/spec-lint`) unless user redirects.

## Open questions for user (deferred)

- LICENSE choice (MIT/Apache-2.0 dual recommended).
- Whether to push `state.md` updates as their own branches each session, or amend onto the active feature branch.
- Whether to add a CI status-badge to README.md once GHA is up.
