# State 2026-05-02

Resumable checkpoint. Update at session exit. Next session reads this first along with `CLAUDE.md` and `docs/MANIFEST.md`.

## Phase

**Charter chain frozen (Z01-Z09).** All 9 charters FROZEN 2026-05-02 with cool-off waiver per `02§1.4`. spec-lint clean across corpus. Workspace shell + PR workflow live. **Phase 0 build-infra unblocked for parts not depending on `36`/`39`/`40`** (still DRAFT).

## What's done

- `docs/` — 46 specs all DRAFT, lean-mode applied, cross-refs mechanical-resolved by `spec-lint xref` (no manual audit), MANIFEST current.
- `CLAUDE.md` — project rules: discipline, code style, doc style, **numbered-branch scheme + PR-mandatory** (updated 2026-05-02), forbidden patterns, where-things-live.
- `.gitignore` — Rust/QEMU/IDE noise; `bench-history`/`soak-artifacts` intentionally tracked.
- `README.md` — entry points.
- `.claude/settings.json` — Bash allowlist incl. `gh pr/issue/run/workflow/api*` and `git push:*` (added 2026-05-02 to remove per-action prompts); deny force-push/sudo/network; ask remains for force-push variants, filter-branch, cargo install, docker push.
- `Cargo.toml` (workspace) + `rust-toolchain.toml` (`nightly-2026-05-01`).
- `tools/spec-lint/` — `docs|code|manifest|xref|all`. Doc rules (status-line + header-form + forbidden phrases), MANIFEST presence/status mismatch, xref resolver (every `<doc>§<sec>` against real headers), code rules (`#![no_std]`, no `extern crate std`, no `static mut` outside test, no `panic!(fmt)`, `// SAFETY:` ≥30ch, `# C:` on every `pub fn`). **`spec-lint all` is clean across the corpus.**
- Memory: `~/.claude/projects/-home-nd-oxide2/memory/` — git workflow updated to PR-mandatory + numbered-branch scheme.
- Git: 12 commits on `main` via 4 PRs and pre-PR-workflow merges; 11 feature branches preserved; pushed to `watkinslabs/oxide`.

## Repo state

History rewritten twice on 2026-05-02:
1. Strip `Co-Authored-By:` trailers from all commits.
2. Rename branches to numbered scheme; merge-commit subjects rewritten to reference new names.

All branches force-pushed to origin. Branch retention preserved (no deletes).

```
main (origin/main): 00991b7 Merge pull request #4 from watkinslabs/C09-spec-lint-xref
├── D01-initial-spec-corpus               (4ba1437) — preserved
├── C01-workspace-setup                   (f07f0f5) — preserved
├── B01-branch-retention-rule             (92f0c8e) — preserved
├── C02-state-checkpoint                  (cb6b47c) — preserved
├── C03-strip-coauthor                    (d7d7932) — preserved
├── C04-state-update-after-coauthor-strip (b553b32) — preserved
├── C05-spec-lint                         (947b93f) — preserved
├── D02-status-line-sweep                 (967248a) — preserved
├── C06-branch-naming-and-pr-workflow     (cb52d86) — preserved [PR #1]
├── C07-state-md-after-rename             (4f859e0) — preserved [PR #2]
├── C08-allow-gh-pr-and-push              (aefe402) — preserved [PR #3]
└── C09-spec-lint-xref                    (2b2639d) — preserved [PR #4]
```

Remote `origin = git@github.com:watkinslabs/oxide.git`. Old project (read-only ref) was `chris17453/oxide` at `~/repos/Projects/oxide_os/`.

**Author**: all commits = `Ablative Personality <chris@watkinslabs.com>`. No co-authors. No AI attribution.

## What's NOT done (pending tasks)

In execution order:

1. **P0-<NN> build-infra (partial, unblocked):** target JSONs, linker scripts, `tools/xtask/`, `crates/hal/` (trait defs), `crates/klog/` (skeleton). All depend only on FROZEN charters.

2. **Subsystem-leaf freezes:** `14`, `23`, `22`, `33`, `36` (HAL/firmware leaves) per `MANIFEST§"Freeze order"`. Each unblocks more of Phase 0.

3. **P0-<NN> build-infra (blocked):** bootloader stubs (`crates/boot-*`) need `36` frozen; `Dockerfile.{build,soak}` and `.github/workflows/*.yml` need `40` frozen; `kernel/src/main.rs` hello-world transitively needs `36`.

4. **Charters that stay DRAFT permanently:** `00` master plan and `05` pre-mortem are living docs per `MANIFEST§"Freeze order"`.

5. Original Phase 0 deliverable list per `00§3`:
   - 2 kernel target JSONs (`targets/x86_64-unknown-oxide-kernel.json`, `targets/aarch64-unknown-oxide-kernel.json`).
   - 2 linker scripts (`link/{x86_64,aarch64}-kernel.ld`).
   - `tools/xtask/` Cargo crate (host binary; subcommands per `07§8`).
   - `crates/hal/` (trait definitions only).
   - `crates/klog/` (minimal UART writer).
   - `crates/boot-x86_64/`, `crates/boot-aarch64/` — handoff stubs.
   - `kernel/src/main.rs` — hello-world.
   - `tools/docker/Dockerfile.{build,soak}`.
   - `.github/workflows/{pr,bg-soak,release,dockerfile,weekly}.yml` — first should wire `spec-lint all` per `40§2`.
   - **Phase 0 exit**: hello-world boots both arches via QEMU, prints "init started" on UART, exits cleanly. PR-time CI green. Docker image published to ghcr.

6. `P1-<NN>-pmm-buddy` — first real subsystem (blocked on `10` freeze).

## Optional spec-lint enhancements (low priority)

- FROZEN-revision-block-on-edit (git-aware diff check).
- Section-paragraph-density warning per `08§6`.
- `klog` format-string `&'static str` check (build-time grep).

## Doc gaps still acceptable v1

- `CONTRIBUTING.md` — defer until external contributors exist.
- `LICENSE` — MIT (per OQ, decided 2026-05-02). Add `LICENSE` file before v1 ship.
- Bench-artifact + soak-artifact JSON schemas — spec on first artifact write.
- GHA issue/PR templates — defer.

## Active discipline (must hold)

- Spec-before-code: subsystem code only after that spec + all its deps freeze.
- **Branch-per-feature + PR-mandatory**: `gh pr create` then `gh pr merge --merge --delete-branch=false`. No local `--no-ff` merges to main.
- Numbered branch scheme: `F<NN>/B<NN>/D<NN>/R<NN>/Z<NN>/C<NN>/P<n>-<NN>` + kebab title.
- Cool-off: 48h on text before freeze.
- AI-density: dense form for new content; existing slack trims on next revision touching it.
- Lean-mode CI: PR-time = wall; soak = bg diagnostic; no 24h gate.
- Cross-ref form: `<doc>§<sec>`. `spec-lint xref` enforces.
- `panic = "abort"`, `kassert!` only, no `static mut`, no `dyn HAL`, `// SAFETY:` ≥30ch.
- Force-push to main: explicit user instruction only (used twice 2026-05-02 for trailer-strip + branch-rename).

## Resume protocol next session

1. Read `state.md` (this file).
2. Read `CLAUDE.md`.
3. Read `docs/MANIFEST.md`.
4. Check `git log --oneline --graph -10` and `git status`.
5. Run `cargo run -p spec-lint -- all` — should be clean.
6. Pick up at `P0-01-target-jsons` (or whatever's next on the unblocked list above). For each freeze that lands a frozen leaf, immediately reassess Phase 0 unblock status.

## Open questions for user (deferred)

- LICENSE: MIT (decided 2026-05-02). Pending `LICENSE` file in repo.
- Whether to add a CI status-badge to README.md once GHA is up.
