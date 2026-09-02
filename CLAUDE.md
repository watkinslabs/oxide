# oxide2

Linux-class kernel + glibc-ABI userspace, in Rust. Kernel targets `x86_64-unknown-oxide-kernel` and `aarch64-unknown-oxide-kernel`; userspace targets upstream `*-unknown-linux-gnu` per `docs/59§1`. Deep in implementation: both arches boot Fedora-composed userspace; work is ledger-driven (`tools/issues.sh --query`) plus the phase plan (`00§3`). Session state: `handoff2.md`.

## NEVER BUILD A WORKAROUND (HARD RULE)

**Diagnose. Read the reference. Never work from memory. Never route around a defect you have not explained.**

A workaround is any change that makes a symptom stop without naming its cause: disabling the failing subsystem, reverting a commit you have not read, widening a timeout, adding a retry, skipping a gate, pinning a boot parameter off. Each converts a fixable bug into an invisible one and lies to the next person about the tree. (Precedent: a boot failure "fixed" twice by SELinux disables; one read of the reference found a seqlock parity bug with a three-line fix.)

- **The reference is the first move, not the last.** Before any hypothesis about externally-defined behaviour, read the implementation in `../reference`.
- **Memory is not evidence.** Neither is a ledger row, a hand-off note, a comment, or a subsystem's name. Read the code.
- **If you cannot explain the mechanism, you have not fixed it.** Record what you measured and hand it on — an open row with a precise diagnosis is a real deliverable; a green tree with a hidden disable is not.
- **A revert is legitimate only when it is the diagnosis** — you read the change, know why it breaks, and reverting is the repair. A revert fired at a symptom is a workaround wearing a suit.

## The framing question (HARD RULE — ask it first, every time)

**"Is this how Linux does it?"** Every feature, fix, and plan starts there — before the design, not after the diff. The reference tree is `../reference`: a checked-out tree; read its files directly and confirm its version (`head -5 ../reference/Makefile`) before quoting. (`../linux-master` is GONE; a stale `../linux-master.zip` still lying around is NOT a reference — a citation to an unpinned snapshot is not verification.)

- **Design.** Find the structure Linux uses and ask why. A differing shape is a decision needing a reason, not an accident found later. Most defects here trace to shapes invented locally — machinery with no caller, a second registry beside the real one.
- **Fixes.** Check what Linux returns and *where it decides*. A fix at the wrong layer passes its test and leaves the defect.
- **Plans.** A plan that cannot name the Linux mechanism it mirrors is a plan to invent one. Name it.
- **Deviations are deliberate and recorded** — ledger row with the reason, pinned by a test so it cannot drift.
- **Ask it even when the answer seems obvious.** The expensive mistakes all looked obvious in the wrong direction until someone read the reference.

Repository text must not name, path-link, or quote external implementation files (`Semantic verification`). Tests carry the provenance.

## Discipline (READ BEFORE EDITING)

1. **Spec-before-code** (`docs/02`): subsystem code may not be written while its spec is DRAFT. Charters (`02`,`08`,`09`,`01`,`06`,`07`) gate everything below.
2. **No cool-off / no soak**: a spec freezes when its text is correct; code merges when tests are green and spec-lint is clean. Duration-gated waits are discipline-theater — reject in review.
3. **No deferrals — there is no v2**: every spec describes the full Linux-equivalent surface. No "deferred", no "subset" framing.
   - **Syscalls (HARD RULE):** every syscall is `IMPL` (full Linux semantics) per `docs/15`. **Never** stub/`ENOSYS`/strawman citing a "tier" (`V1/V2/NEVER` labels abolished, `15` R06). Only the 17 `docs/15` OBSOLETE numbers return `ENOSYS`. Implement fully or say honestly it's not done.
   - **Kernel = hollow shell (`docs/53`):** `kernel/src/syscalls/` is the ABI shim ONLY — parse/validate/fetch/call-one-work-fn/encode, zero work logic. Real work lives in exactly one subsystem work-fn crate (`crates/kernel/<sub>`).
   - **No split source of truth (HARD RULE):** behavior lives in the Linux-shaped owner. No parallel registries, fallback paths, shadow state, string-key side channels, or compatibility shortcuts that can disagree with canonical subsystem state.
4. **AI-density** (`docs/08`): docs and code optimized for AI re-reading. Drop articles, prose intros, restated titles, redundant doc-comments. Keep invariants, ABI tables, test contracts, OQ at full fidelity.
5. **MANIFEST authoritative** (`docs/MANIFEST.md`): every spec listed; status matches file.
6. **Structure contract** (`docs/52`): layout/ownership changes follow `52` and update it in the same PR.
7. **ARM/x86 lockstep (HARD RULE — phase-exit gate):** every phase ships on both arches, not just compiles. Exit checklist: CI green on both kernel builds; `make qemu-x86` AND `make qemu-arm` reach the same smoke target (ARM verified via the qemu MCP, not "should work"); any aarch64 gap exposed closes in the SAME PR. Userspace `.c` compiles on both arches against glibc (no raw `syscall` asm); ARM toolchain is system `aarch64-linux-gnu-gcc` + Fedora sysroot; boot userspace comes from Fedora RPMs via `../images` — never hand-rolled. **No "x86 first, ARM later" anywhere.**

## Cross-references

Form: `<doc>§<sec>` (e.g. `13§4`). Every reference must resolve. When user says `<doc>§<sec>`, **read that section first**.

## Semantic verification (HARD RULE)

Verify externally defined behavior (errno values, error ordering, capability checks, layouts, flag masks) against complete primary reference material before claiming it. Never assert from memory or summaries. Repository comments/docs state only the resulting ABI, observable behavior, invariant, or standard section — never name, path-link, quote, or cite external implementation source files. Tests are the durable provenance: encode verified behavior and error ordering so the contract is re-checkable without citing another codebase.

## Code style hard rules (`docs/07§5`)

- **NEVER run `cargo fmt` / `rustfmt`.** Disabled repo-wide via `rustfmt.toml` (`disable_all_formatting = true`); the compact AI-density style (single-line `if/else`+`for`, aligned columns) is deliberate. Do not delete `rustfmt.toml` or hand-run formatters.
- `panic = "abort"` every kernel profile.
- `kassert!(cond, "literal")` only — no `panic!(fmt)`.
- No `static mut` outside `#[cfg(test)]`.
- No `dyn` on HAL traits (CI vtable grep).
- `#![no_std]` every kernel crate; `extern crate std` = build fail.
- `// SAFETY: <text ≥30 chars naming fn or state>` on every `unsafe { }`.
- `# C: <expr>` doc-comment on every `pub fn` in kernel crates.
- `# Lk:`, `# Ctx:`, `# Sleeps:` markers per `09§6` where applicable.
- klog macros only accept `&'static str` format strings.
- Names short within scope (`pfn`,`pa`,`va`,`sb`,`ino`,`tid`) per `09`.

## File length cap (`docs/08§7`)

- **500 lines** per `.rs` file: at 500, stop and split into focused child modules before continuing. Mandatory.
- **1000 lines** error cap per `.rs`/`.md` (CI fails). Applies to `crates/**`, `kernel/**`, `tools/**`, `docs/**`; vendor code exempt.
- Tests count toward the cap; split `tests.rs` into `tests/<feature>.rs`. Tests live in the module's `tests/` directory, declared path-only from the parent.
- Parent module files are manifests: short `Module manifest` comment naming each child and its responsibility; coordinate/re-export only — no implementation, tests, dispatch bodies, policy, or helper piles.

## Crate/module shape rules

- **Crate main files are manifests only** (`lib.rs`, `main.rs`, `mod.rs`, top-level parents): declare children, re-export surface, carry the manifest comment. Real code lives in focused child files by function/ownership (`ioctl.rs`, `lookup.rs`, `signals.rs`, …).
- **After a split, keep it split.** New logic goes to the owning child module, never back into the root "because it's small".
- Constants owned by contract: UAPI/ABI numbers in `uapi.rs`; flags in `flags.rs` or the owning UAPI module; hardware IDs in `ids.rs`; limits/alignment/timeouts in `limits.rs`; layout offsets in `layout.rs`. No catch-all `constants.rs`.
- Semantic literals are named constants at the owning boundary. Inline literals only for mechanically obvious local values (`0`, `1`, tiny indexes). Major/minors, ioctl encodings, permissions, masks, page sizes, feature bits, timeouts, errno/signal/syscall slots, protocol values: never inline.
- Compiler-gated code at module boundaries (`hosted.rs`, `platform.rs`, `arch.rs`, `kernel.rs` selected by `#[cfg] mod ...; pub use ...;`), not `#[cfg]` scattered through logic.
- Traits at subsystem boundaries (`driver.rs`/`ops.rs` driver-facing, `backend.rs` internal), re-exported by the parent — not defined mid-file.
- UAPI is not policy: constants/structs/numbers in `uapi.rs`; dispatch, permission checks, state mutation, backend translation in focused implementation modules.

## Doc style hard rules (`docs/08`)

- Section headers `## N` (number only) outside charters `00`–`09`.
- One-line bullets unless the second sentence carries an invariant.
- Tables > lists > sentences. Schemas > prose.
- Cite by `<doc>§<sec>`; never restate.
- No "This document defines", "Note that", "In this section we will", "It should be noted", "simply", "really", "actually", "very". No closing summaries.
- Status line: `DRAFT|FROZEN <date>. Dep:<csv>.` at top.

## Forbidden patterns (CI-enforced)

- `static mut` outside test; `panic!(fmt)` in kernel; `format!()` into klog macros; `dyn HAL` traits in compiled kernel; doc-comment restating the function name; `unsafe { }` without ≥30-char `// SAFETY:`; forbidden doc phrases (`08§4`); magic-number errno/signal/flag/syscall-slot literals — use the typed enum (`Errno::Foo as i32`, `Signum::Foo`, `OpenFlags::FOO`, `syscall::nrs::NR_FOO`) per `07§5`.

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
| Repo layout + crate ownership boundaries | `52` |
| Syscall layering (ABI crate / work fns / shim) | `53` |
| **Assembly + low-level ABI checklist (both arches)** | **`54`** ← read BEFORE touching `crates/arch/hal-*` asm OR signal/syscall paths |
| Wireless: cfg80211, mac80211, nl80211 | `62` |
| Boot flow Mermaid | `boot-flow.md` |

When the user asks about a concept: this table → read that spec → answer. Don't guess.

## Quick reference — typed constants (NEVER bare literals)

| Concept | Use | NOT |
|---|---|---|
| Signal number | `sched::live::sigpend::Signum::Sigchld as u8` | `17` |
| `sa_handler` SIG_DFL / SIG_IGN | named consts in same module | `0`, `1` |
| errno | `Errno::Echild.as_i32() as i64` | `-10` |
| Syscall slot | `syscall::nrs::NR_PSELECT6` | `270` |
| Open flag | `OpenFlags::O_NONBLOCK` | `0o4000` |
| Poll mask | `vfs::POLL_IN` / `POLL_HUP` | `1` / `0x10` |

## Toolchain (`docs/07`)

Pinned nightly via `rust-toolchain.toml`; `-Zbuild-std=core,compiler_builtins,alloc` for kernel targets; `rust-lld` both arches; `targets/` JSONs kernel-only (userspace uses upstream GNU targets); GRUB multiboot2 (x86_64) / EFI-stub Image (aarch64).

## CI (`docs/40`)

PR-time gate: both-arch builds, hosted tests with 10M-op proptests, miri, loom, qemu smoke, bench-vs-history, coverage, clippy, deny, spec-lint. GHA hosted runners for PRs; boots stay local (KVM ~1 min vs TCG ~10-15 min). Local QEMU: drive the qemu MCP directly (`mcp__qemu__qemu_start`, `qemu_serial`, `qemu_break`, …) — never claim "needs human-driven QEMU iteration".

## Don't (common future-session mistakes)

- Don't write subsystem code while its spec is DRAFT.
- Don't add `dyn` to a HAL trait "just here" — generic + monomorphized.
- Don't `panic!("fmt {}", x)` — only `kassert!(cond, "literal")`.
- Don't restate spec content in CLAUDE.md or comments — cite `<doc>§<sec>`.
- Don't add MCP servers without asking.
- Don't move docs to `docs/v1/` — versioning is git tags.
- Don't claim work needs human-in-the-loop QEMU testing.

## Boots (HARD RULES — the wall-clock rules)

**NO BOOTS FOR TESTING. A BOOT IS FINAL VERIFICATION ONLY — ONE, AT THE END.** Testing is a harness: a hosted test is milliseconds; a boot is minutes plus a build and serialises against every other lane on the box.

- **Never boot to find something out** — not to see what a parameter does, not to A/B, not to "confirm" a gate that already answered. Extract the decision into an ungated function and test it. If the code is `#![cfg(target_os = "oxide-kernel")]`-gated, that is a defect in where the decision lives (`docs/53`, `Phantom tests`) — moving it is usually faster than the boot.
- **One boot, at the very end, when everything else is green.** About to run a second boot in a lane? You are testing with boots — stop and write the check. Booted >2 times chasing one bug? Build the harness instead. Capture the log so follow-ups re-read it rather than re-boot.
- **Gates are cheap — run freely:** `cargo test`, `feature-gate`, `matrix-gate`, `hosted-gate`, `stack-gate`, `lint-ratchet`. Exhaust them before the single boot.

| question | answer it with |
|---|---|
| does this decision produce the right value? | hosted test on the ungated decision function |
| does this errno/ordering match the reference? | hosted test, reference read first |
| does this option/flag reach the code that acts on it? | extract the wiring decision, test THAT |
| does it work against real glibc userspace? | a boot — the only row that needs one |

**Boot ONLY what can break the boot.** Boot-visible: boot/entry paths, linker scripts, `crates/arch/**`, syscall dispatch/slots, boot-path drivers (console, serial, timer, interrupt, block, virtio), init/exec/mount, mm, sched, ABIs a running binary consumes, image/rootfs, `targets/`, toolchain pins, `Cargo.toml`/`Cargo.lock`. NOT boot-visible: docs, `scratch/**`, comments/SAFETY prose, `#[cfg(test)]`-only, harness edits, lint baselines, off-boot-path tooling, a rebase of already-merged main. State the skip and its reason in the PR body. Unsure = say so and boot once.

**Before push on a boot-visible branch:** `make smoke` (or `smoke-x86`/`smoke-arm`), both arches reach the marker. Pre-push hook enforces (`git config core.hooksPath .githooks`; `SKIP_SMOKE=1` for doc-only).

**Mechanics:**
- **Minimal boot time:** name the marker that answers the question before launching; kill at the marker. Early boot/init ≈15-30s; services/`basic.target` ≈90s; desktop = full boot. Never block-wait on a full smoke when a shorter run answers.
- **Run the two arches CONCURRENTLY** (`make smoke` already does). By hand: background both, `wait` on both, collect both exit codes. Same for any independent long-running pair — serial execution of independent work is the largest avoidable session cost.
- **Every parallel job must `cd` to the worktree ITSELF:** `( (cd <wt> && gate) & (cd <wt> && smoke) & wait )`. `cd <wt> && (a) & (b) &` runs `b` in the original directory — usually the MAIN TREE — and once green-checked `main` instead of the branch. Confirm a gate's log names YOUR worktree.
- **Trust your invocation's exit status, never a `/tmp` log found by timestamp.** `boot-smoke.sh` log names collide across concurrent runs. Use the `boot-smoke: PASS/FAIL` line + exit code from your own run; before reading any log, confirm it has kernel lines (`grep -c '^\[[0-9]'`) and your worktree's build paths.
- **Run smokes with the sandbox DISABLED** (`dangerouslyDisableSandbox: true`): sandboxed `boot-smoke.sh` cannot reap its QEMU, which then holds the image lock — later attempts die with "Is another process using the image", zero kernel output, indistinguishable from a boot failure. Before believing red: kernel lines in log + `lsof` the image for a live QEMU.
- **Scratch artifacts are lane-prefixed** (branch slug in filename); generic names collide across lanes.
- **Shared box:** concurrent boots contend — "fails 3/3" during 6 live smokes measured contention, not the kernel. Check `ps -C qemu-system-x86_64,qemu-system-aarch64` empty before a boot you trust (not `pgrep -fc`, which matches itself). Kill wedged QEMU **by PID** with `dangerouslyDisableSandbox` — never blanket `pkill`; never launch background boot retry-loops. `Z` (defunct) QEMU is harmless.

## Conflict resolution is where coverage dies (HARD RULE)

Two lanes splitting one file along different axes produce a conflict where the STALE side looks plausible (a line-by-line resolution once nearly reverted live sysctl leaves with nothing red).

- **Take the other side wholesale, then re-apply your own delta.** Never hunk-by-hunk on such files.
- **Verify by MULTISET count, not name set** — a set dedupes exactly what you're looking for. Count declarations both sides and after: none dropped, none duplicated.
- Diff hook *bodies* across both sides — one resolution nearly re-introduced a just-fixed bug.

## `cargo check -p <crate>` IS A NULL GATE ON TARGET-GATED CRATES (HARD RULE)

A per-crate `cargo check` compiles NONE of a file carrying `#![cfg(target_os = "oxide-kernel")]` — no check at all, returning green in 2s (measured with a planted type error: `cargo check -p syscalls` 0 errors; `make feature-gate-x86` correct file+line). About a third of `syscalls` is gated; so is `procfs/ctl.rs` and any kernel-only code.

- Touching a target-gated file? Inner loop: `cargo run --quiet -p xtask -- kernel --arch x86_64 --check` (~4s warm); run `--arch aarch64` too before reporting.
- `make feature-gate` is the superset (also compiles `debug-*` blocks) and is what a lane reports against.
- Never report "cargo check is clean" as evidence for a gated file — say which command you ran.

## Verification must be able to fail (HARD RULE)

A green check that does not exercise what it claims converts an unknown into false assurance (confirmed: target-gated files cargo-check "passed" unbuilt; a set-based dup check structurally unable to find dups; a gate set compiling no feature-gated code). **Require a positive control:** plant the defect, confirm RED; restore, confirm GREEN; report both. Applies to new tests, new gates, and any coverage claim.

## Never state a conclusion a proxy cannot support (HARD RULE)

A timestamp, a count, an absence, or a single sample is evidence ABOUT the thing, not the thing. Repeat offenders: mtime read as build provenance (wrong); a grep of a nonexistent path read as a missing feature; one boot read as a rate; a ledger row read as the code (~two-thirds of claimed gaps were already closed). Before asserting X, ask what would be true if X were false and check THAT — reading the file beats reading its date; one hosted test beats three boots. If the check is expensive: **say "I observed A, which suggests B" — never "B"** when you only have A.

## Re-verify a claimed gap before implementing it (HARD RULE)

A recorded gap is a hypothesis. Ledger/matrix text goes stale pessimistically; measured on one campaign, ~two-thirds of claimed gaps were already closed. Read the current code, then the reference, then implement. Correcting a stale claim is worth as much as an implementation — report either way.

- **A zero grep is not absence:** wrong path (`net/src/unix/` vs `net/src/unix_sock/`), name-only miss (hand-rolled ABI record), or behaviour gated out of your build. Grep for behaviour and call sites; confirm the path exists before trusting a zero.
- **"Remaining: coverage, not behaviour" is where live defects hide** — three security bugs were found under exactly that phrasing. It usually means nobody looked recently.
- **A wrong justification is worse than an open gap** — check the *reason* a row gives, not just its status (one row recorded a divergence as compliance by citing a reference built without the relevant configs).

## A hard row never blocks the queue (HARD RULE)

Throughput across the ledger beats closing any single item. **Two honest attempts is the signal**: then write up what you MEASURED (numbers, dead ends, disproved premises), pick a different row, preferably another subsystem. An open row with a precise diagnosis is a good outcome; a stalled queue is not. Never report a blockage as a reason to stop working. This does NOT license giving up early or leaving a regression — revert failed attempts, keep the tree green, file the negative results.

## Out-of-lane work gets a lane, not a filed row (HARD RULE)

A lane that finds a real fix outside its file ownership must not stop at filing it — the finder reports the boundary; the coordinator spawns a lane NOW, while the diagnosis is fresh. Never route around a boundary with a duplicate (that is the forbidden split source of truth). Blocked-on-a-sibling is a scheduling fact, not a scope reduction. Supporting work (harness fixes, probes, fixtures, make targets) is in scope for the lane that hits it — four lanes were unblocked exactly that way.

## Phantom tests: kernel-gated files cannot be tested (HARD RULE)

Any file carrying `#![cfg(target_os = "oxide-kernel")]` (and every module a gated `kernel_body.rs` declares) compiles out of `cargo test` entirely — a `#[cfg(test)]` block there is never built, and `cargo test` still says "ok". **Therefore:** decision logic — errno ordering, flag validation, permission ladders, ABI layout — lives in ungated modules; the slot file stays a thin shim (`docs/53`). Working examples: `syscalls/src/pkey.rs`, `lsm.rs`, `obsolete.rs`, `sched_policy.rs`, `sched/src/cred/caps.rs`. **Verify tests actually ran:** `0 passed; N filtered out` means never compiled; the count must go UP when you add a test.

## How to act on big/cross-subsystem changes (HARD RULE)

1. **Verify left — boot is the final gate, not the dev loop.** Build a hosted `cargo test` harness driving real code against a real fixture; iterate there; boot once at the end.
2. **Foundation before wiring.** If the plan replaces a fragmented structure, do that first so the new primitive is THE path — not a legacy-first fallback bolt-on you'll unwind.
3. **Audit constraints up front, in ONE pass.** Enumerate which handler each glibc wrapper invokes and backend capabilities before touching syscalls; read glibc/UAPI/dispatch once, not one boot at a time.
4. **Boot-harness hygiene:** warm-build the debug kernel once; exclusive boots (kill stale qemu, port 2222 free); dev shell runs `set -e` — guard capture chains with `|| true`.
5. **When thrashing, fix the loop, not the repetition.** >2-3 boots on one bug = build the harness or add a trace. Surface half-built state honestly.

## Lessons learned (boot campaigns — HARD RULES)

1. **Bare `xtask kernel` builds but does NOT export** — `make boot` then boots a STALE `target/artifacts` kernel silently. Build boots with `make kernel boot PROFILE=... ARCH=...`; confirm the artifact mtime is fresh before trusting any boot.
2. **imagectl reads the MAIN tree's `../kernel/target/artifacts`, not a worktree** (`KERNEL_DIR` does not change what boots). Boot-verify centrally; worktree lanes copy their kernel in if they need a boot.
3. **Single boots LIE about intermittent bugs.** Measure over N sequential boots (report clean/total) before attributing, reverting, or declaring fixed; a hosted causality test beats any boot count.
4. **When a boot contradicts strong evidence, suspect the MEASUREMENT first** (stale artifacts, fouled harness) before re-opening a closed fix.
5. **Boot-verify after EVERY merge** — hosted-green fixes have broken real boots (ABI/integration classes only a boot exposes). Both arches build + `cargo test` 0-failed before any push; "main is always known-good" is what makes a bad merge a fast revert.
6. **Disprove-don't-hack, with evidence.** "I disproved X, here's the evidence, here's the narrowed suspect" beats a plausible patch. Never blindly re-enable a reverted hack.
7. **Reap your own stale QEMU** — by PID, `dangerouslyDisableSandbox: true`; never blanket-pkill (sibling lanes), never background boot retry-loops.
8. **A flaky ~8-line "boot" is a GRUB hang, not a result** (~half of cold boots); a real boot is >2000 lines. Re-run once.
9. **A refcounted kernel RAM frame shared into userspace maps as `VmaBacking::KernelFrame`, NEVER `PhysRange`.** `PhysRange` (= `remap_pfn_range`) is for unrefcounted device memory: no inc_ref, no mapcount, so the owner's last drop frees the page while userspace still maps it — free-while-mapped UAF corrupting the heap with incidental values (io_uring hit this, B1342). Audit every `glue_mmap(..., phys_base=Some(pa), ...)`: device MMIO ok; refcounted RAM must be `KernelFrame`. `map_phys_range`'s mapcount=0 also defeats the never-free-a-mapped-page guard; the `debug-cow` `[COW-LEAK]` detector catches the class.
10. **The buddy allocator ZEROS every page on alloc**, wiping write-while-free poison before downstream checks — the poison detectors only ever see zeros for the page body. A body check must run inside `alloc_inner` BEFORE the zero loop. "The poison detector didn't fire" proves nothing until you've confirmed it runs before zeroing.
11. **The multi-session ~90%-boot heap-corruption campaign resolved as a KERNEL-STACK OVERFLOW** (16KB Box stacks, no guard page) scribbling the adjacent heap block — fixed C213 (VMAP_STACK guard pages + frame de-bloat); every UAF/refcount theory was wrong. Durable lessons: "masked by every allocator change + victim varies by layout" = suspect stack-overflow-into-heap and check `debug-stack-guard` FIRST; free-IP provenance (kalloc's `FreeIpRing`, printed at every corruption site) deterministically names a UAF victim's freer — reuse the method for any UAF.

## Agent model selection (HARD RULE)

**Investigative agents run on Sonnet** (`model: "sonnet"` on the Agent call — not the default); only genuinely hard work gets Opus.

| Sonnet | Opus |
|---|---|
| triage, audits, inventories, "find where X is" | subsystem implementation with real design choices |
| reading specs/matrix rows, reporting state | root-causing a live bug with no working hypothesis |
| ledger folds, doc sweeps, mechanical edits | ABI/semantics work cross-checked against the reference |
| flake diagnosis, running gates, collecting evidence | anything where a wrong answer ships a silent defect |

A lane that turns out to need Opus gets **re-spawned from the written finding**, not upgraded in place. A Sonnet lane told to report returns a finding; an Opus lane given the same brief tends to fix it — scope creep.

## A fan-out must be MEASURED, not assumed (HARD RULE)

"Running" is not "making progress": a lane blocked on a lock or a broken tree reports the same silence as one working (a four-lane wave once ran at one-lane speed for 40 min on a shared cargo lock, invisible from outside).

- **Every lane gets its OWN `CARGO_TARGET_DIR`** (`CARGO_TARGET_DIR=<scratch>/tgt-<lane>` in the opening brief) — one target dir is a global build lock.
- **Run `tools/lane-health.sh`** before concluding anything about a lane (lock contention, non-compiling tree, orphan `mod` declarations, source silence); check it when a lane goes quiet.
- **A `mod foo;` declaration and `foo.rs` land in the SAME write** — a dangling declaration breaks the crate for every lane in the worktree.
- **Never diagnose a lane from silence.** Check processes, mtimes, whether the crate compiles; state what you measured.
- **Prefer one worktree per lane** when lanes edit overlapping files or all need the crate compiling; a shared worktree needs strict file ownership and serialised hook passes, stated in each brief.

## Claim work before starting (HARD RULE — no duplicate lanes)

Two agents once rewrote the same subsystem item in parallel — hours of conflicting work. Before writing ANY code for a ledger item / subsystem task:

1. **Check for an existing lane:** `git worktree list` + `git branch -a` (branch covering this item?); `tools/issues.sh --show KI-NNNN` (row IN-PROGRESS/claimed?); for core work, grep the source for the symbol you'd add.
2. **If a lane exists, do NOT open a parallel one** — continue it, take it over, or pick a different item.
3. **Claim before starting:** `tools/issues.sh --claim KI-NNNN <branch>` and commit the claim so the next agent's check sees it.
4. **After any agent wave, before boot-verify:** re-check main-tree HEAD + branches + worktrees — concurrent lanes move them, and a stale HEAD assumption invalidates a boot result.
5. **One item = one lane = one agent.** Discover a duplicate mid-task: STOP, preserve your commit on a branch, reconcile with the owner.
6. **Fan out independent work immediately** — one owner per file area, one integration owner, explicit handoff evidence. Don't serialize independent work; don't overlap ownership to inflate agent count.
7. **Delegated agents have no merge authority.** Only the primary/integration owner creates or merges PRs; "do not commit/push/PR/merge" is a hard boundary.
8. **A worktree belongs to its lane owner.** Never remove, prune, reset, or repurpose a worktree you did not create; the integration owner removes it only after handoff, clean `git status`, and merge.

## A lane is not done until it is WIRED (HARD RULE)

Code that compiles and passes its own tests is delivered only when something in the running system CALLS it — a lane's tests call the lane, so "complete, 113 tests green" says nothing about reachability (one wave shipped six f2fs lanes, four of them dead code, all green). This is `Machinery without callers` through the front door.

- **The orchestrator owns integration and cannot delegate it** — applying hooks, resolving cross-lane conflicts, proving reachability. No lane owns the call site.
- **Never report a lane complete on its own test count.** Prove reachability: grep the entry point's callers from OUTSIDE the lane's files and outside `#[cfg(test)]`.
- **Name the call site in the completion report** ("wired into `volume/io.rs::read_file` at the `Mapped::Compressed` arm") — a checkable claim, unlike a test count.
- **An integration test at the boundary the lane crosses is the proof**, not a unit test.
- **A hook a lane reports is an orchestrator task:** apply it in-session, re-run the suite, positive-control the hook (remove the call, confirm red).
- **Ledger rows are filed by the orchestrator per lane on receipt** — never batched to the end, never left in a report; a row that exists only in a transcript does not exist.

**Completion bar for a fan-out:** hooks applied, full suite green, positive control per hook, call site named per lane, rows filed. Anything short is honestly "built, not wired".

## NEVER WORK ON MAIN (HARD RULE)

All work on a branch, reaching `main` only through a PR. No "it's only a doc", no one-line exception. Before editing ANY file: `git rev-parse --abbrev-ref HEAD`; if `main`, branch first. `main` is read-only reference; a shared checkout may hold someone else's uncommitted work. Opening/merging the PR is the integration owner's call — push and report.

## NEVER `git stash` (HARD RULE)

The stash stack is SHARED across every worktree of a clone — with concurrent lanes, `stash`/`pop` is a cross-lane data race (already happened; recovered via `git fsck`). Park WIP as a temporary commit on your own branch (`git commit -m wip` / `git reset --soft HEAD~1`). Stash entries you did not create are someone else's live work. Applies to `-u` and `push <path>` forms too.

## NEVER `git add -A` (HARD RULE)

No `git add -A`, `git add .`, `git commit -a`, or any stage-everything form — blanket staging sweeps up other agents' edits and stray artifacts (already shipped someone's unfinished work under wrong authorship). `git status --short` first; stage each path by name; commit only after `git diff --cached --stat` shows exactly the intended files. A long list means the change is too big, not a reason for `-A`.

## Git workflow (mandatory)

**Commit author (HARD RULE):** every commit + PR is authored by `Chris Watkins <chris@watkinslabs.com>` — the only valid identity. Verify `git config user.name`/`user.email` in any fresh clone before committing.

**Branch per change.** Single-letter type + zero-padded counter + kebab-case title (≤40 chars):

| Prefix | Use |
|---|---|
| `F<NN>-` | new functionality |
| `B<NN>-` | bug fix |
| `D<NN>-` | spec edits only |
| `R<NN>-` | revise a FROZEN spec (`02§1`) |
| `Z<NN>-` | freeze a DRAFT spec |
| `C<NN>-` | tooling, deps, CI plumbing |
| `P<n>-<NN>-` | phase-N work |

Counters per-type, monotonic, never reused.

**CLAIM the counter, never just read it (HARD RULE):**
```
name=$(tools/next-branch.sh --claim B my-fix-title)
git worktree add -b "$name" ../kernel-${name%%-*} origin/main
```
`--claim` pushes a `claim/<T><NN>` ref so the number is yours atomically; reading (`--dry-run`, `metadata/index.md`) is NOT claiming — three lanes once drew the same number and one implementation was discarded. Never invent or hand-pick a number; git refs are the only source of truth. `make counters` prints next free per type.

**Short-lived feature branches / worktree loop (HARD RULE):** each item gets a fresh branch from current `origin/main` in its own worktree; commit, push, PR, merge, update main, delete branch + worktree, then start the next item from a new worktree. No omnibus branches, no reused worktrees, no piling onto a dirty branch. Refactors are features too. Misshapen branch: archive-tag it, cherry-pick the good commits onto clean branches.

**Phase prefix matches `00§3`;** phases are sequential — no phase-`n+1` work before phase-`n` exit gates; pick the lowest unfinished phase.

**Commits:** small, focused; `<type>: <subject>` + body (why, not what); `<type>` ∈ `feat|fix|doc|spec|refactor|test|bench|chore|ci|build|revise|freeze`.

**Push policy:** auto-push every feature branch with `-u` at first commit; auto-push merged main. **Never pipe a state-changing command when its exit status is the evidence** (`git push | tail` reports `tail`'s status): run it directly or check `${PIPESTATUS[0]}`; before reporting a push landed, fetch and verify the remote ref SHA.

**PRs:** `gh pr create` then `gh pr merge --merge --delete-branch=true`; no local merges to `main`; delete remote + local branch on merge.

**Never (without explicit user confirmation):**
- Force-push to `main` or anyone else's branch.
- `git rebase main` on a branch under review by others.
- `git commit --amend` on a pushed commit.
- Skip hooks (`--no-verify`) or signing (`--no-gpg-sign`).
- Direct commits to `main` outside emergency-fix-then-PR.
- `git reset --soft/--hard` onto a REMOTE ref from a feature branch — with the remote advanced, it stages a silent mass revert (~130 files once). Rebase or reset onto your own merge-base.
- **Any `Co-Authored-By:` trailer, ever** (CI lint rejects).
- **Any AI attribution anywhere in the repo** — no "Generated with Claude Code", no 🤖 footers, no session/assistant links, in commits, PR bodies/titles, issues, comments, or docs; strip harness-supplied footers before opening the PR.

**Tags:** `v1.0`-style releases; `v0.<n>-phase-<m>` milestones; signed once we have a key. **Reverting:** always `git revert <sha>`; never delete history on `main`. **Branch retention:** delete on merge (remote via `--delete-branch=true`, then clean worktree, then local); keep unmerged branches until explicitly abandoned — never force-delete without confirmation.

## Plans live in scratch/ (HARD RULE)

Every plan / analysis / ledger doc goes in `scratch/`, never the repo root or `docs/` (specs only). Plans carry a **Status** first column and a **Branch** column per item, updated as lanes claim/merge.

## Known issues ledger (HARD RULE)

Every issue, breakage, divergence, gap, flake, or thing-worth-noting gets a row in `scratch/known_issues.md` **in the same PR that finds it**. There is no second store; per-lane drop files are abolished. A concurrent-lane conflict here is worth the rebase — resolve by taking BOTH sides' rows.

**Row shape: `| Id | Status | Class | Sev | Issue | Evidence | Owner |`** — `Id` is a stable `KI-NNNN`, assigned by tooling, never reused; escape literal `|` in cell text as `\|` (code spans included). `Class` ∈ `DEFECT` (diverges from Linux) | `MISSING` (absent or unconsumed Linux surface) | `COVERAGE` (no check can fail here) | `INFRA` (tooling, gates, docs, images, dev box) | `PERF`. Class says what KIND of work a row needs, never whether it gets done — no "won't fix", no deferral status; every row is work this project WILL do.

**Use the tooling — never read or grep the whole ledger:**
- `tools/issues.sh --query [status=..] [class=..] [sev=..] [owner=..] [grep=RE]` — brief matching rows; `--show KI-NNNN` — full row.
- `--add CLASS SEV OWNER 'issue' 'evidence'` — files a row, prints its id.
- `--claim KI-NNNN <branch>` — marks it yours (see `Claim work before starting`).
- `--fix KI-NNNN <sha>` — flips to FIXED and moves the row to `scratch/archive/fixed-issues.md`, id preserved. Run in the fixing PR.
- `--check` — shape/id/cap validation (CI gate). Evidence cells cap at 2000 chars — park longer detail in `scratch/archive/`.

Rules: find it, file it (including deliberate divergences — the choice is not the fix, the row stays open until Linux behaviour lands). Fix it, flip it — never silently delete a row. A row with no owner is still a row. Record EVIDENCE, not theory; negative results are first-class. Never downgrade a severity without new evidence.

**`scratch/archive/` is closed history** (fixed rows, finished session docs, evidence captures, journal overflow). NEVER grep or bulk-read it while working; open a specific file only when chasing a named id or incident.

## handoff2.md is short-lived session memory, not history

Hand-off note from the previous session only. Hard cap 200 lines; overwrite, don't append; headline + open work + literal first command for next session. No session archaeology (git log is), no commit-message duplication (cite SHAs). Durable knowledge goes in CLAUDE.md or auto-memory.

## When in doubt

Read `docs/MANIFEST.md` → the spec your work touches → ask the user before deviating.

## Communication

- **BE SUCCINCT (HARD RULE).** As few words as the answer needs; a table or code block beats a paragraph. No preamble, no restating the question, no end-of-turn recaps, no re-listing merged work. Report results, not the narrative of reaching them; dead ends get one line. Long output only for content the user asked for.
- Honest opinion before action when stakes are non-trivial: "advise then act", not "ask then act".
- Changes touching multiple specs: list the specs first, action second.
- When uncertain, say so. Don't smooth-talk.

## Autonomous-run discipline (HARD RULE)

On "continue / keep going / work through everything":

1. **Do not stop until the project is done** — the next phase, and the one after, until `00§3` is exhausted or a hard blocker (unresolvable compile fail, missing external resource, destructive op needing confirmation) appears.
2. **No intermediate stopping-point announcements** ("natural seam", "clean place to pause") — they cost the user hours of assumed-background wall-clock. Start the next phase.
3. **No EOD-style summaries between phases** — update docs, push the PR, start the next branch, silently.
4. A long phase is many small PRs, not an excuse.
5. Writing "this is a natural stopping point"? Stop that sentence and start the next branch.
6. Only (a) explicit user instruction, (b) genuine blocker, or (c) red tests/build with root cause unfound after ~3 attempts justifies stopping.
