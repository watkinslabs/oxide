# oxide2

Linux-class kernel + glibc-ABI userspace, in Rust. Kernel targets `x86_64-unknown-oxide-kernel` and `aarch64-unknown-oxide-kernel`; userspace targets upstream `*-unknown-linux-gnu` per `docs/59§1`.

## Status

Pre-code. 46 specs in `docs/`, all DRAFT. Spec-lint tool (`tools/spec-lint/`) and Phase 0 build infra are next.

## Discipline (READ BEFORE EDITING)

1. **Spec-before-code** (`docs/02`): subsystem code may not be written while its spec is DRAFT. Charters (`02`,`08`,`09`,`01`,`06`,`07`) gate everything below.
2. **No cool-off / no soak**: a spec freezes the moment its text is correct. Code merges the moment tests are green and spec-lint is clean. Duration-gated waits and 24h/48h/168h soaks are forbidden discipline-theater. Reject them in PR review.
3. **No deferrals — there is no v2**: every spec describes the full Linux-equivalent surface. No "rides v2.x", no "deferred to v2", no "subset" framing. If a feature is part of the Linux contract for that subsystem, it is in scope for v1 and gets implemented before the spec freezes. Old `v2-arch-plan.md` and `docs/v2/` directory are dead history.
   - **Syscalls (HARD RULE):** every syscall is `IMPL` (full Linux semantics) per `docs/15` — build all the Linux syscalls we can so real programs work. **Never** stub/`ENOSYS`/strawman a syscall citing a "tier" or "version" — those labels (`V1/V2/NEVER`) are abolished (`15` R06). The ONLY syscalls that return `ENOSYS` are the 17 `docs/15` OBSOLETE numbers (modern Linux itself ENOSYS's them). If asked for a syscall, implement it fully or say honestly it's not done — never silently stub.
   - **Kernel = hollow shell (`docs/53`):** `kernel/src/syscalls/` is the ABI shim ONLY — parse/validate/fetch/call-one-work-fn/encode, **zero** work logic. Real work lives in a subsystem work-fn crate (`crates/kernel/<sub>`), in exactly one place — never written directly in the kernel, never duplicated kernel+crate.
   - **No split source of truth (HARD RULE):** Eliminate any split source of truth. Linux compliance comes first, in both logic and location. Put behavior in the Linux-shaped owner that actually owns it; do not add parallel registries, fallback paths, shadow state, string-key side channels, or compatibility shortcuts that can disagree with the canonical subsystem state.
4. **AI-density** (`docs/08`): docs and code optimized for AI re-reading. Drop articles, prose intros, restated section titles, redundant doc-comments. Keep frozen invariants, ABI tables, test contracts, OQ at full fidelity.
5. **MANIFEST authoritative** (`docs/MANIFEST.md`): every spec listed; status matches file's status line.
6. **Structure contract** (`docs/52`): new layout and ownership changes must follow `52` and update it in the same PR when boundaries change.
7. **ARM/x86 lockstep** (HARD RULE — phase-exit gate): every phase ships on **both** arches, not just compiles. A phase is not done until `make qemu-arm` AND `make qemu-x86` both reach the same user-visible milestone. **Per-phase exit checklist (mandatory, every phase):**
   - PR-time CI green on both `build kernel x86_64` AND `build kernel aarch64`
   - `make qemu-x86` boots through the phase's smoke target (init prints, fork+exec works, etc.)
   - `make qemu-arm` boots through the SAME smoke target — verified via the qemu MCP (`mcp__qemu__qemu_start arch=aarch64`), not "should work" reasoning
   - Any aarch64 gap exposed by the work (missing syscall, missing fault classifier, x86-only inline-asm in userspace `.c`, missing toolchain, missing register save/restore, etc.) closes in the SAME PR — never deferred to a later session
   - Userspace `.c` sources must compile on both arches against the glibc ABI, not raw `syscall` inline asm. Use standard glibc entry points and the repository's GNU-target sysroot.
   - The ARM toolchain is fetched on demand by `tools/fetch-cross.sh`. Userspace comes from real vendor cross-builds (bash, coreutils, util-linux, systemd, …) — never hand-rolled minimal replacements.

   **No "x86 first, ARM later" anywhere in the phase ladder.** Out-of-phase work belongs in `docs/v2/` per `00§14` rule 5; lockstep gaps go in the same PR or block phase exit.

## Cross-references

Form: `<doc>§<sec>` (e.g., `13§4`, `02§1`, `04§1.1`). Every reference must resolve to a section in the cited doc.

When user says `<doc>§<sec>`, **read that section first** before responding.

## Code style hard rules (`docs/07§5`)

- **NEVER run `cargo fmt` / `rustfmt`.** rustfmt is disabled repo-wide via `rustfmt.toml` (`disable_all_formatting = true`) — the codebase uses a deliberate compact / AI-density style (single-line `if/else`+`for`, aligned columns) that default rustfmt destroys. A stray `cargo fmt` once reformatted 679 files; the guard makes `cargo fmt` (and `--check`) a no-op. Do not delete `rustfmt.toml`, do not hand-run formatters, do not "tidy" with rustfmt.
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

- Cutoff: **500 lines** per `.rs` code file. At 500, stop adding implementation to that file and split it into focused child modules/files before continuing work in that area. This is mandatory, not advisory. The parent file remains a manifest, not a place to park excess code.
- Error cap: **1000 lines** per `.rs` or `.md` file. CI/spec-lint fails above this. Applies to our source in `crates/**`, `kernel/**`, `tools/**`, `docs/**` (excluding `docs/v2/`, `vendor/**`, and `vendors/**`). Imported third-party vendor code is not subject to line caps.
- Split big files into submodules: Rust `mod foo; foo/{a.rs,b.rs}`; markdown into sister docs cross-referenced via `<doc>§<sec>`.
- Tests count toward the cap — split `tests.rs` into `tests/<feature>.rs` once it grows.
- Parent module files are manifests: keep a short `Module manifest` comment near the top that names each child module and its owned responsibility. The parent coordinates/re-exports; it must not contain implementation logic, tests, long impl blocks, dispatch bodies, policy, backend translation, or helper piles.

## Crate/module shape rules

- **Crate main files are manifests only.** `lib.rs`, `main.rs`, `mod.rs`, and top-level parent module files declare child modules, re-export the public surface, and carry the short module manifest that says where each functional group lives. All real code lives in focused child files/modules by function or ownership group (`ioctl.rs`, `lookup.rs`, `signals.rs`, `creds.rs`, `irq.rs`, `modeset.rs`, `tests/<feature>.rs`, etc.). These manifest files must not hold subsystem logic, method bodies, dispatch bodies, policy, backend translation, tests, or growing helper piles.
- **After a module is split, keep it split.** Do not add new logic back into the crate root or parent manifest because it is "small" or convenient. Put new code in the child module that owns that responsibility, or create a new named child module when no current owner fits.
- Constants are owned by contract, not convenience. UAPI/ABI numbers live in `uapi.rs`; bit flags, mode flags, caps, and feature bits live in `flags.rs` or the owning UAPI module; hardware/bus IDs live in `ids.rs`; limits, alignment, counts, and timeout constants live in `limits.rs`; layout offsets and ABI size helpers live in `layout.rs`.
- Do not create catch-all `constants.rs` files unless the crate is tiny and has exactly one constant contract. A generic constants file becomes a dumping ground; prefer a name that states ownership (`uapi`, `flags`, `ids`, `limits`, `layout`, `features`).
- Semantic literals in logic must be named constants at the owning module boundary. Inline literals are only acceptable for mechanically obvious local values (`0`, `1`, tiny array indexes, immediate boolean/count checks). Major/minor numbers, ioctl encodings, permissions, alignment masks, page sizes, feature bits, IDs, timeout values, errno/signal/syscall slots, and protocol values are never inline.
- Compiler-gated code belongs at module boundaries when more than a tiny local alternative is needed. Prefer `hosted.rs`, `platform.rs`, `arch.rs`, `kernel.rs`, or target-specific child modules selected by `#[cfg] mod ...; pub use ...;` in the parent manifest. Do not scatter `#[cfg(...)]` through unrelated implementation logic.
- Traits live at subsystem boundaries. Driver-facing traits belong in `driver.rs` or `ops.rs`; internal backend traits belong in `backend.rs`; public traits are re-exported by the parent manifest. Do not define long-lived traits halfway down implementation files.
- UAPI is not policy. Linux constants, ioctl structs, ioctl numbers, wire structs, and ABI flags live in `uapi.rs`; dispatch, permission checks, state mutation, and backend translation live in focused implementation modules (`ioctl.rs`, `auth.rs`, `modeset.rs`, etc.).

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
- Magic-number errno / signal / flag / syscall-slot literals — use the typed enum (`Errno::Foo as i32`, `Signum::Foo`, `OpenFlags::FOO`, `syscall::nrs::NR_FOO`). Per `07§5`

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
| **Assembly + low-level ABI correctness checklist (x86_64 AND aarch64)** | **`54`** ← read BEFORE touching `crates/arch/hal-{x86_64,aarch64}` asm OR signal/syscall paths |
| Boot flow Mermaid | `boot-flow.md` |

When user asks about a concept: check this table → read that spec → answer. Don't guess; read.

## Quick reference — typed constants (NEVER use bare literals)

Per `07§5`. Replace magic numbers with the named constant at call site:

| Concept | Use | NOT |
|---|---|---|
| Signal number | `sched::live::sigpend::Signum::Sigchld as u8` | `17` |
| `sa_handler` SIG_DFL / SIG_IGN | named consts in same module | `0`, `1` |
| errno | `Errno::Echild.as_i32() as i64` | `-10` |
| Syscall slot | `syscall::nrs::NR_PSELECT6` | `270` |
| Open flag | `OpenFlags::O_NONBLOCK` | `0o4000` |
| Poll mask | `vfs::POLL_IN` / `POLL_HUP` | `1` / `0x10` |

Bare integer literals in any of these positions = silent bug bait
(off-by-one between arches, between Linux uapi versions, etc.).

## Toolchain (`docs/07`)

- Pinned nightly Rust via `rust-toolchain.toml`.
- `-Zbuild-std=core,compiler_builtins,alloc` for kernel targets.
- `rust-lld` linker both arches.
- Custom JSONs in `targets/` are kernel-only; userspace uses upstream `*-unknown-linux-gnu` targets.
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

## Boot smoke before push (mandatory for kernel changes)

Hosted unit tests cannot catch syscall-table / ABI / arch-routing regressions — these only fail once real glibc userspace (systemd, bash, Fedora packages) runs. The cheapest gate is local: boot the kernel under qemu, wait for `oxide login:`, fail-fast if it doesn't appear.

**Rule:** before `git push` on a branch that touches `kernel/`, `crates/kernel/`, `crates/drivers/`, `crates/arch/`, `userspace/`, `targets/`, `vendor/`, `rust-toolchain.toml`, `Cargo.toml`, or `Cargo.lock` — run `make smoke` (or `make smoke-x86` / `smoke-arm`) and confirm both arches reach login.

A pre-push hook at `.githooks/pre-push` enforces this automatically. Install once per clone with `git config core.hooksPath .githooks`. Bypass for known-safe doc-only pushes with `SKIP_SMOKE=1 git push`.

Hosted runners are not used for this — TCG boots are ~10-15 min/arch and burn GHA minutes. The pre-push hook runs on the dev box where KVM keeps boot under a minute.

## How to act on big/cross-subsystem changes (HARD RULE — learned the hard way)

When a change spans subsystems, needs many boot-test cycles, or sits on a structure a later stage will replace, follow these or you will burn hours and ship half-built bolt-ons:

1. **Verify left — QEMU boot is the final gate, NOT the dev loop.** Before wiring a subsystem, build a **hosted `cargo test` harness that drives the real code against a real fixture** (e.g. drive `vfs::path_lookup` over an ext4 image via the global mount; assert resolution/symlink/ELOOP). Milliseconds, no boot, no port, no rebuild. Iterate there; boot once at the end for lockstep. A full `make qemu-x86` boot as the inner loop = wasted hours. The qemu MCP session (one warm VM, breakpoint+inspect) beats repeated cold boots when you must boot.

2. **Foundation before wiring — never build on sand.** If the plan has a unification/refactor stage that replaces a fragmented structure (e.g. unified dentry-keyed mount tree replacing string-table + devfs-registry), do it **before** migrating callers, so the new primitive is THE path used uniformly — not a `legacy-first + fallback` bolt-on you'll unwind. Reorder stages to put the foundation first. A bolt-on on top of a doomed structure is the "minimal/v1-subset" the project forbids (`docs/02`, Discipline rule 3).

3. **Audit constraints up front, in ONE pass — don't discover them one boot at a time.** Before touching syscalls, enumerate which kernel handler each glibc wrapper invokes (including architecture-specific fallback paths), and the real capabilities of the backends you depend on. Read glibc, Linux UAPI, and the dispatch table once; don't reverse-engineer routing by trial boot.

4. **Boot-harness hygiene (the thrash sources):** warm-build the debug kernel once before iterating (cold debug-boot rebuild ≈ 5 min); ensure **exclusive** boots — kill stale `qemu-system` first and confirm port 2222 free (overlapping QEMUs from prior runs cause `Could not set up host forwarding` failures); the dev shell runs `set -e`, so `cmd > file; echo >> file` chains **lose the capture when `cmd` exits non-zero** — guard with `|| true` or split the commands.

5. **When stuck thrashing: stop and fix the loop, don't repeat it.** If you've booted >2-3 times to chase one bug, the loop is the problem — build the hosted harness or add a targeted trace, rather than re-running the slow path. Surface the half-built state honestly instead of pushing a compromise.

## Lessons learned (boot-to-GNOME campaign — HARD RULES, learned the expensive way)

These cost real hours. Violating them produces false conclusions and wasted boots.

1. **`cargo run -p xtask -- kernel` BUILDS but does NOT export to `target/artifacts`.** The export is a separate `cargo run -p xtask -- artifacts --arch <a>` step. imagectl / `make boot` boot `target/artifacts/<arch>/kernel.elf`. Building with bare `xtask kernel` then `make boot` boots a **STALE** kernel — silently (you "verify a fix" against an old binary and see a bug that's already fixed, or vice-versa). ALWAYS build boots with `make kernel boot PROFILE=live-gnome ARCH=x86_64` (= `xtask kernel` + `xtask artifacts` + ISO). Before trusting any boot, confirm `ls -la target/artifacts/<arch>/kernel.elf` mtime is fresh. Tell-tale: a "release" boot showing debug-only klog traces (e.g. `[B288 dgram]`) means the artifacts are a stale debug kernel.

2. **imagectl reads the MAIN tree's `../kernel/target/artifacts`, not a worktree.** `KERNEL_DIR=<worktree>` does not change which kernel boots. Boot-verify centrally in the main tree (on the integrated branch); subagents do code + hosted tests in worktrees and must `md5`-copy their kernel into `../kernel/target/artifacts` if they need to boot it.

3. **Single boots LIE about intermittent bugs.** An intermittent SEGV/wedge that fires ~half the time will "reproduce" or "vanish" on any one boot, so a one-boot-each A/B falsely attributes it to whatever you changed. We reverted a good branch on a single-boot false-positive. Measure intermittent failures over **N sequential boots** (report clean/total) before attributing, reverting, or declaring fixed. A causality test (hosted, deterministic) beats any boot count.

4. **When a boot result contradicts strong evidence, suspect the MEASUREMENT first, not the conclusion.** An agent's 3/3 clean boots + a failing→passing causality test outweigh one local SEGV — which turned out to be a stale-artifacts boot (lesson 1). Investigate the harness before re-opening a closed fix.

5. **Boot-verify after EVERY merge — hosted tests cannot catch runtime/ABI/integration bugs.** Two fixes that passed their full hosted gate broke the actual boot (an inode `fsid` that's a struct field instead of a dynamic call; a sysfs change that made a userspace process busy-spin). Only a real ISO boot exposes these. Pair it with: verify **both arches build + `cargo test` 0-failed BEFORE any push** (a rushed merge once broke MS_REC + compile). The "main is always known-good" invariant is what makes a bad merge a fast `git revert`, not a debugging session.

6. **Disprove-don't-hack, with evidence.** The hardest bugs were mis-framed for multiple sessions (the COW corruption chased as a "refcount under-count" when the invariant harness was green all along — the real bug was `MAP_SHARED|ANON` COW-split on fork). An agent that returns "I disproved hypothesis X, here's the evidence, here's the narrowed suspect" is worth more than one that ships a plausible patch. Never re-enable a previously-reverted hack blindly; find the correct mechanism (e.g. a real shmem backing, not in-place writable COW).

7. **The Bash sandbox cannot kill processes** (`kill`/`pkill` silently fail, even with sandbox disabled). So **never launch background boot retry-loops** — they spawn `qemu-system` you cannot reap, which then foul every subsequent boot (port/resource contention → GRUB-hang). Run single or strictly-sequential boots; if stale qemu accumulate, ask the user to `pkill -9 qemu-system`.

8. **A flaky ~8-line "boot" is a GRUB hang, not a result.** ~half of cold boots stall at GRUB with no kernel output. An 8-line log proves nothing; a real boot is >2000 lines. Re-run once.

9. **A REFCOUNTED kernel RAM frame shared into userspace MUST map as `VmaBacking::KernelFrame`, NEVER `PhysRange`.** `PhysRange` (`map_phys_range`, `remap_pfn_range` semantics) is for UNREFCOUNTED device memory (`/dev/fbN`, scanout): it installs the user PTE with "no PMM frame, no copy, **no refcount**" — it does not `inc_ref` the frame or bump its mapcount, so the mapping is invisible to the frame's lifetime accounting. If you back a real refcounted RAM page (`alloc_object_frame`) with `PhysRange`, the owner dropping its ref (e.g. closing the fd) frees the page **while userspace still maps it** — a free-while-mapped UAF: kalloc recycles the freed frame into a heap arena and the still-live user PTE's writes corrupt the kernel heap with *incidental* values (whatever userspace writes), crashing a random, unrelated victim (`Dentry`, `HoleHdr`, a registry `Weak`) at a random later time — the exact "non-deterministic wild write, unrelated victim" shape. `KernelFrame` (`map_kernel_frame`) `inc_ref`s on fault and the AS-teardown/`munmap` path `dec_ref`s, so the page is freed only once BOTH the owner drops its ref AND every mapping is gone (Linux `vm_file`-reference semantics). Found the hard way: io_uring mapped its refcounted ring page as `PhysRange` (B1342). **Audit every `glue_mmap(..., phys_base=Some(pa), ...)` / `PhysRange` site: is `pa` device MMIO (OK) or refcounted RAM (must be `kframe`/`KernelFrame`)?** Corollary: `map_phys_range`'s "no refcount" also defeats `release_frame_on_zero`'s never-free-a-mapped-page guard (mapcount stays 0), and the `debug-cow` `[COW-LEAK]` free-while-mapped detector is the tool that catches this class.

10. **The buddy allocator ZEROS every page on alloc (`buddy/api.rs`), which wipes write-while-free poison before any downstream check runs.** The `debug-cow`/`debug-watchdog` `0xCC`/`0xAA` poison-on-free + write-while-free detectors in `frame_alloc.rs`/`contig.rs` are therefore **defeated for the page body** — they run *after* the buddy zeroed it, so they only ever see zeros. (Also: `mm-pmm` has **no** `debug-watchdog` feature declared, so those `#[cfg(feature="debug-watchdog")]` blocks are phantom dead code — an `unexpected_cfgs` warning, silently compiled out.) `verify_poison` only covers the 16-byte free-list header, not the body. To actually catch a body write-while-free you must check **inside `alloc_inner`, before the zero loop** — the one point the evidence survives. Don't trust "the poison detector didn't fire" as proof of no write-while-free until you've confirmed the detector runs before the zeroing.

11. **The ~90%-boot heap corruptor is a CPU stale-KERNEL-pointer write into the STATIC kalloc heap — device DMA, userspace double-map, and buddy overlap are all RULED OUT (proven, not theorized).** Classify the victim before theorizing: enable `[KALLOC] corruption-probe` on the fast `debug-dealloc-diag` profile (C202 wired it there; heappoison hides the bug) — it resolves the corrupt free-list node's PA and reports its struct-page (`refcount`/`mapcount`/MANAGED). RESULT across boots: the corrupt nodes are consistently in the **static heap** (`ffffffff81xxxxxx`, the 64 MiB `STATIC_HEAP` BSS in `kalloc/lib.rs`), and probe as **`refcount=0 mapcount=0, not-pmm-managed (reserved kernel-image frame, never seeded into the buddy)`**. That trio is decisive: *not-pmm-managed* ⇒ no device can be handed the frame (never in the buddy) and it's not a buddy double-alloc; *mapcount=0* ⇒ no userspace/foreign mapping reaches it (kills the double-map/wild-cross-write hypothesis). So the writer is **kernel code holding a `*mut` into a freed static-heap block and writing it after free** — a pure CPU UAF, value incidental. **Retracted:** the earlier "virtio used-ring UAF" reading (a corrupt header `bad_next=0x300000000 node_size=0x200000000` decoding as a `vring_used`) was **over-fitting one sample** — other boots show `size=0`, `0xaaaaaa`, `0x80ffb180ffffffff`, none used-ring-shaped; and `release_transport_record` (the theorized ring-free path) is **never called during boot** (traced: 0 `[VRING-FREE]` hits), while a recycled ring frame would land in a GROWN HHDM region (`ffff8000…`), NOT the static heap. The `X<<32` values are just small incidental integers in u64 high halves. `[ZRAM-SYSFS] disksize=` clustering is the detection point (heaviest alloc burst), not the corruption point.

12. **FREE-IP PROVENANCE names the corruptor's free-site deterministically — the ~90% corruptor is a stale raw-`Arc` REFCOUNT op on a recycled `ArcInner`, class-confirmed.** kalloc records each block's last `caller::dealloc_return_ip()` in a `base→free_ip` ring (`holes.rs` `FreeIpRing`, C204, `any(debug-heappoison, debug-dealloc-diag)`); every corruption-detection site prints `[KALLOC] corrupt-node last-free-ip base=… free_ip=0x…`. Since the corrupt node is FREE when detected, its last free-IP names where the WRITER's victim was freed → `addr2line` → the Drop glue → the victim type. RESULT (cracked a multi-session mystery in one boot): free_ip → **`vfs::fdtable::model::FdTable::close`** (the `drop(f)` → `File::Drop`). So the corrupt block is an **`ArcInner<File>`** (strong@0, weak@8, data@16). Combined with kalloc's `HoleHdr{size@0, next@8}`: the corrupt `next@8` (`0x…819a1460`) is kalloc's OWN free-list link (a real hole), NOT an external pointer write; the DAMAGE is at `size@0` = the freed ArcInner's old strong-count word, overwritten to a count-like value (`0x1FFFFFFFF`/`0`/`0xaaaaaa`). ⇒ the corruptor is a **stale `Arc::increment_strong_count`/`from_raw`/manual refcount write** on a raw pointer to a freed-and-recycled block — the victim varies by layout (an `ArcInner<File>` this run) but the free-IP is stable, so the DAMAGE class is fixed. There is NO raw `Arc<File>`/`*const File` refcount machinery in vfs/fs/net/mm (grep clean); ALL manual raw-Arc machinery (`Arc::increment_strong_count`+`from_raw`) is on **Task/AddressSpace/AnonVma/FileRmap/Tty in `sched`/`mm`** (`live/wait_list.rs`, `runqueue.rs`, `schedule/{active_mm,switch}.rs`, `zombies.rs`, `futex/wait.rs`). **B1345 fixed one instance** (msleep leaked a one-shot → `wake_all` on a freed stack WaitList); ≥1 more stale raw-Task/AS-Arc op remains. **Method reuse:** to name ANY UAF's victim allocation, capture the free-IP at dealloc and print it at the detector — free-IP names the freer even when the writer is elsewhere. To name the WRITER, pin/rotate the `debug-hw-watchpoint` (C203 killed its false-positive storm) on close-freed blocks. Verification is now deterministic: a real fix makes the `FdTable::close` free-IP stop appearing on corrupt nodes.

## Claim work before starting (HARD RULE — no duplicate lanes)

Two agents independently rewrote the SAME mount subsystem item (the `mounted_mounts`
dual-truth removal) in two branches at once — hours of wasted, conflicting work.
Never again. Before writing ANY code for a ledger item / D-item / subsystem task:

1. **Check for an existing lane FIRST — three greps, every time:**
   - `git worktree list` and `git branch -a` — is there already a branch/worktree whose name or title covers this item?
   - `grep -n "<item-id>" fix-ledger.md` (and any `*-ledger.md`) — is the row already marked IN-PROGRESS / claimed / has a branch SHA next to it?
   - For mount/vfs/sched core work, grep the source for the symbol you intend to add (e.g. a helper name) — if it already exists on another branch's diff, someone is on it.
2. **If a lane exists, DO NOT open a parallel one.** Either continue that lane (its worktree; resume its agent via SendMessage; or take it over and finish it), or pick a DIFFERENT unclaimed item. Duplicating a live lane is the single most expensive mistake in this repo.
3. **Claim it before you start.** Mark the ledger row `[CLAIMED <branch> <date>]` (or add the branch name to the row) and commit that claim, so the next agent's grep in step 1 sees it. Release/flip to DONE on merge.
4. **After any agent wave, before boot-verify: re-check `git -C <main-tree> rev-parse HEAD` + `git branch -a` + `git worktree list`.** The shared main tree gets reset/advanced by concurrent lanes; a stale assumption about HEAD invalidates a boot result (you may boot a different lane's kernel — see Lessons §2).
5. **One item = one lane = one agent.** If you discover mid-task that you've duplicated a live lane, STOP, preserve your commit on a branch, and reconcile with the owning lane rather than racing it to merge.
6. **Fan out independent work immediately.** When a task has two or more independently-owned subsystem areas, assign them to separate agents before implementation: one owner per file area, one integration owner, and explicit handoff evidence (tests + file list). Do not serialize independent investigation, implementation, or test-design work while capacity is available; do not overlap ownership merely to increase agent count.

## Git workflow (mandatory)

**Commit author (HARD RULE).** Every commit + PR is authored by **`Chris Watkins <chris@watkinslabs.com>`** — period. This is the only valid author identity. Before committing in any clone, ensure `git config user.name "Chris Watkins"` and `git config user.email "chris@watkinslabs.com"` are set (a fresh clone may have `user.name` unset, which produces garbage authors like "Ablative Personality" — fix it first). Never let any other name/email land on a commit or PR.

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

**Counters live in `metadata/index.md` — HARD RULE, never invent them.** The repo is ~4000 commits in (`F` is in the 400s, `B`/`D` in the 90s–110s). Before creating a branch of type `<T>`, read the `next` value for `<T>` in `metadata/index.md`, name the branch with it, then INCREMENT that line and commit `metadata/index.md` (same PR or a tracking commit) so the next branch/run is correct. Guessing a counter (e.g. `F30`) produces garbage, non-sortable names that collide with real history.

**Short-lived feature branches (HARD RULE).** Every feature / bug / doc change gets its own fresh branch from current `origin/main`; no omnibus branches and no long-running catch-all worktrees. Finish one feature, commit it, push it, open/merge the PR, then delete the local branch and worktree before starting the next feature. Refactors are features too: isolate them on their own branch instead of mixing cleanup with driver work, and never continue piling new work onto a dirty or conflicted branch. If a branch becomes misshapen, stop, preserve it with an archive tag, and cherry-pick the still-valuable commits onto clean one-feature branches.

**Feature worktree loop (HARD RULE).** For every feature/bug/doc item: pull/fetch clean `main`, create the numbered branch in its own worktree from current `origin/main`, do the work there, commit, push, open the PR, merge it, pull/update main, then start the next item from a new worktree. Do not reuse a feature worktree for the next item. Remote CI/CD smoke is not required before merge; run only the local verification needed for the touched files, and use `SKIP_SMOKE=1` for doc-only pushes.

**Phase prefix MUST match `00§3` master-plan phase.** `P<n>-` means phase-`n` per the master-plan §3 table (0=build infra, 1=PMM, 2=VMM+MMU, 3=slab, 4=sched+ctxsw+preempt+SMP, 5=syscalls+ELF+init+bash, 6=VFS+ext4 RO, 7a=block+pagecache, 7b=ext4 RW, 8=net, 9=hardening, 10=modules loader, 11=PCI enumeration, 12=virtio common, 13=dynamic linker, 14=libc/NSS/PAM, 15=system manager, 16=RPM toolchain, 17=tty + login). Rotate the prefix when crossing a phase boundary; do **not** keep using the old phase number as a generic counter. Counter resets to `01` per phase. Example: when phase 4 work begins, branches restart at `P4-01-...`, regardless of how high the `P3-` counter went.

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

**Push policy.** Auto-push every feature branch with `-u` as soon as its focused commit is made; do not hold local-only work across features. Auto-push merged commits to `origin/main` after each merge without asking. Force-push remains forbidden per the Never list below.

**PRs (mandatory).** Every branch merges to `main` via `gh pr create` then `gh pr merge --merge --delete-branch=true`. No local `--no-ff` merges to `main`. PR-time CI per `docs/40§2` is the gate; until CI exists, manual review then merge. Delete remote + local branch on merge — keeps the branch list clean. Git history (the merge commit) preserves recoverability.

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

**Branch retention.** Delete branches on PR merge (remote via `gh pr merge --delete-branch=true`, local via `git branch -D <name>`), then remove the local worktree. Don't accumulate stale post-merge branches or parked local worktrees. Unmerged branches: keep until they're explicitly abandoned; never `git branch -D` an unmerged branch without confirmation.

## Plans live in scratch/ (HARD RULE)

Every plan / analysis / ledger doc (`*fix.md`, `*-plan.md`, audit writeups, compliance
ledgers) goes in `scratch/`, never the repo root or `docs/`. `docs/` is specs only. Each
plan carries a **Status** first column and a **Branch** column per work item, updated as
lanes are claimed / merged.

## state.md is short-lived session memory, not history

`state.md` is the hand-off note from the previous session — what
was worked on, what's open, what to pick up next. It is NOT a
running log, NOT a session journal, NOT a place to accumulate
session-by-session reports.

Rules:
- **Hard cap 200 lines.** If it grows past that, you're doing it wrong.
- **Overwrite, don't append.** Each session replaces the file with a fresh hand-off — no "Below this line is session N-1" appendix.
- **Headline + open work + first task.** Branch + PR, what got done, what's still open, the literal first command for next session. Nothing else.
- **No "session 53/54/55" archaeology.** Git log is the archaeology.
- **No commit-message duplication.** Cite SHAs, don't restate.
- Persistent project knowledge (architecture decisions, conventions, gotchas that survive across sessions) goes in CLAUDE.md or auto-memory, not state.md.

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
