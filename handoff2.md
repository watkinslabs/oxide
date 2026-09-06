# Native Notepad integration — 2026-09-06

First command: `git status --short --branch`

## Latest wave: desktop interchangeability and process identity

- User requires Windows apps alongside Linux apps under GNOME/KDE/JWM, and ordinary Linux task-manager visibility. masterplan and31gd now state desktop independence; X11/XWayland exists, native Wayland not claimed. Diagnostics corrected without changing startup hooks. KI0418 tracks missing application `_NET_WM_PID` association.
- KI0414 child naming wired: `nt_process_create::dispatch -> identity::publish`; Task/MM exe metadata and canonical exec comm basename. Fixture `cargo test -p syscalls --test native_process_identity`6 pass; generated actual hook removal fails. Full syscalls lib2425 pass. Initial PE metadata remains KI0417: Windows request path is not automatically a real Linux executable path; do not blindly reuse child helper there. Cmdline/MM argument bounds also missing.
- KI0416 canonical Unix pathname resolver now checks VFS MAY_WRITE before type check with current credentials. Standalone `tests/unix_resolver_permission`12 pass (5 resolver +7 errno); generated REMOVE_UNIX_DAC_HOOK=1 causes4 expected failures, restored12 pass. Latest production target checks x865.28s/ARM5.46s pass.
- KI0412 remains normal-user launch blocker: wrapper root-owned paths, native registry ignores selected socket, initial-root lookup and initial-netns connect.31ac frozen for per-user paths, shared daemon lifecycle and canonical admission. Existing service holds database sidecar flock; wrapper unlinks before that lock and kills shared service on one app exit. Real registryd lifetime test1 pass, isolated unlink control fails, restored1 pass. Test proves daemon locking, not repaired wrapper. Daemon serial serve-until-EOF can starve other clients.
- KI0413 remote NT process/thread open authorization bypass filed. KI0415 ledger-shape check fails nine existing FIXED-in-active rows; no archive cleanup/bypass performed. KI0408 evidence corrected: no pending scope choice or required separate logind broker.31fl root contract corrected to desktop-owned lifetime, not weak application-process lifetime; existing root helper still needs migration.
- Active worker Nash (`01a073a8-418e-7703-b5cd-6dcd6e8419f5`): implementing runtime `user_paths.rs` children under frozen31ac; main owns declaration/callsite/normal-launch wiring. Averroes (`01a07470-dc64-7671-961b-746833e99b73`) auditing real initial image provenance/procfs metadata next. Bernoulli finishing resolver fixture cleanup. Other bounded workers returned; desktop process-membership child changed but remains unwired and requires admitted handle candidates.
- Next integration: consume user-path helper in normal image launcher, preserve shared registry service, carry admitted endpoint into NT owner. Reuse repaired namei resolver; add explicit-network-namespace connection API preserving coredump's existing initial-namespace path. Registry keys/watches must retain correct service domain, not merely remote numeric key IDs. No guest boots or image staging yet.
- User-path review returned to Nash before wiring: replace create-then-pathname-chmod with atomic DirBuilder mode0700; handle EEXIST by validation; resolve HOME only when defaults need it; reject privilege mismatch; add symlink/NUL/relative/concurrent creation tests in children. These helpers do not pin VFS authority and must not be described as admission.

## Earlier verified foundation

- Branch D1550-notepad-masterplan, baseline586e5390e; attached HEAD. Large shared dirty tree belongs to ongoing work. No branch moves, commits, pushes, image staging or guest boots during this wave. Preserve untracked implementation children.
- Read CLAUDE.md before edits. No rustfmt; 500-line Rust cap; primary implementation verification before ABI changes; coordinator owns hooks. masterplan.md top checkpoint supersedes historical status below it.
- Notepad is NOT guest-verified. Default root image currently lacks `/usr/local/bin/windows-compositor`; read-only `python3 tools/windows-rootfs-payload-check.py --image target/builds/default/root-x86_64.img` rejects it. Current injector explicitly stages compositor and now calls post-staging payload gate before success.
- Payload fixture9 pass; validates PE identity, native ELF pair/export, links, launch metadata and native byte identity against selected staging inputs. Structural catalog check does not prove full transitive DLL closure. Existing separate ELF-dependency gate remains.
- Canonical GetDC leases, pens/regions, glyph-index text, shared DC zero-area encoding and geometry-only projection wired. Actual shared binding5 pass; glyph raw-to-renderer16 pass. IPC586 pass. DC query5 pass covers Notepad-required selectors1/2/9; other selectors not implemented.
- Native thread `lifecycle::prepare` inherits PROCESS DEFAULT desktop, not creator-selected desktop. Actual production standalone fixture2 pass; missing-hook control red/restored green. Typed desktop/station objects, global handle count and task/group fields integrated. Desktop root itself still unissued/unpublished.
- Get/Peek dispatcher flushes process-owned dirty GDI backing before idle/wait, with busy50ms policy. EndPaint/full-frame/erase share reservation/ACK owner. Stale acknowledgements cannot clear newer writes. Failed/Busy publication retains pending work. Raw EndPaint maps retained output to TRUE without claiming presentation or callback installation.
- Production output/message/erase/paint-reservation fixture75 pass; output13 pass. Erase and native paint rollback controls red/restored green. Position25 pass with isolated flags-hook control for NOREDRAW.
- EndPaint standalone removal-control under `crates/kernel/syscalls/tests/paint_pending_control`; coordinator removed pending hook in generated copy, observed expected failure, restored20 pass. Native inheritance control likewise red/restored2 pass.
- BeginPaint raw boundary20 pass. Production factory/live/callback-queue fixture19 pass: simulated Send paints two nonblack pixels, NC precedes ERASE, NULL output retains pixels before cleanup without usercopy; invalid pointer faults only after callbacks. No actual guest callback execution is claimed.
- Latest full syscall lib2425 pass after final BeginPaint changes. Both-arch debug-preempt checks passed latest production code: x864.96s/ARM4.94s. Warnings remain; these are not full feature/lint/boot gates.

## Open work

1. Probe build-path repair (KI-0411) wired: Cargo metadata resolves target directory, build receives it explicitly, staged artifact derives from same directory. Resolver4 real-workspace tests pass; explicit xtask test builds the real compositor in private target. Reintroducing default-cache path fails the build-boundary gate; correct hook restored. No image written.
2. User clarified one Oxide/Linux system, existing GNOME desktop, Windows apps alongside Linux apps. No scope question remains. Reference startup creates/opens logical station/desktop objects inside an authenticated runtime namespace; it does not establish a new logind broker prerequisite. Reuse existing compositor connection for presentation, Linux credential/pinned VFS identity for namespace admission, and canonical NT object/process owners. NT bookkeeping does not create another visual shell. Per-process HWND allocation/hierarchy still needs a shared canonical owner.
3. Connect authorized station/desktop issuance, process default/current thread attachment, real canonical root creation/publication, HWND0 resolution and shared GDI ownership. Children under `nt_window/desktop` remain unwired; helpers alone are not completion. No scope choice is pending. Desktop root must survive application-thread exit, unlike the present weak-process helper.
4. After mandatory chain and nonboot gates are green, rebuild the standard make qemu-x86 image and perform one final visible launch/type/close verification. Do not use boots to discover missing functions. Boot performance and ARM Windows execution remain unverified; KI-0388 tracks ARM continuation gap.

## Commands

```sh
CARGO_TARGET_DIR=/home/nd/oxide/kernel/target/codex-lanes/lsm cargo test -p syscalls --test nt_window_output_dispatch --test nt_gdi_output --test nt-wine-paint-boundary --quiet
CARGO_TARGET_DIR=/home/nd/oxide/kernel/target/codex-lanes/lsm cargo test -p syscalls --lib --quiet
CARGO_TARGET_DIR=/home/nd/oxide/kernel/target/codex-lanes/lsm cargo test -p ipc --lib --quiet
CARGO_TARGET_DIR=/home/nd/oxide/kernel/target/codex-lanes/compositor-integration cargo run --quiet -p xtask -- kernel --arch x86_64 --features debug-preempt --check
CARGO_TARGET_DIR=/home/nd/oxide/kernel/target/codex-lanes/compositor-integration cargo run --quiet -p xtask -- kernel --arch aarch64 --features debug-preempt --check
python3 tools/perf/test_windows_rootfs_payload_check.py
git diff --check
```

- Kernel xtask checks use shared internal target paths: run the two compile checks sequentially. Independent hosted lanes use separate CARGO_TARGET_DIRs.
- `tools/lane-health.sh` itself launches cargo builds, and its process/environment counts can misidentify contention. Inspect actual cargo command/target ownership before attributing a stall. Do not treat its count as scheduler/boot evidence.
- Known issue rows KI-0405 output,0406 handle lifetime,0407 geometry projection,0408 desktop authority,0409 image post-write gate,0410 BeginPaint ordering,0411 probe artifact path remain OPEN candidates until verified/committed. No FIXED SHA claimed.
