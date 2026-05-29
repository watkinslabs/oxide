# Session hand-off — 2026-05-29

## TL;DR
Autonomous run: build the FULL production distro (drop-in Linux,
systemd PID1, RPM pkg mgr, real multi-user) and validate end-to-end
on both arches. Stale D6/D7 roadmap replaced with a comprehensive
production plan in **TASKS.md**. Research cached in `research/`.
Now executing **Track K** (kernel prerequisites for systemd),
starting **K1: cgroup v2**.

## What just happened (this session)
- 3 parallel research agents produced: `research/systemd-musl.md`,
  `research/kernel-gaps-systemd.md`, `research/distro-inventory.md`.
- Rewrote TASKS.md into Tracks K (kernel prereqs) → L (shared libs)
  → D6 (systemd) → D7 (drop busybox) → P (RPM, multi-user, etc.).
- Key facts: systemd v259 builds on musl (`-Dlibc=musl`); MUST link
  dynamically (oxide2 is static-musl today → need shared lib tree).
  Kernel blockers: cgroup v2 (none), real mount (only tmpfs), per-ns
  mount tables (CLONE_NEWNS id-only). Specs 26/16/27/19 all FROZEN.

## First task next session — K1 cgroup v2
Implement to FROZEN spec `26-namespaces-cgroups.md`. Real cgroupfs at
`/sys/fs/cgroup`: controllers cpu/cpuset/io/memory/pids; files
`cgroup.procs`/`threads`/`controllers`/`subtree_control`/`events`(populated
notify)/`kill`/`freeze`/`stat`; real `/proc/<pid>/cgroup`.
- Existing stub: `crates/kernel/nscg/src/lib.rs` (v1 pid_ns+user_ns only).
- Fake mount: `kernel/src/syscalls/mount.rs:59` noops cgroup2.
- Hardcoded stub: `kernel/src/procfs/static_files.rs:55` `/proc/self/cgroup`.
- First command: `cargo run -p xtask -- spec-lint | tail -1` (confirm
  clean) then read docs/26 cgroup sections, then `git checkout -b
  F265-cgroup-v2` (or P-prefix after phase re-audit).

## Branch / PR state
- This branch `D06-distro-prod-plan`: planning docs only (TASKS.md,
  research/, state.md). PR + merge, then start F265-cgroup-v2.
- main @ e6ef1abe (D5 iputils #1347 merged). No other open PRs.

## Hard-won workflow notes (carry forward)
- **One simple shell command per Bash call.** Don't bundle many as
  parallel calls (one non-zero exit cancels the batch). Don't chain
  git with `;`/`&&` to non-git tools (breaks `Bash(git:*)` matching).
- Tool-output DISPLAY intermittently corrupted/delayed this session
  (doubled/blank/stale). Edit's exact-match + `git status` are ground
  truth; re-read narrowly if an Edit "string not found".
- rootfs `.img` rebuilt non-deterministically each kernel build —
  discard image churn, don't recommit.
- CHANGELOG.md stale past ~Session 47; state.md + git log are the record.

## Direction reminders
- Production drop-in Linux distro on musl. No hacks/stubs/placeholders.
- Fix each kernel gap in the SAME PR that surfaces it.
- Each task = own PR, both-arch boot smoke, spec-lint clean, branch
  deleted on merge. Autonomous: don't stop at phase seams.
