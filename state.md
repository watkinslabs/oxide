# Session hand-off — SMP done; vendor-app buildout in progress (autonomous /loop)

Driving `smp-distro-plan.md` as a self-paced /loop. Merge on local-green
(= CI-green here: build both arches + hosted tests + spec-lint, all local;
pre-push hook runs SMP=2 smoke). Merge with `--admin` (no CI wait).

## DONE this session (PRs #1662–#1686, ~20 PRs)
- **SMP scheduler rework COMPLETE** (Phase A/B + Phase C core): both arches
  boot SMP=2 to login, online=2, APs run migrated user tasks. One switch
  engine + per-task IRQ, rq-lock-across-switch + deferred reap, x86+arm AP
  scheduling, ttwu wake-placement + resched IPI, affinity relocate, newidle +
  cache-hot balance, on_cpu handshake. sched miri-clean. (Phase C remaining
  irqsave/loom = §E, no active bug.)
- **Syscall coverage**: tools/syscall-audit.py green (383/384 routed);
  uretprobe→SIGILL, map_shadow_stack→ENOSYS(no-CET), removed bogus NR_UPROBE;
  listns→§E (ns registry).
- **Box B cleanups**: dropped "Tier 1/2/3" jargon → roles; busybox scrubbed.
- **Box C distro**: login-shell sourcing, python3 encodings, stty — all
  VERIFIED + gated in boot-smoke-login.sh. Phase 15 net substantively met
  (oracle/lo/loopback); rtnetlink ip-dump → §E. Phase 16 real-ns → §E.
- **Box D vendor apps**: base set + 24 broader apps VERIFIED running both
  arches (rg/fd/jq/bat/eza/curl/wget/tmux/htop/btop/dust/procs/sd/delta/…),
  gated (BASEAPPS=5).
- **3 KERNEL BUGS fixed (Go/Rust app-hang thread)**: (1) timerfd ignored
  TFD_TIMER_ABSTIME (#1684), (2) sys_exit clear_child_tid #PF crashed the
  kernel on threaded exit (#1684), (3) EpollInode had no poll() → nested epoll
  always-ready → parent epoll spun (#1686). micro/glow/starship now RUN both
  arches, gated GOAPPS=2. Likely unblocks a CLASS of epoll-nesting/async apps.

## NEXT — highest-value remaining (all substantial/focused)
- More vendor apps: NEW ones (zip/unzip/dash/zsh/fish/neovim/tig/…) need
  fetch+build infra written (no fetch scripts yet; all easy ones vendored).
  Re-verify vendored TUI/async apps now that epoll-nesting works.
- §E rtnetlink ip-dump fix (`ip`/`ss` truncate — "Dump terminated"; recv/build
  paths look correct; needs raw-netlink-byte trace).
- §E duf scan loop (duf-specific; openat+name_to_handle_at+statx never
  terminates — readdir-no-EOF or mountinfo re-scan).
- §E Phase 16 real namespaces; Phase C irqsave/loom hardening.

## DEBUG RECIPES (carry forward)
- SMP=2 boot: `OXIDE_SMP=2 ./tools/boot-smoke.sh x86 300` (BARE command —
  pkill prefixes abort the line under set -e). arm: `... arm 400`.
- Stress: `MAXBOOTS=12 python3 /tmp/diag-hang-mon.py` (rebuilds ISO,
  hypervisor-monitored boots). Run stress + smoke SEQUENTIALLY (qemu contends).
- Syscall trace: build/boot FEATURES=debug-syscall → `[SYS] pid=.. nr=.. a0..a2`
  per entry (a0 ambiguous across syscalls — fd vs signal/count).
- epoll readiness trace: klog in epoll.rs scan_once logging the reported fd's
  ino (high byte = type: 0x10 pipe, 0x40 eventfd, 0x71 inotify, 0x72 signalfd,
  0x73 timerfd, 0x74 epoll).
- App-run gate: BACKGROUND the app + file-check + computed marker (VAR=$N,
  expands only in OUTPUT) — NEVER a foreground `timeout` (unkillable spin
  blocks it) or a literal marker (the wait_for echo false-matches it).
- ISO rebuild: `xtask grub --arch x86_64 --build-only`. Multi-line commit: -F.
