# GNOME login blockers — working log

Goal: full GNOME graphical login on the live-gnome boot. Every blocker fixed the
Linux-correct way (real semantics, no stubs/hacks). One blocker = one branch =
one PR (worktree off fresh `origin/main`; PR smoke-test skipped per directive).

Method: capture-first (`debug-stderr`/`debug-eacces`/targeted probes), implement
real Linux behaviour, boot-verify on live-gnome. Concurrent agent works the
kernel driver lane — always fresh main + isolated worktree.

## Current status (2026-07-06)
Progress toward full GNOME login, in order:
- **G1 (fatal, session lookup) — ✅ FIXED + merged (c43e148f #2741) + boot-verified** (NoSessionForPID 100%→0; gnome-shell no longer code=1).
- **G4 (gdm code=1 = missing /usr/bin/plymouth) — ✅ FIXED** in the image builder (oxide-images 404d6a5) → gdm now stays up.
- **G5 (next gate): `gdm-session-worker` code=265 loop + accounts-daemon NAMESPACE `/run/systemd/seats`** — the executor/mount-ns area. Kernel-side, OPEN.
- **G3 = env constraint:** this sandbox runs boots ~20× slower than realtime → greeter-render iteration is impractical here; verify on a real box (`make live PROFILE=live-gnome MEM=6G`).
Diagnostics landed: #2716 (debug-stderr), #2723 (debug-session), #2744 (debug-dbus/debug-cgroup).

## Status legend
`INVESTIGATING` · `FIX-IN-PROGRESS` · `PR-OPEN` · `DONE` · `BLOCKED`

## Blockers

| # | Blocker | Status | Branch / PR | Notes |
|---|---------|--------|-------------|-------|
| G0 | `debug-stderr` visibility probe (echo userspace fd==2 → console) | **DONE** | B596 #2716 (merged) | Enabled capturing gnome-shell's death message. Also fixed debug-atexit `VmaProt` build break. |
| G1 | gnome-shell greeter exits code=1 — `Failed to find any matching session` (from libmutter) | **✅ DONE + BOOT-VERIFIED** | c43e148f (PR #2741) | **ROOT CAUSE (debug-cgroup + debug-dbus wire trace):** a `CLONE_THREAD` child was stamped a FRESH distinct `vtgid` instead of sharing the leader's, so every mutter worker thread carried its own visible PID. GDBus does socket I/O on a worker thread → `SO_PEERCRED`/`getpid()` reported the worker's pid `W` (not the process pid `V`). logind's `GetSessionByPID(0)` → caller creds `W` → `/proc/W/cgroup` → `cgroup_of(worker tid)` = **`0::/` (root)** (only the leader tid is in `proc_cg`) → `NoSessionForPID` → mutter "Failed to find any matching session" → code=1. **Fix (3 layers, Linux-correct):** (1) `056_clone.rs` CLONE_THREAD shares leader `vtgid` (threads report process PID; distinct `vtid`=gettid); (2) `registry.rs` `lookup_by_vpid` resolves a process vpid to the thread-group LEADER (`vtid==vtgid`); (3) `procfs/cgroup_file.rs` resolves any thread tid→tgid before rendering `/proc/<pid>/cgroup`. **Boot-verified: NoSessionForPID 100%→0, no gnome-shell code=1, no "matching session" error.** NOT a GPU/logind-state/sd-login-file problem (all proven correct via disassembly + debug-session). |
| G3 | Sandbox boots run ~20× slower than realtime (TCG/CPU-throttle) | **ENV CONSTRAINT (not a bug)** | — | Measured: 203s wall for 9.7s guest time even with KVM free + 6G RAM. The earlier "t=7–21s wedge" was this slowdown (boots timing out mid-progress) + a concurrent rogue agent stealing /dev/kvm — NOT a guest wedge. Reaching the greeter (guest t~76s) needs ~25 min/boot here → greeter-render verification is impractical from this sandbox. Verify on a real box: `make live PROFILE=live-gnome MEM=6G` (or a headless serial capture with a 900s+ timeout). |
| G4 | `/usr/bin/gdm` exits code=1 on `execve = -2` (ENOENT) at t~12s | **✅ FIXED (image)** | oxide-images 404d6a5 (local, no remote) | The missing exec target was **`/usr/bin/plymouth`** (gdm forks/execs it for the boot-splash→greeter transition; `@gnome-desktop` didn't pull it into the minimal image). Added `plymouth` to `imagectl/src/main.rs` `GNOME_PACKAGES`; with it, gdm starts and STAYS up (no more code=1). NOTE: `configs/live-gnome.toml` `packages` is a DEAD decoy — imagectl uses the compiled-in `GNOME_PACKAGES` static, not the TOML (hardcoded antipattern; wire imagectl to read the TOML later). Also bumped default guest RAM 2G→6G (Makefile + oneboot.sh) to stop the host SIGKILL under llvmpipe. |
| G5 | `gdm-session-worker` exits code=265 in a loop (gdm respawns) + `accounts-daemon` fails **step NAMESPACE — /run/systemd/seats: No such file or directory** | **OPEN — next kernel gate** | — | With G4 fixed, gdm now advances to launching the greeter via `gdm-session-worker`, which loops on code=265 → no session established. Alongside: `systemd-logind.service` declares `RuntimeDirectory=systemd/sessions systemd/seats systemd/users …` and `accounts-daemon.service` bind-mounts `/run/systemd/seats/` in its sandbox → mount-ns setup fails because that dir is missing/invisible inside the private mount-ns. This is the long-standing **executor-spawn / mount-namespace** area (cleanupv2 1.2; campaign "executor-spawn ESRCH / 226-NAMESPACE"). Kernel-side, `crates/kernel` branch. The G1 vpid/cgroup fix will matter here once the session-worker can establish a session. Needs boot diagnosis (fails early ~t20s, reachable even on slow boots). |
| G2 | `user@979` session-bus `org.freedesktop.systemd1` activation times out (120s) | INVESTIGATING | — | gnome-session can't reach its `systemd --user` manager over the session bus. May share a root with G1 or be independent. |

## Red herrings (proven non-fatal — do NOT chase)
- `openat=-13 EACCES code=70` frontier note: the EACCES hits are `/etc/ld.so.cache`
  (0600 root → loader fallback), `/dev/console` (uid-979 write), cgroup `init.scope`
  resource files (systemd --user delegation warnings), `/proc/self/oom_score_adj`.
  None crash gnome-shell.
- GPU / "mutter couldn't detect graphical desktop": DISPROVEN. card0 is fully functional.

## Evidence anchors (2026-07-06 fresh post-B580 capture)
```
[STDERR gnome-shell] Failed to setup: Failed to find any matching session  → code=1
gnome-session-binary: Could not get session id for session. Check that logind is
                      properly installed and pam_systemd is getting used at login.
gnome-session-binary: …StartServiceByName for org.freedesktop.systemd1: Timeout was reached
logind: New seat seat0 / New session c1 of user gnome-initial-setup / New session c2
```
