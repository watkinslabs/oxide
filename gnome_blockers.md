# GNOME login blockers — working log

Goal: full GNOME graphical login on the live-gnome boot. Every blocker fixed the
Linux-correct way (real semantics, no stubs/hacks). One blocker = one branch =
one PR (worktree off fresh `origin/main`; PR smoke-test skipped per directive).

Method: capture-first (`debug-stderr`/`debug-eacces`/targeted probes), implement
real Linux behaviour, boot-verify on live-gnome. Concurrent agent works the
kernel driver lane — always fresh main + isolated worktree.

## Status legend
`INVESTIGATING` · `FIX-IN-PROGRESS` · `PR-OPEN` · `DONE` · `BLOCKED`

## Blockers

| # | Blocker | Status | Branch / PR | Notes |
|---|---------|--------|-------------|-------|
| G0 | `debug-stderr` visibility probe (echo userspace fd==2 → console) | **DONE** | B596 #2716 (merged) | Enabled capturing gnome-shell's death message. Also fixed debug-atexit `VmaProt` build break. |
| G1 | gnome-shell greeter exits code=1 — `Failed to find any matching session` (from libmutter) | **✅ DONE + BOOT-VERIFIED** | c43e148f (PR #2741) | **ROOT CAUSE (debug-cgroup + debug-dbus wire trace):** a `CLONE_THREAD` child was stamped a FRESH distinct `vtgid` instead of sharing the leader's, so every mutter worker thread carried its own visible PID. GDBus does socket I/O on a worker thread → `SO_PEERCRED`/`getpid()` reported the worker's pid `W` (not the process pid `V`). logind's `GetSessionByPID(0)` → caller creds `W` → `/proc/W/cgroup` → `cgroup_of(worker tid)` = **`0::/` (root)** (only the leader tid is in `proc_cg`) → `NoSessionForPID` → mutter "Failed to find any matching session" → code=1. **Fix (3 layers, Linux-correct):** (1) `056_clone.rs` CLONE_THREAD shares leader `vtgid` (threads report process PID; distinct `vtid`=gettid); (2) `registry.rs` `lookup_by_vpid` resolves a process vpid to the thread-group LEADER (`vtid==vtgid`); (3) `procfs/cgroup_file.rs` resolves any thread tid→tgid before rendering `/proc/<pid>/cgroup`. **Boot-verified: NoSessionForPID 100%→0, no gnome-shell code=1, no "matching session" error.** NOT a GPU/logind-state/sd-login-file problem (all proven correct via disassembly + debug-session). |
| G3 | Intermittent early boot wedge (~t=7–21s, systemd stalls, no progress) | **INVESTIGATING** | — | Pre-existing "intermittent early busy-spin wedge" (campaign notes). A/B confirmed: origin/main (no G1 fix) + debug-stderr wedges at t=7.5s; G1-fix build wedges at t=21s; debug-cgroup build (different timing) reaches t=135s. Timing-sensitive → NOT the G1 fix. Blocks clean greeter-render verification. Next: capture the wedged task set (debug-watchdog / sysrq task dump) at the stall. |
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
