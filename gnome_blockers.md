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
| G1 | gnome-shell greeter exits code=1 — `Failed to find any matching session` (from libmutter) | **INVESTIGATING** | B599-gnome-session-diag | logind session state is **CORRECT** (captured via debug-session probe): `/run/systemd/sessions/c1` = TYPE=wayland CLASS=greeter SEAT=seat0 VTNR=1 ACTIVE=1 IS_DISPLAY=1 LEADER=161; `/run/systemd/users/979` = DISPLAY=c1 ACTIVE_SESSIONS="c2 c1" SEATS=seat0. So `sd_uid_get_display(979)`→c1 and c1 has seat+VT. Bug is **client-side in libmutter's sd-login session lookup** (string lives in libmutter-16.so). cgroup migration machinery proven correct (Explore). Disassembling libmutter for the exact sd_* call + condition. NOT a GPU problem. |
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
