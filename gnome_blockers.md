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
- **G5 (accounts-daemon 226/NAMESPACE) — ✅ FIXED:** root cause was `/` owned by uid 1000 (rootless-build ownership loss), not a kernel/executor bug; imagectl now packs the rootfs root:root (82ec9c2). Boot-verified: unsafe-transition + accounts-daemon failures gone.
- **G6 (current frontier): gdm launches no greeter session** — seat0 created but likely not graphical (master-of-seat/CanGraphical). Needs clean boots.
- **G3 = env constraint:** sandbox boots are slow when KVM is contended; a concurrent agent churning the shared image + KVM is currently blocking clean iteration on G6.
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
| G5 | accounts-daemon `226/NAMESPACE` + `Detected unsafe path transition / (owned by 1000) → /run (owned by root)` | **✅ ROOT-CAUSED + FIXED + boot-verified** | oxide-images 82ec9c2 (local, no remote) | **ROOT CAUSE (debug-mnt capture):** the ext4 rootfs root inode (`/`, inode 2) was owned by **uid 1000**, not root — the rootless build flattens the work tree to the builder's uid (`chown_tree_to_user`) and `populate_ext4_mounted`'s `cp -a` preserved it. systemd's `CHASE_SAFE` path canonicalization correctly REFUSES to traverse a non-root-owned `/` into root-owned `/run` → breaks RuntimeDirectory + every service's mount-ns setup → accounts-daemon 226/NAMESPACE, gdm-session-worker. **NOT a kernel bug** — systemd/kernel behave correctly; the IMAGE was wrong (real Linux `/` is root:root). **Fix:** `populate_ext4_mounted` packs with `tar --owner=0 --group=0` (root ownership, preserves setuid modes). Boot-verified: `unsafe path transition` 0, accounts-daemon FAILED 0 (both present every prior boot). Also needs the full desktop package set (G6). |
| G6 | gdm starts + logind creates seat0 (**CAN_GRAPHICAL=1**), but **no greeter session** (no gnome-shell / gdm-session-worker fork; gdm goes idle, produces zero journal output even with [debug]Enable=true) | **OPEN — downstream of G7** | — | Ruled OUT the seat-graphical theory: debug-session capture shows `/run/systemd/seats/seat0` has **CAN_GRAPHICAL=1** — the seat IS graphical. gdm starts (t~80s), forks exactly one child (exits fast), then idles to timeout with no greeter and no logs. The "Failed to update monitor information: Protocol not available" is **systemd-resolved** (netlink `ENOPROTOOPT`), a red herring. Prime suspect = **G7** (systemd thinks it's a container → gdm won't create a local graphical display). Revisit after G7. |
| G7 | systemd misdetects virtualization as **`container-other`** (should be qemu/kvm) | **✅ ROOT-CAUSED — next impl target** | — | **Confirmed via debug-openat trace:** systemd's `detect_vm()` reads `/sys/class/dmi/id/{sys_vendor,product_name,board_vendor,bios_vendor}` + `/sys/firmware/dmi/entries/0-0/raw` to identify QEMU — but **oxide exposes NO DMI/SMBIOS at all** (grep: no dmi/smbios anywhere in kernel). So detect_vm returns NONE → systemd falls through to `detect_container()` → `Detected virtualization container-other`. Cascade: plymouth-start + 6 other `ConditionVirtualization=!container` units skipped, and gdm/session components behave as if headless-in-a-container (the likely G6 cause). **Linux-correct fix (no stub): parse the qemu SMBIOS tables and expose `/sys/class/dmi/id/*` + `/sys/firmware/dmi/entries/*/raw`.** Impl: x86 = scan phys 0xF0000–0xFFFFF for `_SM_`/`_SM3_` anchor (or multiboot2 SMBIOS tag 13) → parse type 0/1/2/3 → strings; aarch64 = EFI SMBIOS3 config table (lockstep). New `firmware/src/smbios.rs` + a sysfs dmi class. This is the concrete next build. |
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
