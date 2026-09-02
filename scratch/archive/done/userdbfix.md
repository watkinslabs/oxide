# Session hard-record — GPU/DRM driver + userdb + session-render frontier
Date: 2026-07-07. Target: fully rendered, usable GNOME greeter (gnome-initial-setup
wizard) on the live-gnome QEMU image (virtio-gpu). Kernel tree: /home/nd/oxide/kernel
(NOT a git repo here). Images: /home/nd/oxide/oxide-images.

===============================================================================
## WHAT WAS FIXED THIS SESSION (all land in the kernel tree, uncommitted)
===============================================================================

### 1. userdb / "Received too short user lookup message" — FIXED + VERIFIED (14 -> 0)
ROOT: `writev(2)` on an AF_UNIX SOCK_DGRAM/SEQPACKET socket emitted ONE datagram
PER iovec. systemd forks a service, the child sends its resolved identity back to
PID1 via `writev(user_lookup_fd, [uid(4)][gid(4)][unit_id(N)], 3)` on the
SOCK_DGRAM `user_lookup_fds` socketpair. Per-iovec datagrams => PID1 reads uid(4)
then gid(4) as two separate messages, each <= 8 bytes => "Received too short user
lookup message, ignoring" (the recurring PAIRS in the log, t=32/63/73/148/155/311/367).
Every service's uid/gid->name mapping was lost => dbus-broker "Falling back to racy
auxiliary groups resolution using nss", logind session-id lookup fail, polkit
"Process not found".
FIX: crates/kernel/syscalls/src/020_writev.rs — before the per-iovec loop, if the
fd is a message-boundary socket (Udp | UnixDgram | UnixMsgPair), COALESCE all
iovecs into ONE buffer and `file.write(&msg)` once => a single datagram. Mirrors the
identical fix already in 046_sendmsg.rs (which coalesces). Verified in boot
"render1": too-short count 14 -> 0.

### 2. GPU / DRM driver — the mutter-modeset blocker + missing modes + wrong ioctl #s
THE blocker (FIXED + live-validated in boot "hunt10"): mutter 48 reads plane pixel
formats from the **IN_FORMATS blob property**, not the legacy GETPLANE format list.
We exposed neither the property nor GETPROPBLOB (was ENOTTY) => mutter logged "KMS:
Plane has no advertised formats" for primary plane 768 => aborted modeset => console
never left fbcon.
  FIX (crates/drivers/drm/src/):
   - modeset.rs: added `get_prop_blob` (GETPROPBLOB) serving a 56-byte
     `drm_format_modifier_blob` (XRGB8888+ARGB8888, LINEAR); `in_formats_blob()`;
     IN_FORMATS in `get_obj_properties` (prop id 17, blob id 0x50) + in
     `get_property` (BLOB|IMMUTABLE).
   - node.rs: dispatch GETPROPBLOB + the new ioctls (below).
  VALIDATED: mutter did the 2-pass `getblob id=80 ulen=0 -> 56`, then "Adding format
  XR24/AR24", primary plane usable, "Queue mode set".

FOUR WRONG IOCTL NUMBERS in drm/src/uapi.rs (same class as the historic
GETPLANERESOURCES size bug — wrong size/nr field => libdrm call silently ENOTTYs):
   - GETGAMMA/SETGAMMA 0x18 -> 0x20 (drm_mode_crtc_lut is 32 B)
   - SETPLANE 0x30 -> 0x40 (drm_mode_set_plane is 64 B)
   - CURSOR2 nr 0xbf -> 0xbb
  Added drm test `ioctl_size_fields_match_structs` (tests.rs) asserting each ioctl's
  embedded size field == sizeof(struct) — permanently catches this class. 70/70 drm
  tests pass. LESSON: verify DRM ioctl numbers by computing _IOWR(nr,sizeof) and
  diffing uapi.rs.

MISSING KMS MODES IMPLEMENTED (crates/drivers/drm/src/kms_ext.rs — new module,
repr(C) structs read wholesale, NAMED CONSTANTS throughout, no magic numbers):
   - SETPLANE (primary plane -> scanout, fb 0 -> restore console)
   - DIRTYFB (TRANSFER_TO_HOST + FLUSH of the on-screen fb)
   - OBJ_SETPROPERTY / SETPROPERTY (DPMS + property writes -> no-op success)
   - GET/SETGAMMA (identity ramp / accept — no HW gamma)
   - GETFB (framebuffer geometry query)
   - ADDFB2 now accepts the LINEAR/INVALID modifier path (dumb/ioctl.rs)
   - runtime.rs: named BYTES_PER_PIXEL (was magic 4) + pitch/stride note.
  New UAPI structs in uapi.rs: DrmModeSetPlane, DrmModeFbDirtyCmd,
  DrmModeObjSetProperty, DrmModeConnectorSetProperty, DrmModeCrtcLut, DrmModeCursor,
  DrmModeCursor2, DrmModeFbCmd + flag consts (CURSOR_BO/MOVE, DPMS_*).
  Both arches build; 70/70 drm tests pass.

GPU items DEFERRED (not blocking a single-head 1280x800 render):
   - HW cursor CURSOR/CURSOR2: needs the virtio-gpu CURSOR virtqueue (queue 1)
     brought up — only ctrlq is initialized today (drv-virtio-gpu). mutter uses a
     working SW cursor meanwhile. UAPI structs + ioctl #s are ready; needs a
     CursorOps hook on ScanoutOps + UPDATE_CURSOR/MOVE_CURSOR on the cursor queue.
   - Multi-head SET_SCANOUT hardwired to scanout 0 (runtime.rs) — 1 head only.
   - Connector EDID/DPMS as readable props absent (count_props=0, tolerated).

### 3. debug-watchdog default-on serial spam — FIXED (production cleanliness)
boot-x86_64/Cargo.toml + boot-aarch64/Cargo.toml have `default = ["debug-watchdog"]`.
That enabled `dump_exit_recent` which dumped `[EXIT] name=... code=` + ~30 lines of
"recent syscalls" to the SLOW serial console on EVERY non-zero process exit — despite
its comment claiming "no steady-state noise". ~1109 serial lines/boot.
FIX: crates/kernel/sched/src/diag/ring.rs — re-gated `dump_exit_recent` from the
default-on `debug-watchdog` to the OPT-IN `debug-taskdump`. The soft-lockup watchdog
(the wanted default-on part) is unaffected. x86 build green; aarch64 build was
IN-FLIGHT when the session exited (verify it: `cargo run -p xtask -- kernel --arch aarch64`).

### 4. MM free-while-mapped backstop (from earlier in the session) — landed, UNVALIDATED
crates/kernel/mm-pmm/src/setup/refs.rs: single free-on-zero choke point
`release_frame_on_zero` (both dec paths funnel through it) enforcing the Linux
never-free-a-mapped-page invariant. PLUS a production peer-scan repair in
user_as/teardown.rs (both arches): before freeing a teardown leaf with refcount<=1,
`fwm_peer_maps` scans other live ASes; if a peer still maps it, `repair_frame_counts`
restores the count and does NOT free (logs [FWM-REPAIR]). `fwm_peer_maps` was
un-gated from debug-fwm to production (metadata.rs). NOTE: the double-free panic is
INTERMITTENT (~50% of boots at teardown.rs:44) and did NOT fire in the last ~5
instrumented boots, so the backstop is correct-by-construction but not yet caught
catching the live bug. See memory [[sigsetxid-rt-siginfo-greeter]] history.

===============================================================================
## REMAINING WALL: DESKTOP STILL DOES NOT RENDER (console stays on screen)
===============================================================================
GPU driver is NO LONGER the blocker (IN_FORMATS fixed). The wall is the SESSION +
SLOWNESS:

A) SESSION FAILS: gnome-shell (== the mutter compositor in Wayland) "failed to
   register before timeout" => "Unrecoverable failure in required component
   org.gnome.Shell.desktop" => gnome-session-failed => nothing presents. Chain:
   - greeter dbus (uid 979 pid 275, a gdm-launched dbus-DAEMON — a PRIVATE/fallback
     bus, NOT the systemd --user bus): "Failed to activate service
     'org.freedesktop.systemd1': timed out (120000ms)". systemd --user provides
     systemd1 on the USER bus (/run/user/979/bus); the greeter is on bus 275 =>
     unreachable => 120s block => gnome-shell misses its registration deadline.
   - gnome-session: "Could not get session id ... Check that logind ... pam_systemd"
     + "Unset XDG_SESSION_ID". logind DID create session c1/c2, but XDG_SESSION_ID
     is not in the greeter env and the pid->session (cgroup) lookup fails.
   - WHY the fallback bus: `user@979.service` (systemd --user) takes ~32s to reach
     Started (real Linux <1s); gdm-wayland-session launched the greeter before the
     user-bus was ready => fell back to a private dbus-daemon.

B) SLOWNESS is the deeper root: userspace boot ~2min40s (release) / 3min08s (debug)
   vs seconds on real Linux. `systemd-analyze`-style "Startup finished in 5.0s
   (kernel) + 2min40s (userspace)". Multi-second STALLS where the WHOLE system idles
   (37.5s ending t=213, 28.5s@98, 17.4s@53, 15s@238, ...). Each stall ENDS with a
   service that was parked in `poll` (last syscall `poll = -4` = EINTR) getting
   SIGTERM'd on a systemd timeout. Two candidate roots (not yet disambiguated):
     (i) scheduler wakeup-latency (parked poll/epoll waiters serviced late — the
         same class as the historic B580 park_yield fix, memory
         [[scheduler-park-yield-wakeup-latency]]); OR
     (ii) a userspace D-Bus timeout CASCADE driven by systemd1 being unreachable
         (services block on 120s activation, systemd serializes, kills, retries).
   Plus: zram device timeouts (`dev-zram0.device/start timed out` ~90s => swap
   dependency failures) — our kernel likely lacks zram; contributes stall time.

===============================================================================
## NEXT STEPS (priority order)
===============================================================================
1. Finish the aarch64 build check of the debug-watchdog fix (was in flight).
2. Attack the SLOWNESS — it is the root of the session timeouts. Disambiguate (i)
   vs (ii): boot with `debug-taskdump` (periodic all-task state dump every 20s) and
   look at task states DURING a 37s stall — if a task is RUNNABLE-but-not-scheduled
   it's scheduler wakeup latency; if all tasks are legitimately BLOCKED on a D-Bus
   reply it's the systemd1 cascade. The scheduler park/wake/poll path lives in
   crates/kernel/sched/src/ (grep for the run-queue wake + poll/epoll wait).
3. systemd1 reachability: make `user@979.service` start FAST (unwinds the fallback-bus
   chain), OR get the greeter onto the user bus. Likely resolves once slowness fixed.
4. "Could not get session id" / XDG_SESSION_ID: verify pam_systemd sets XDG_SESSION_ID
   in the gdm-launch-environment session and that the greeter procs' /proc/PID/cgroup
   reflects session-cN.scope (sd_pid_get_session reads the cgroup).
5. zram: either fail-fast (mask systemd-zram-setup@ / dev-zram0 in the image) or note
   it's non-critical.
6. Then re-verify the desktop renders (shotboot.sh screendump) once the session comes
   up — the GPU path is ready.

===============================================================================
## TOOLING / METHOD (reuse these)
===============================================================================
- SEE the framebuffer: oxide-images/shotboot.sh <log> <secs> <interval> — boots with a
  QMP socket and screendumps the virtio-gpu framebuffer every <interval>s to
  output/shots/shot_NN.png (via qmp_shot.py). Read the PNGs to see console-vs-graphics.
- Get mutter's own reasoning: inject `MUTTER_DEBUG=kms` (+ `G_MESSAGES_DEBUG=all`, but
  it slows userspace) into the root.img /etc/environment via
  `debugfs -w -R "write /tmp/environment /etc/environment" output/live-gnome-x86_64-root.img`
  (pam_env in gdm-launch-environment propagates it). REMOVE it for fast/clean boots:
  `debugfs -w -R "rm /etc/environment" ...`.
- DRM ioctl trace: build with `debug-boot` => `[DRMIOCTL req=]` per ioctl + `[DRMPROP ...]`.
- Boots: oxide-images/oneboot.sh <log> <secs> (serial only). ALWAYS `cargo run -p xtask
  -- kernel --arch x86_64 [--features ...]` THEN `cargo run -p xtask -- artifacts
  --arch x86_64` THEN `cargo run -p imagectl -- build-boot --profile live-gnome --arch
  x86_64` (imagectl reads target/artifacts). Launch detached: `nohup ./oneboot.sh ... &
  disown`. Do NOT prefix commands with `pkill` (returns 1 => aborts the compound cmd);
  don't pipe cargo through `| tail` (SIGPIPE => exit 1). Sandbox cannot kill qemu.
- Time-gap analysis (find stalls): grep the boot-t prefixes and awk the deltas.

Files touched this session (all in /home/nd/oxide/kernel, uncommitted):
  crates/kernel/syscalls/src/020_writev.rs            (userdb writev coalesce)
  crates/drivers/drm/src/{uapi.rs,modeset.rs,node.rs,kms_ext.rs(new),crtc.rs,dumb/ioctl.rs,tests.rs,lib.rs}
  crates/drivers/drv-virtio-gpu/src/post_init/runtime.rs
  crates/kernel/sched/src/diag/ring.rs                (debug-watchdog exit-spam re-gate)
  crates/kernel/mm-pmm/src/{setup/refs.rs,setup/metadata.rs,setup.rs,user_as/teardown.rs,user_as/unmap.rs}  (MM backstop)
  crates/kernel/mm-vmm/src/address_space/fault/fill.rs (debug-cow import gate)
  crates/kernel/mm-pmm/src/setup/{alloc_integrity.rs,double_free.rs,buddy/inner.rs,buddy/api.rs,user_as/debug.rs} (MM diag, earlier)
