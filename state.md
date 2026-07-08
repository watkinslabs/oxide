# Handoff — resolved busy-loop FIXED (B650); next blocker = gdm crash-loop

## STATUS
Branch **B650-ip-recvttl-resolved-busyloop** (commit aecb2c53). Boot-verified.

### What landed (B650)
systemd-resolved was **busy-looping**: LLMNR/mDNS socket setup calls
`socket_set_recvttl` → `setsockopt(IPPROTO_IP, IP_RECVTTL=12)`, which our
handler didn't recognize → returned ENOPROTOOPT → resolved retried in a
tight loop ("LLMNR-IPv4(UDP): Failed to set common socket options: Protocol
not available", once per netlink event), starving polkit/dbus-broker on the
scheduler → polkit.service (Type=dbus, 45s) timed out → no greeter.
FIX: implement `IP_RECVTTL` (store flag + deliver received IPv4 TTL as an
IP_TTL cmsg on recvmsg; plumbed ttl through UdpRxQueue tuple →
recv_udp_meta_opts → Received.ttl → write_cmsgs, mirroring IPV6_HOPLIMIT)
and accept `IP_MTU_DISCOVER`. Both arches build.

### VERIFIED (recvttl1 + taskdump1 boots)
- resolved LLMNR spam **GONE**; console reaches polkit-start cleanly.
- Boot now advances all the way to gdm: at t=160s taskdump shows gdm
  running (tgid 4316, ppoll) + NetworkManager/logind/dbus-broker/avahi/
  cupsd all in normal waits. polkit NO LONGER the blocker.

## NEXT BLOCKER: gdm greeter session HANGS (not crashes) → SIGTERM → crash-loop
Diagnosed across taskdump1 + scmfd1 boots:
- gdm daemon (tgid ~4277) stays ALIVE in ppoll with an idle worker-thread
  pool; the process that dies is gdm's **session wrapper** (exec'd via
  `/proc/self/fd/9`, e.g. gdm-wayland-session / gdm-x-session).
- It exits `code=271` = **256+15 = SIGTERM** (code=265 = 256+9 = SIGKILL),
  ~46s apart (t≈100s, 146s) → killed after a ~45s HANG, then gdm retries →
  "restart counter is at 3" → "Failed to start gdm.service".
- **No SIGSEGV/fault anywhere** in the boot (greeter does NOT crash — hangs).
- **No `gnome-shell` exe ever appears** and **no SCM_RIGHTS pidfd relay fires**
  (debug-scmfd = 0 traces) → gdm hangs LAUNCHING the greeter session, BEFORE
  logind CreateSession(WithPIDFD). Suspects: DRM master / VT switch / a D-Bus
  call to gdm/logind that never returns / gdm-session-worker setup.

### Hard limit hit: gdm's real error is in the JOURNAL, unreadable
gdm redirects stderr to the journal (debug-stderr does NOT catch it), and
there is NO serial getty (getty runs on tty1, not ttyS0 — sending Enter to
serial yields no login). So the decisive error message is inaccessible
without either (a) a tty1/graphical shell (the broken thing), or (b) many
gdm-reaching boots with display-stack tracing — but boots are intermittent
(~50% wedge early at ~cups/t31s, a SEPARATE bug) and the user forbids
boot-per-hypothesis loops.

### First task next session (need a gdm-reaching boot)
Options to get gdm's error / pin the hang:
1. Enable a serial getty (systemd `serial-getty@ttyS0`) or console=ttyS0 in
   the image cmdline so a shell is reachable over serial → `journalctl -u
   gdm -b` gives the exact failure. (Best ROI — do this first.)
2. Or `features=debug-displaystack` / `debug-futextrace` on a gdm-reaching
   boot → see the greeter wrapper's stuck futex/VT/ioctl op.
3. Static-audit the gdm-session-worker → VT/DRM ioctl path (VT_ACTIVATE,
   DRM_IOCTL_SET_MASTER, KDSETMODE) for an ioctl we stub/hang on — the
   greeter wrapper does capget/prctl/close-storm then hangs, consistent with
   a VT/DRM setup ioctl that never returns.
Also: fix the intermittent early wedge (boot with debug-taskdump, catch the
stuck task at ~t31s) so gdm-reaching boots are reliable.

## Push/PR — DONE
B650 pushed + PR #2838 MERGED to main (commit a1f650c0). Boot-verified.

## Notes
- gdb-over-KVM is flaky in this env (qemu_break/regs/interrupt time out);
  use debug-taskdump / debug-stderr feature boots instead of gdb.
- `quiet` cmdline → systemd status goes to tty0 framebuffer, NOT serial;
  serial freezes ~15s normally. Screenshot the framebuffer for real state.
- Leftover debug-syscost diagnostics (LSCAN/EPADD/syscost.rs targeting
  polkit) from the EPOLLET session are committed but gated off — harmless.
