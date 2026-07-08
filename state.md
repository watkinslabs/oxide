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

## NEXT BLOCKER: gdm.service crash-loops (NEW frontier)
Framebuffer at t=192s:
```
Failed to start gdm.service - GNOME Display Manager.
gdm.service: Scheduled restart job, restart counter is at 3.
[EXIT] name=fork-child exe=/proc/self/fd/9 code=271
  recent syscalls: nr#14(sigprocmask) nr#13(sigaction) nr#9(mmap)
  nr#125(capget) nr#157(prctl) nr#186(gettid) nr#104/102(getgid/uid)
  nr#3(close ×many)
```
gdm starts, a child (/proc/self/fd/9, a gdm re-exec) exits code=271, gdm
fails, restarts (counter climbing). Investigate WHY the gdm child dies.

### First task next session
Boot with `debug-stderr` (echoes userspace fd==2 writes to console) to
capture gdm/gdm-session-worker's death message:
```
qemu_start arch=x86_64 name=gdmdbg features=debug-stderr,debug-watchdog accel=kvm mem=4G paused=false
```
Wait ~150s, screenshot framebuffer + grep serial for [STDERR]. code=271
(0x10F) + the capget/prctl/close-storm pattern suggests a gdm helper
failing during privilege/fd setup or exec — check what /proc/self/fd/9
is exec'ing and why it exits. Also confirm polkitd is actually alive
(one taskdump showed polkitd main tid 4241 in state Z — verify it's not
also crashing, which could cascade into gdm).

## Push/PR
B650 committed but NOT yet pushed. Push with SKIP_SMOKE=1 (kernel change,
already boot-verified locally), open PR, merge. Then pursue gdm.

## Notes
- gdb-over-KVM is flaky in this env (qemu_break/regs/interrupt time out);
  use debug-taskdump / debug-stderr feature boots instead of gdb.
- `quiet` cmdline → systemd status goes to tty0 framebuffer, NOT serial;
  serial freezes ~15s normally. Screenshot the framebuffer for real state.
- Leftover debug-syscost diagnostics (LSCAN/EPADD/syscost.rs targeting
  polkit) from the EPOLLET session are committed but gated off — harmless.
