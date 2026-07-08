# Handoff — greeter root-caused to polkitd D-Bus name-acquisition timeout

**Branch:** `F693-quickboot-glibc-rootfs` (pushed, PR #2837).
**Goal (NOT yet met):** graphical GNOME to a visible greeter, 100% Linux-compat, no stubs.

## THE root cause (nailed this session, evidence in D-Bus wire trace)
Final dbus-broker frames (debug-dbus wire dump):
```
systemd1/job/596 -> polkit.service -> "failed"
org.bus1.DBus.Name.Error.StartupFailure
"Could not activate remote peer 'org.freedesktop.PolicyKit1': startup job failed."
```
Chain:
1. A client (upowerd/gdm/…) calls a PolicyKit1 method → glib does D-Bus **StartServiceByName(org.freedesktop.PolicyKit1)**.
2. dbus-broker asks systemd to start **polkit.service** (Type=dbus, job 596).
3. **polkitd starts but never acquires `org.freedesktop.PolicyKit1` on the bus within systemd's 25s activation timeout** → `polkit.service: start operation timed out. Terminating.` → job 596 = **failed**.
4. dbus-broker returns `StartupFailure` to every waiter.
5. **upowerd SEGVs (status=11)** — glib `polkit_authority_get_sync` returns NULL after the timeout, upower derefs it. `MESSAGE=failed to get polkit authority: … Timeout was reached` then `status=11/SEGV`.
6. **gdm exits code=1** (needs polkit/accounts); `gdm.service: Triggering OnFailure=`; restart loop.
7. Everything cascades down (services stop; upower `stop-sigterm` timeout → SIGABRT). By ~t=120s only init+journald remain on the collapsing boots; on other boots it wedges with services idle.

## What polkitd is doing when it stalls (two boots agree)
- polkitd main (tid ~4241) and its GDBus worker (~4255) DO ping-pong cleanly via futex early (handoff healthy), then **freeze**: main `nsysc` plateaus at 4003 (2.9s CPU burned), worker at 457 — both parked in ppoll making **zero** further syscalls. A genuine terminal stall mid-startup, NOT slow-progress and NOT a hot busy-loop at the end.
- So: polkitd gets partway through startup, then blocks in ppoll on a D-Bus reply (or a rules/JS/fs op) that never completes, so it never calls RequestName-complete → name never owned.

## RULED OUT this session (do not re-chase)
- **D-Bus transport works.** Wire trace shows Hello, unique-name assignment (:1.8/:1.9/…), RequestName, NameOwnerChanged all flowing correctly over AF_UNIX.
- **Futex lost-wakeup** — polkit main↔worker futex handoff is healthy/cycling (traced). The low-addr `0x100xxxxx` WAIT-with-no-WAKE futexes (upower/switcheroo/accounts) are idle glib thread-pool workers, not the cause.
- **poll/epoll permanent lost-wakeup** — BOTH ppoll (007_poll.rs RESCAN_NS) and epoll_wait (fs/epoll.rs:370 RESCAN_NS) self-heal every 20ms; neither can hang forever. Worst case 20ms latency/round-trip.
- **AF_UNIX poll readiness** — sock/io.rs:177 SockKind::Unix poll correctly sets POLLIN when read_q non-empty, POLLHUP on eof.
- **AF_UNIX write backpressure** — unix stream write (stream.rs write_inner) is UNBOUNDED, always returns full data.len(), never EAGAIN → no write busy-loop.
- **dbus-broker health** — alive, low CPU, actively processing (not stuck/spinning); it correctly reports the failure.
- **userdb ECONNREFUSED** (`/run/systemd/userdb/io.systemd.DropIn`) — RED HERRING; refused 238× by systemd-tmpfiles too; normal NSS fallback. gdm's connect=-111 in its death trace was this, not the fatal cause.

## MEASUREMENT CAVEAT (cost hours; heed it)
debug-futextrace / debug-taskdump / debug-boot klog to the **UART on every event** → ~0.7ms/syscall → slows D-Bus ~100× and PUSHES polkit past the 25s activation timeout. So debug-heavy boots' *timing* is not representative. Whether polkitd would make the 25s window on a clean release boot is UNKNOWN — but the futextrace boot showed a genuine terminal FREEZE (nsysc frozen), so it's a real stall, not merely slow.

## NEXT (the one decisive measurement, set it up carefully — don't firehose)
Trace polkitd's startup to its exact stuck syscall/message:
1. Boot `debug-boot,debug-dbus` (lighter than futextrace), run to polkit's stall (~120-200s), and dump **polkitd's own** D-Bus frames + its last syscall (per-syscall trace filtered to exe~polkit). Find the reply/op polkitd blocks on.
2. Suspects for polkitd's mid-startup block: (a) a `_sync` D-Bus call to systemd/logind whose reply is dropped; (b) polkit's mozjs rules-engine init doing an ext4/read that hangs; (c) a self-call (polkit → own bus name) ordering deadlock.
3. Once the blocking op is known, fix that kernel path. That unblocks polkit → upower/gdm proceed → greeter renders.

## Diagnostic scaffolding left in tree (feature-gated, harmless, KEEP)
- `crates/kernel/ipc/src/live/futex/wait.rs` ftx_target_exe(): widened to polkit/upower (debug-futextrace).
- `crates/kernel/net/src/unix_sock/stream.rs` trace_dbus_stream(): widened is_tgt to polkit/dbus-broker/upower/switcheroo/accounts + PolicyKit1/RequestName/StartServiceByName/NameAcquired filters (debug-dbus).
- Both verified to COMPILE + run (the futextrace and dbuswire boots built with them).

## Tooling facts
- Build+boot via qemu MCP: `qemu_start arch=x86_64 accel=kvm mem=4G features=debug-boot,debug-dbus[,debug-taskdump]`.
- `debug-dbus` is forwarded kmain→net (kmain/Cargo.toml:93). `debug-taskdump` = per-20s all-task dump (state/last-sysc/nsysc/cputime). `debug-futextrace` = FTX-WAIT/WAKE (uaddr hex NO 0x prefix).
- Serial capture is one JSON blob with escaped \n — unescape via json.loads(...)["result"] then splitlines before grepping.
- Boots are intermittent: some cascade-collapse (~t120), some wedge idle to t320. init tid=3235774466 (vpid1).

## Also open (lower priority)
- `init=/usr/bin/bash` #PF at smoke::elf::user_fault_handler (bash-as-PID1 only; separate; greeter boots have 0 [FAULT]).
- ext4 read_file doesn't follow usrmerge /bin→/usr/bin symlink (so init=/bin/bash picks /init).
