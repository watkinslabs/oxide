# Handoff — greeter blocked by SYSTEMIC WAKE LATENCY (timer-tick gaps), surfacing as polkit timeout

## TOP FINDING (2026-07-08, debug-wakelat, CLEAN boot confirms it's real)
The greeter fails because of **systemic wakeup latency**, NOT anything polkit-specific:
- Every thread's blocking wait (epoll/ppoll, kind=1) returns after **50–350ms** (median 149ms, mean 287ms, max 2.5s) with the fd ALREADY ready — the wakeup/arrival edge is slow, not the data.
- Threads wake in BATCHES at identical timestamps (e.g. 3 services all wake after ~410ms at t=21.03s) — the scheduler wakes everyone together after a stall, not promptly.
- **`WLTICKGAP us=334535`** + **`WLSCANGAP us=397861`**: the timer tick and the poll/epoll 20ms safety-rescan have **334–397ms GAPS** (should be ~1ms / 20ms). Avg tick period is ~1.2–1.4ms (WLTICK), so MOST ticks are fine but there are frequent hundreds-of-ms gaps.
- CLEAN boot (features=debug-watchdog only, NO klog firehose): polkit.service still ran the full **45s** and `[FAILED] start operation timed out` → so the slowness is REAL, not a tracing artifact. Read the systemd boot log directly off the framebuffer (qemu_screen as_text=False → PPM → png → Read).
- Mechanism: mozjs (spidermonkey, polkit's JS rules engine) does thousands of SEQUENTIAL futex/poll round-trips; at ~150ms wake latency each, its init blows systemd's 45s TimeoutStartSec → polkit.service FAILED → upowerd SEGV on NULL authority → gdm exit 1 → no greeter. Other services (NetworkManager/logind/udisks) are less round-trip-bound so they squeak in [OK].

## MECHANISM (traced to scheduler/timer core)
`arch-irq/src/lapic/dispatch.rs` `oxide_irq_resched_on_exit` (line ~153): the scheduler is **VOLUNTARY-preempt — it switches tasks ONLY on IRQ-exit to USER mode** (`from_user = (saved_cs & 3)==3`). The timer tick sets need_resched but a task in a long KERNEL section is NOT preempted until it returns to user or blocks. Meanwhile `note_tick` (dispatch.rs:49) firing with 334ms gaps means the LAPIC timer IRQ itself didn't fire for 334ms → IRQs were masked (IF=0) in some kernel section that long, OR the periodic tick stalled. Between them, a runnable thread waits ~150ms median to actually run.
`hal-x86_64/src/timer.rs:174 set_oneshot` is a NO-OP stub — the LAPIC timer is periodic (armed once at bring-up), so gaps ⇒ IRQ-masked stalls, not a missing rearm. Suspects for the long IF=0 section: tick_poll (BSP hook, dispatch.rs:75, runs IRQs-masked — fbcon flush?), a spinlock held across slow work, or klog/UART done with IRQs off.

**CAVEAT:** the 334ms tick-gap magnitude may be partly INFLATED by debug-wakelat's own klog (per-WLBLK UART write, possibly IRQs-off). The CLEAN boot proves the slowness is REAL (polkit 45s timeout) but the exact latency without tracing is unmeasured. Confirm the tick-gap on a lighter instrument (a tick-gap counter that does NOT klog per-block; only emit a summary).

## NEXT (THE lever — core scheduler/timer, high-risk, design carefully)
1. Confirm+quantify the IF=0 stall: which kernel section runs with IRQs masked long enough to drop LAPIC ticks. Instrument IF=0 duration (rdtsc at cli/sti boundaries) rather than per-block klog.
2. Likely fixes (pick after root-cause): add kernel preemption points (preempt on tick even from kernel at safe points), or shorten/eliminate the long IRQ-masked section (move fbcon flush / slow work out of IRQs-off), or make the softirq/tick_poll not run IRQs-off.
3. This collapses wake latency → mozjs/polkit init finishes in time → gdm renders the greeter. It ALSO likely fixes the intermittent ~17-20s udev-coldplug boot wedge (same latency/preempt class).
Do NOT patch the scheduler core at session end without a hosted causality test + N-boot verification.

Framebuffer-read method (reliable greeter/boot-status check): qemu_start features=debug-watchdog; qemu_screen as_text=False; pnmtopng /tmp/oxide-qemu-*/screen.ppm; Read the png — shows systemd [OK]/[FAILED] log when `quiet` is removed (temporarily) OR the greeter when it renders.

---
# (earlier layer) greeter → polkitd D-Bus name-acquisition timeout

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

## What polkitd is doing when it stalls (per-syscall [POL] trace, debug-polktrace)
Threads (poltrace3 boot):
- **tid 4241 (main)**: 525+ syscalls — futex:159, mmap:82, openat:36, read:28, mprotect:26, getdents64, clone3, inotify_add_watch(=1/2/3 SUCCESS on the dirs that exist). This is **mozjs (spidermonkey) JS-engine init + polkit rules loading**. At the END of the window it is STILL actively progressing (clone3 spawning threads, getdents enumerating /usr/share/polkit-1/rules.d, reading rules) — NOT deadlocked, just SLOW.
- **tid 4269 (GDBus worker)**: recvmsg:18 / sendmsg:2 / write:8-byte eventfd wakeups — normal D-Bus I/O; only 2 D-Bus sends (Hello + 1). Alive.
- **tid 4267**: glib missing-dir monitor retry — ppoll(timeout)=0 then 5× inotify_add_watch=-2 (ENOENT) on the 5 NON-EXISTENT dirs (/etc/polkit-1/actions, /run/polkit-1/{actions,rules.d}, /usr/local/share/polkit-1/{actions,rules.d}). This is glib's normal 4s missing-dir poll — NOT a hang, NOT the bug.

**REFRAMED root cause:** polkit's `polkit_backend_authority_get()` (spidermonkey JS runtime init + compile/load of ~20 .rules files) is **pathologically slow** under our kernel — it exceeds systemd's 25s Type=dbus DefaultTimeoutStartSec, so systemd kills polkit before it finishes init and calls g_bus_own_name → RequestName. NOT a stub-able bug; NOT a hard deadlock in THIS boot.

**BUT intermittent:** the earlier 320s futextrace boot showed polkit main FREEZE (nsysc plateau 4003, zero further syscalls) — a genuine hang. So across boots polkit is sometimes slow-progressing, sometimes frozen — a race/perf split. The mozjs-heavy init (159+ futex, 82+ mmap) is the sensitive path.

**Two clean-boot facts:** (1) framebuffer on a minimal build (debug-watchdog only) stayed a TEXT console — greeter never rendered. (2) debug tracing (per-event UART klog) slows syscalls ~100× (0.7ms each), massively amplifying the timeout. So the debug boots' timing is NOT representative; whether polkit makes the 25s window on a truly clean boot is still UNPROVEN.

## NEXT (perf, not deadlock): why is polkit's mozjs+rules init so slow?
Profile which syscall dominates polkit's init wall-clock on a CLEAN boot (no per-syscall klog). Candidates: mmap/mprotect (mozjs GC arenas — 82 mmap), futex (159 — mozjs thread sync), getdents64/openat/read (rules files off ext4). If a specific syscall is pathologically slow (e.g. mmap fault-in, or futex, or ext4 read), fixing that unblocks polkit within 25s. Use debug-wakelat / a coarse per-syscall-latency counter, NOT the per-syscall klog firehose (which distorts). Also: the intermittent early udev-coldplug wedge (~17-20s, ~half of boots) is a SEPARATE blocker that also prevents reaching the greeter.

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
