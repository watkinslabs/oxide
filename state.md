# Session hand-off — Linux-exact TTY/VT/console rebuild COMPLETE (T1–T9 + T7b)

## Status: DONE. All 10 tasks merged to main + verified.
The TTY/VT/console subsystem was rebuilt the real Linux way per
tty-rebuild-plan.md. The intermittent login race is FIXED and live;
login->shell verified both arches; /dev/fd correctness verified; bash
interactive (pipes/loops/^C) verified; smoke PASS both arches every push.

## Layers (all merged, ~210 hosted tests + proptests)
- vtdata: Vc screen buffer + ECMA-48 Emulator + Consw trait (#1640,#1641)
- tty: N_TTY ldisc (#1643) + TTY core tty_struct/driver/port with the
  LOST-WAKEUP-FREE blocking read (#1644, the login-race fix, race-tested)
- vtconsole VT console driver (#1645), serialtty ttyS0 driver (#1646)
- T7 cutover: /dev/console -> serial TtyStruct (#1647); /dev fd-link +
  console winsize (#1648); T7b printk register_console registry + fbcon
  renders vc_data lossless + numbered VTs (#1650); T9 hosted integration
  net 17 tests (#1651)

## Verified live (qemu MCP, both arches unless noted)
- login -> root shell, no nudge, both x86 + arm
- /dev/fd: /dev/std*->/proc/self/fd->/dev/console, /dev/fd/1 write,
  readlink, tty, isatty, stat char-special — all correct (x86)
- bash: pipe (tr), for-loop, fork/exec, ^C interrupts sleep (x86)
- pre-push boot-smoke PASS both arches on every push

## Remaining polish (non-blocking, future): per-VT TtyStruct+vc_cons[N]
for true multi-VT (today numbered VTs share the fg Vc); truecolor cell
(stored as index); scrollback depth 0.

## Parked: sched unified-engine WIP = git stash@{0} (WIP-unified-sched-
step1); plan in sched-anal.md. Return to it now that tty is stable.

## Counters: F=422, B=73, C=10, D=94. Author Chris Watkins <chris@watkinslabs.com>.

## REGRESSIONS REPORTED (user, on real display+serial) — fix next, do NOT merge P5 yet
1. GRUB on serial only, not display = GRUB terminal_output config (pre-kernel, NOT the rebuild).
2. **Console display freezes after login = T7 regression.** /dev/console now -> serial
   TtyStruct -> UART only (console/src/static_console.rs). Pre-rebuild it went through
   klog::write_raw -> serial+fbcon (mirror). printk still hits fbcon (P7b) so boot logs
   show then freeze; shell I/O is serial-only. FIX: multi-console — in static_console
   write+echo path, after UART also feed fg fbcon VT (fbcon::kernel::vt_write(fg,bytes)).
   (Linux console=tty0 console=ttyS0.) Verify with qemu_screen on the framebuffer.
3. Serial echo missing + login-sometimes-absent: needs clean repro. Suspect per-VT VtState
   lock (P3) / klog-render contention from printk context, or pre-existing getty wedge.
   Bisect: T7(#1647) routing, P7b(#1650) klog->fg-VT render, P3(#1654) per-VT lock.
4. P5 (box-drawing font, branch F426-fbcon-unicode-font, NOT merged/committed) is in the
   working tree — commit or drop before bisecting.

## UPDATE — regression #2 FIXED + merged (B74 #1656, main 361ecea8)
KernelUart::emit (console post-OPOST sink) now fans to UART + fbcon
fg VT (vt_console_sink). qemu_screen confirmed: framebuffer shows the
cleared+login/shell console (was frozen on boot logs). serialtty gained
oxide-kernel fbcon dep.

## STILL OPEN (next session — user says login issue is systemd/kernel, NOT getty/vt)
- #1 serial echo missing: verify at login prompt vs bash. Echo path =
  N_TTY ECHO -> driver_write -> SerialTtyDriver::write -> KernelUart::emit
  (-> UART + now fbcon). If serial shows no echo: check N_TTY ECHO flag /
  termios after login(1) TCSETS, or driver_write not reaching emit. (In
  MCP tests "root" DID echo on serial, so may be display-only or a
  termios-after-login regression — repro carefully.)
- #3 login sometimes never comes up (systemd/kernel suspect): NOT getty/vt.
  Hypotheses: (a) GPU-flush softirq now fires on every console write (B74
  mirror) -> virtio-gpu 4MB transfer stalls/contends, slowing boot enough
  to race systemd getty start; (b) per-VT VtState lock (P3) contended from
  printk(klog vt_console_sink, try_lock) + console emit(try_lock) + kbd
  switch(REAL lock) + numbered vt_write(REAL lock) — a REAL-lock holder
  vs printk could wedge; (c) pre-existing cooperative-sched/getty race.
  Repro N boots, watch where it stalls (qemu_screen + serial); if boot
  reaches "Reached target" but no login, it's getty/systemd-side; if it
  stalls earlier, kernel. Consider: throttle the fbcon flush (already
  softirq-deferred + dirty-deduped) and confirm vt_console_sink try_lock
  can't starve. Bisect across #1647/#1650/#1654/#1656.
