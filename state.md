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
