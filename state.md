# Session hand-off — Linux-exact TTY/VT/console rebuild (T1–T8 LANDED), T9/T7b remain

## Headline
Rebuilding the TTY/VT/console the **real Linux way** per `tty-rebuild-plan.md`
(5 layers: vc_data+emulator / consw+fbcon / N_TTY ldisc / tty_struct+driver /
console+serial drivers + printk-console split). The intermittent **login race
is FIXED and LIVE on main**, verified login→shell on BOTH arches (smoke PASS;
manual `T7OK_0_/dev/console` + `ARM_T7OK_0_/dev/console`).

## Landed to main (all merged, tested both arches)
- T1 #1640 `vtdata` crate: `Vc` screen buffer + ECMA-48 `Emulator` (32 tests).
- T2 #1641 `Consw` trait + fbcon renders `Vc` (per-cell attrs; real lock).
- T3 #1643 N_TTY ldisc (`tty/src/ldisc/`): OPOST/ICANON/ECHO/ISIG (91 tty tests).
- T4 #1644 TTY core (`tty/src/core.rs`,`wait.rs`): tty_struct/driver/port +
  **lost-wakeup-free blocking read** (port-lock serializes enqueue-waiter vs
  queue+wake; proven by a 2000-iter race test that hangs if reverted). 108 tests.
- T5 #1645 `vtconsole` crate: VtConsoleDriver (full VT stack end-to-end, 8 tests).
- T6 #1646 `serialtty` crate: ttyS0 SerialTtyDriver (8 tests).
- T7 #1647 **CUTOVER**: `/dev/console` → serial `TtyStruct`
  (`console/src/static_console.rs`); UART RX → N_TTY; console write → OPOST →
  UART (not the kmsg ring). 016_ioctl console TCGETS/TCSETS/TIOC*PGRP/SCTTY for
  vt<=1 → static_console. **QEMU-verified login→shell both arches, smoke PASS.**
- T8 #1648 console TIOCSWINSZ fix (was dead no-op) + `/dev` fd-link contract
  locked (vfs `dup_fd_target`/`parse_proc_fd`, 48 vfs tests). Audit confirmed
  /dev/std*, /dev/fd, /proc/self/fd/N, isatty/ttyname already correct post-T7.

## Remaining (tasks #9, #10)
- **T9 (#9) integration + QEMU acceptance** — run on BOTH arches: the /dev/fd
  userspace script (below), bash interactive (history/^C/^D/pipes), repeatability
  ×N (no nudge/wedge), dmesg≠shell-output. Add a hosted full-stack
  serial+console integration test. (vtconsole T5 already does VT end-to-end.)
- **T7b (#10)** — the remaining "exactly Linux" output arch: real printk
  `struct console` registry in klog (register_console; fan-out), fbcon renders
  the VT via vc_data as a printk console (lossless, replace klog aux byte-sink),
  migrate numbered VTs /dev/tty1..N to vtconsole. QEMU-verify fbcon screen.

## T9 QEMU /dev/fd acceptance script (paste into serial as root; expected → )
```
echo hi > /dev/stdout            # hi
echo via_fd > /dev/fd/1          # via_fd
readlink /proc/self/fd/0         # /dev/console
readlink /dev/stdin              # /proc/self/fd/0
readlink /dev/stdout             # /proc/self/fd/1
readlink /dev/fd                 # /proc/self/fd
tty                              # /dev/console
[ -t 0 ] && echo ISATTY0         # ISATTY0
stat -c %F /dev/console          # character special file
stty size                        # 24 80
```

## Login for testing: `root` + Enter (nullok, B72). B73 autologin branch OPEN
(unmerged, band-aid). qemu MCP: x86 KVM; arm; drive via qemu_run_until +
qemu_send_serial. NOTE qemu-mcp prompt-timing differs from `make smoke`
(smoke is the truth for "login: appears").

## Other open (pre-rebuild, parked): sched unified-engine WIP is stash@{0}
(`WIP-unified-sched-step1`) — return AFTER tty is 100%. sched-anal.md is its plan.

## Counters: F=420, B=73, C=10, D=92. Author Chris Watkins <chris@watkinslabs.com>.
