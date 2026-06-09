# TTY / VT / console / serial rebuild — the Linux way (exact)

Goal: replace the `ConsoleInode`+`klog`-funnel hack with the **actual Linux**
console/tty/VT/serial architecture. Same structures, same boundaries, same data
flow. Verifiable over serial + framebuffer at every step. No knockoffs.

Status legend: ☐ todo ◐ in-progress ☑ done (verified).

---

## 0. The Linux architecture we are copying (reference, code-level)

Layers (each is a distinct Linux source area):

1. **TTY core** — `drivers/tty/tty_io.c`. `struct tty_struct` (per open terminal),
   `struct tty_driver` (per class: console/serial/pty), `struct tty_port`.
   `open(/dev/ttyN|ttyS0|pts/*)` → `tty_struct` bound to its driver + termios + ldisc.
   `tty_read`/`tty_write` dispatch into the ldisc.

2. **Line discipline N_TTY** — `drivers/tty/n_tty.c` (`tty_ldisc_ops`):
   - output: `n_tty_write` → `process_output_block`/`do_output_char` (OPOST, ONLCR,
     OCRNL, tab, col tracking) → `tty->ops->write` (the driver).
   - input: driver pushes RX via `tty_insert_flip_char` + `tty_flip_buffer_push` →
     `n_tty_receive_buf` → ICANON line edit, ECHO (echo re-enters the *driver*
     write path so it renders), ISIG (Ctrl-C/Z → `kill_pgrp` on fg pgrp), IEXTEN,
     assemble lines → `n_tty_read` returns to user.

3. **TTY drivers** (the `tty->ops->write`/`ops->*` targets):
   - **VT console driver** — `drivers/tty/vt/vt.c`, `con_write` → `do_con_trol`:
     the ECMA-48 / vt102 **emulator**. Mutates the **per-VT screen buffer**, then
     calls the renderer via `consw`.
   - **serial driver** — `serial_core.c` (`uart_ops`): write = enqueue to the
     16550/PL011 TX; RX IRQ → `uart_insert_char` → flip buffer → ldisc.
   - **pty** — `pty.c`: master↔slave, slave is a tty with N_TTY, master is raw.

4. **VT data + renderer** (two different objects — do not conflate):
   - `struct vc_data` (`include/linux/console_struct.h`), `vc_cons[MAX_NR_CONSOLES]`,
     `fg_console`: per-VT **screen buffer** `vc_screenbuf` (glyph+attr cells),
     cursor (`vc_x`,`vc_y`,`vc_pos`), `vc_cols`/`vc_rows`, scrollback, attrs,
     emulator state. THIS IS THE DATA.
   - `struct consw` (`include/linux/console.h`): the **renderer**. `fbcon`
     (`drivers/video/fbdev/core/fbcon.c`), `vgacon`, `dummycon` implement it
     (`con_init`,`con_putc`,`con_putcs`,`con_scroll`,`con_cursor`,`con_switch`,
     `con_blank`). fbcon **blits vc_data cells** to the framebuffer, repaints on
     VT switch. fbcon never sees a byte stream.

5. **printk consoles — SEPARATE registry** (`struct console`, `register_console`,
   `kernel/printk/printk.c`). `printk` → log buffer → `console_unlock` fans to
   every registered console:
   - serial console (`uart_console_write`) → UART directly;
   - VT console (`vt_console_driver`→`vt_console_print`) → writes into `fg_console`
     `vc_data` via the emulator → fbcon.
   A UART registers BOTH a tty (`ttyS0`, N_TTY login) AND optionally a `console`.

Two load-bearing facts:
- **(a) tty-write and printk are SEPARATE paths**; they converge only at the output
  *device*. A user shell write never touches the printk/kmsg ring.
- **(b) the VT owns the screen buffer; consw renders it.** fbcon is downstream of
  `vc_data`, not of a byte funnel.

### Canonical data flows (must hold after rebuild)

- **VT write**: `write(fd→/dev/ttyN)` → tty core → N_TTY `process_output` (OPOST/
  ONLCR) → VT driver `con_write` → vt102 emulator mutates `vc_data[N]` → consw
  (fbcon) blits cells. NOT into kmsg ring.
- **Serial write**: `write(fd→/dev/ttyS0)` → N_TTY OPOST → serial driver → UART TX.
- **VT input/echo**: kbd/UART-RX byte → driver flip buffer → N_TTY receive → ICANON
  edit + ECHO (echo char goes back out the driver write → emulator → fbcon) + ISIG
  → line ready → `read` returns.
- **printk**: `klog` → log ring → for each registered console: serial console →
  UART; vt console → `fg vc_data` emulator → fbcon. Independent of any tty.
- **VT switch** (`fg_console` change): consw repaints the new vc_data; input routes
  to the new fg tty.

---

## 1. Gap analysis (oxide today, code-cited)

| Linux structure | oxide today | gap |
|---|---|---|
| `tty_struct`+`tty_driver`+`tty_port`+ops | `ConsoleInode` (a VFS `Inode`) does `read`/`write` directly (`console/lib.rs`) | no tty core, no driver abstraction, no ops table, no tty_struct lifetime |
| N_TTY ldisc as a layer | input cooking+echo in `tty/live.rs` (`feed`, `echo_byte`, `flush_line`), output OPOST/ONLCR in `ConsoleInode::write` | ldisc is split across two crates and inlined into the inode; not a swappable discipline; echo bypasses the driver (goes straight to klog) |
| `vc_data[]` per-VT screen buffer | none. VT = input-only (`VT_RINGS`/`VT_TERMIOS`/`VT_LINES`/`VT_WAITERS`/pgid/sid). screen state is one **global** `fbcon::Console` emulator | no per-VT screen, no scrollback as data, no VT-switch of content |
| `consw` renders `vc_data` | `fbcon::Console` IS the emulator AND renderer, wired as a **klog aux sink** fed a byte stream; `klog_sink` uses `try_lock`→**drops bytes** | renderer is fed bytes not cells; lossy; not driven by the VT layer |
| `struct console` printk registry | `klog` `BYTE_SINK`(serial)+`AUX_SINK`(fbcon) ad-hoc fan-out (`klog/lib.rs:178 invoke_sink`) | no console registry; **tty output is funneled through `invoke_sink`** so `/dev/console` writes ALSO `ring_push` into the 64 KiB kmsg ring (`console/lib.rs:30 console_emit=write_raw`) — shell output pollutes dmesg |
| VT console + serial console registered consoles | hardcoded `set_byte_sink`/`set_aux_sink` in `kmain.rs` | no register_console; can't add/remove consoles; printk and tty share one funnel |
| serial dual-role (ttyS0 tty + serial console) | serial is only a klog byte sink + a poll-driven RX (`drv_serial::poll` on timer tick) | no serial tty driver; RX is timer-polled not flip-buffered; no separate serial console object |
| input delivery | UART RX timer-polled → `tty::live` line discipline directly; lost-wakeup race in `ConsoleInode::read` park loop | not a flip buffer → ldisc receive; RX should be IRQ/flip-driven; read-park race (separate bug, fixed by correct ldisc wait) |
| `/dev/{console,tty,tty0,ttyN,ttyS0}` nodes | `console::register_devnodes` registers `ConsoleInode`s in devfs | nodes exist but are inodes not tty devices; `/dev/tty` should resolve to the *controlling* tty of the caller, not always fg |
| `/dev/fd`, `/proc/self/fd`, `/dev/std{in,out,err}` | `init_console_fd_table` sets fd0/1/2 to `/dev/console` dentry; `/proc/self/fd` exists | must verify readlink targets, symlink-follow reopen, isatty/ttyname after rebuild |

Net: oxide collapsed **5 Linux layers into 2** (`ConsoleInode` + `klog` funnel),
made the VT input-only, and made fbcon a lossy byte-mirror. The rebuild restores
the 5 layers.

---

## 2. Target crate / module layout (Linux boundaries)

```
crates/kernel/tty/            # TTY CORE (was: input-only live.rs)
  src/core.rs                 #   tty_struct, tty_driver trait, tty_port, registry, ops
  src/termios.rs              #   termios bits (move from pty.rs)
  src/ldisc/                  # LINE DISCIPLINE
    n_tty.rs                  #   N_TTY: output OPOST/ONLCR, input ICANON/ECHO/ISIG
    mod.rs                    #   LdiscOps trait + N_TTY registration
  src/pty.rs                  #   pty master/slave (keep, re-home onto tty core)
crates/kernel/vt/             # VT LAYER (new)
  src/vc.rs                   #   vc_data: per-VT screen buffer + cursor + attrs + scrollback
  src/emulator.rs             #   ECMA-48/vt102 state machine (relocated from fbcon::Console)
  src/console_driver.rs       #   the VT tty_driver: con_write → emulator → consw
  src/consw.rs                #   consw trait (con_putcs/con_scroll/con_cursor/con_switch...)
crates/drivers/fbcon/         # RENDERER (recast)
  src/lib.rs                  #   impl consw for fbcon: blit vc_data cells; repaint on switch; REAL lock
crates/kernel/serialtty/      # SERIAL TTY DRIVER (new; wraps drv-serial)
  src/lib.rs                  #   ttyS0 tty_driver (TX enqueue, RX flip-buffer→ldisc) + serial console
crates/shared/klog/           # PRINTK
  src/console.rs              #   struct console registry + register_console; printk → consoles
                              #   (BYTE_SINK/AUX_SINK become two registered consoles)
crates/kernel/console/        # /dev nodes (recast)
  src/lib.rs                  #   /dev/{console,tty,tty0,ttyN,ttyS0,pts/*} → tty_struct lookup
```

CLAUDE.md rules apply: `#![no_std]`, `# C:` on pub fns, SAFETY≥30, file ≤1000 lines,
typed constants, klog gated, no dyn-HAL. consw/ldisc/tty_driver are **generic
traits monomorphized**, not `dyn` (mirror the HAL-trait rule).

---

## 3. Task breakdown (ordered; each ships with tests + serial verify)

Foundation-first: data (vc_data+emulator) → renderer (consw/fbcon) → ldisc →
tty-core+drivers → printk-console-split → /dev-node correctness → acceptance.

- **T1 ☐ vc_data + emulator (data layer).** New `vt` crate. `Vc` struct: cell grid
  `[Cell{glyph:u32, attr:u16}]`, cursor, rows/cols, scrollback ring, saved-cursor,
  modes (DECAWM, IRM…), G0/G1 charset. Port the ECMA-48/CSI state machine out of
  `fbcon::Console` into `emulator.rs` operating on `Vc`. `vc_cons[N_VT]`, `fg`.
  Tests: golden emulator tests (input byte stream → expected cell grid + cursor):
  plain text, `\n`/`\r`, BS, TAB, wrap, scroll, CSI cursor moves, SGR colors, ED/EL
  erase, save/restore cursor, DECAWM, UTF-8 decode. No rendering yet.

- **T2 ☐ consw trait + fbcon renderer.** `consw.rs` trait (`con_init`, `con_putcs`,
  `con_clear`, `con_scroll`, `con_cursor`, `con_switch`, `con_bmove`). Recast fbcon
  to **render a `Vc`** (blit changed cells), **real Spinlock** (no `try_lock`-drop),
  repaint-all on `con_switch`. Emulator calls consw after each screen mutation
  (dirty-region or full). Tests: mock consw records ops; assert emulator drives
  correct putcs/scroll/cursor sequences. fbcon glyph-blit unit test against a
  fake framebuffer (assert pixels for a known glyph).

- **T3 ☐ LdiscOps trait + N_TTY.** `ldisc/mod.rs` trait: `receive_buf(tty,&[u8])`,
  `read(tty,buf)`, `write(tty,buf)`, `poll(tty)`, `ioctl`. `n_tty.rs`: output
  `process_output` (OPOST/ONLCR/OCRNL/tab/col-track), input `receive_buf` (ICANON
  line edit incl ERASE/KILL/WERASE/EOF/EOL, ECHO via tty driver write, ISIG →
  signal fg pgrp, ICRNL/INLCR/IGNCR, IEXTEN/lnext, raw mode passthrough), `read`
  (canonical line vs raw VMIN/VTIME), `poll`. Tests: hosted, drive bytes through
  N_TTY with a mock tty driver; assert cooked lines, echo bytes, signals raised,
  raw passthrough, ERASE/KILL/WERASE, EOF (^D) → 0-length read, ONLCR on output,
  10M-op proptest on the cook/uncook round-trip where applicable.

- **T4 ☑ TTY core (tty_struct/tty_driver/registry).** `core.rs`: `TtyDriver`
  trait (`write`, `flush`, `ioctl`, `set_termios`, `install`/`open`/`close`),
  `TtyStruct` (termios, ldisc=N_TTY, port, fg_pgrp, sid, winsize, ctrl-tty link),
  `TtyPort` (flip buffer in→ldisc), driver registry keyed by (major,minor). Tests:
  open/close lifetime, termios get/set, winsize, flip-buffer→ldisc receive,
  pgrp/sid plumbing, TIOC* ioctls.

- **T5 ☑ VT console driver onto tty core.** New crate `crates/kernel/vtconsole`
  (`tty`+`vtdata`+`fbcon`; `tty` stays free of vtdata/fbcon — no cycle).
  `VtConsoleDriver<R: Consw, S: FgSignal>`: `vc_cons[N_VT]` + `fg`, one `Emulator`,
  renderer `R`, signal sink `S`. `TtyDriver::write` → `emulator.feed_bytes(vc)` →
  `vtdata::render(vc, renderer)` (shared by program writes + ldisc echo). `assemble`
  factory builds `TtyStruct<VtConsoleDriver<R,S>, W>`. Host-tested END-TO-END
  through the real N_TTY+core+emulator+Vc+consw: program-write→cells+cursor,
  input→read+echo→screen, password ECHO-off (read line, blank screen),
  ctrl-C→SIGINT to fg pgrp, CSI SGR red attr through the stack, backspace editing,
  256-case proptest (interleaved write/recv/read, in-bounds, never panics). 8/8
  green; both kernel-target builds + spec-lint clean. NOT yet wired to `/dev/ttyN`
  (boot cutover is T7).

- **T6 ☐ serial tty driver + RX flip.** `serialtty`: `ttyS0` `TtyDriver` (TX →
  `drv_serial` UART; RX → flip buffer → ldisc). Replace the timer-poll-direct-to-
  live path with RX→port→N_TTY. Keep timer poll only as the RX source until a real
  UART RX IRQ lands (documented). Tests: TX OPOST to UART mock; RX byte → read;
  echo; signals.

- **T7 ☐ printk console registry + split.** `klog/console.rs`: `Console` registry
  (`register_console`/`unregister`); `klog` emit fans to registered consoles only.
  Register (a) **serial console** (→UART, the durable copy), (b) **VT console**
  (→fg vc_data emulator→fbcon). **Remove tty-write from the klog funnel**:
  `/dev/console` + echo no longer call `klog::write_raw`; they go through the tty
  driver. Result: shell output NOT in kmsg ring; `dmesg` shows only kernel logs.
  Tests: printk → both consoles; a tty write does NOT appear in the kmsg ring;
  kmsg ring only contains kernel/`/dev/kmsg` records.

- **T8 ☐ /dev node + fd/symlink correctness.** `/dev/console` = the system console
  (boot console / fg VT). `/dev/tty` = the **caller's controlling tty** (per-task
  ctty), NOT always fg. `/dev/tty0` = current fg VT. `/dev/ttyN` = VT N. `/dev/ttyS0`
  = serial tty. `/dev/pts/*` via ptmx. Verify: `/dev/std{in,out,err}` →
  `/proc/self/fd/{0,1,2}` → real node; `/dev/fd` → `/proc/self/fd`; `readlink
  /proc/self/fd/0` = the open node path; symlink-follow reopen works; `isatty`/
  `ttyname`/`tcgetattr` on fd0; `TIOCGWINSZ`/`TIOCSWINSZ`; `tcsetpgrp`/`tcgetpgrp`;
  `TIOCSCTTY`/`TIOCNOTTY`. Tests: hosted vfs-level + QEMU userspace.

- **T9 ☐ integration + acceptance.** End-to-end: serial login deterministic over
  N boots (no lost-wakeup, no nudge needed); bash interactive (history, line edit,
  ^C, ^D, ^Z, ^W, pipes, job control prompt); `tty`, `stty`, `isatty`, `echo >
  /dev/tty`, `cat` from /dev/tty; VT screen renders on fbcon (screendump assertion);
  dmesg vs shell-output separation; `/proc/self/fd` + `/dev/fd` + symlinks. Both
  arches (x86 + arm) reach the SAME milestones.

---

## 4. Test strategy (no way it can be silently wrong)

### Hosted unit (per layer, `cargo test`, milliseconds)
- **emulator golden tests** (T1): byte-stream → expected cell grid + cursor +
  attrs. Cover the whole CSI/SGR/charset/UTF-8 surface. 10M-op proptest:
  random byte streams never panic / never index OOB / cursor stays in bounds.
- **consw drive tests** (T2): mock consw asserts the emulator emits the right
  ops; fbcon blit test against a fake `fb_info` asserts pixels for known glyphs +
  scroll + cursor.
- **n_tty tests** (T3): mock tty driver; assert cooked lines, echo bytes, signals,
  raw passthrough, ERASE/KILL/WERASE/EOF/EOL, ICRNL/ONLCR, VMIN/VTIME, proptest
  round-trip.
- **tty core tests** (T4): open/close, termios, winsize, ioctls, flip→ldisc.
- **printk console tests** (T7): fan-out to N consoles; **kmsg-isolation test**:
  a tty write must NOT appear in the kmsg ring.

### Hosted integration (drive real layers against fixtures)
- Build a hosted harness that wires: fake fb (consw) ← vt(emulator+vc_data) ←
  console_driver ← n_tty ← tty_core, and a fake UART ← serialtty ← n_tty.
  Drive full sequences (login prompt, password echo-off, bash line) and assert
  both the **cell grid** (what the screen shows) and the **read() stream** (what
  the program sees) and the **UART bytes** (what serial emits). This is the
  "no way it's wrong" net: every path asserted end-to-end without QEMU.
- **/dev correctness harness** (T8): over the vfs, assert readlink/symlink/reopen
  for `/dev/std*`, `/proc/self/fd/*`, `/dev/fd`, `/dev/tty` ctty resolution,
  isatty/ttyname.

### QEMU acceptance (final gate, both arches)
- Deterministic serial login ×N (script: boot → login → shell → command → repeat),
  no nudge, no wedge. bash interactive matrix. fbcon screendump assertion (MCP
  `qemu_screen`) shows the rendered VT. dmesg≠shell-output. Drive via qemu MCP.

### Regression guards to keep (from this session)
- Login must succeed→shell repeatedly (not just prompt appears).
- No lost-wakeup in blocking read (T3 ldisc wait covers it).
- Both arches lockstep (CLAUDE.md HARD RULE).
- `nullok` root login + (optional) autologin remain available for test determinism
  (B72 merged; B73 autologin branch open — keep as a TEST image toggle, the REAL
  fix is the ldisc race + correct tty, not the band-aid).

---

## 5. Execution protocol (the loop)

Per task Tn: branch `Pxx`/`Fxx` → implement layer → hosted unit + integration
tests green → spec-lint clean → `make x86 && make arm` build → serial verify via
qemu MCP for the user-visible ones → PR → merge → next task. Update this file's
status legend + state.md each task. Do not advance a layer until its tests are
green (foundation-before-wiring). Keep patches single-purpose. Stop only on a hard
blocker; otherwise run the ladder T1→T9 to completion.

---

## 6. Open questions / decisions
- N_VT: keep 63 (Linux MAX_NR_CONSOLES default). fg pinned to 1 until kbd VT-switch.
- Scrollback depth: start 0 (no scrollback) for T1, add later — vc_data still owns
  the visible screen. (Linux default 32KB; not load-bearing for correctness.)
- UART RX: remain timer-polled as the RX *source* feeding the flip buffer until a
  real 16550/PL011 RX IRQ lands; the ldisc/flip path is identical either way.
- Spec docs/28 + docs/16 will be revised (D-branch) to match once code is frozen;
  code is the source of truth for this rebuild.
