# Console / TTY / VT analysis — what we have vs Linux, and the plan

Scope: code analysis + boot-path facts. Companion to `poll.md`. Goal: understand
why the serial "works but feels off" and the GTK/virtio-gpu window is blank, then
fix it the Linux way — no hacks.

## TL;DR

The tty/console stack is **not** a klog-passthrough hack. There is a real,
monomorphized **N_TTY line discipline** (canonical + echo + signals + i/o
translation) shared by the serial line and every numbered VT, real per-device
`TtyStruct`s, an fbcon terminal emulator on the virtio-gpu framebuffer, keyboard
routed into the foreground VT's ldisc, job control, ctty, and `console=` parsing.

So the "terminal is broken" feeling is mostly **misattribution**: the window is
blank because the boot **stalls at sysinit** (the userdb `GetMemberships("lp")`
loop, see `poll.md`) **before `getty.target`**, so no `getty@tty1` ever runs in
the window and no `serial-getty@ttyS0` ever runs on the wire. The only shell youmlinks present or not, and whether the lp lookup hangs). That pins the userdb root cause without depending on you or boot-looping. This is the right way to use the debug shell we kept on serial.

get is `systemd.debug_shell=ttyS0` (deliberately started early for debugging).

Real, fixable divergences from Linux do exist, but they are narrow (below).

## 1. How qemu boots us

Chain (from `make qemu-x86` → `xtask grub`, `tools/xtask/src/image_qemu/x86_64.rs`):

```
make qemu-x86
  └─ xtask grub --arch x86_64
       ├─ build kernel ELF → boot/oxide-x86_64
       ├─ GRUB rescue ISO, grub.cfg:
       │     serial --unit=0 --speed=115200
       │     terminal_input serial console ; terminal_output serial console
       │     multiboot2 /boot/oxide-x86_64 BOOT_IMAGE=... root=/dev/oxide0 rw quiet \
       │        console=ttyS0,115200 console=tty0 \
       │        systemd.mask=... systemd.debug_shell=ttyS0
       └─ qemu-system-x86_64:
             -serial <stdio,id=ser0[,mux=on],signal=off>   # UART ↔ your terminal
             -vga none                                      # no std-VGA
             -device virtio-gpu-pci                         # THE display (GTK window)
             -device virtio-keyboard-pci                    # window keyboard
             -device virtio-mouse-pci                       # window pointer
             -device virtio-blk-pci drive=root (/dev/oxide0)
             ...
```

Key consequences of the cmdline `console=ttyS0,115200 console=tty0`:

- Two kernel consoles requested: the 16550 UART (`ttyS0`) and the VT/fbcon (`tty0`).
- **Last `console=` wins** for `/dev/console` (Linux rule) → `/dev/console` = `tty0`
  = the virtio-gpu window. systemd's stdio and the *primary* login land there.
- `ttyS0` is a secondary kernel console + (when the boot gets far enough)
  `serial-getty@ttyS0`.
- `systemd.debug_shell=ttyS0` → `debug-shell.service` runs a root `sh` on the
  serial **early**, independent of `getty.target`. This is the shell you reached.

## 2. Linux reference model (what "correct" looks like)

**Serial (`ttyS0`) — two decoupled users of one UART:**
- printk writes **raw, polled, straight to the UART**, independent of any tty open.
  Always on; interleaves with a shell.
- `/dev/ttyS0` is a tty with **N_TTY**: canonical/line-buffered, ECHO, ISIG
  (^C→SIGINT), ICRNL (CR→NL), ONLCR (NL→CRLF), VMIN/VTIME.
- `serial-getty@ttyS0` opens it, sets termios, prints `login:`, execs login→shell.

**Window (`tty0`/`tty1..N`) — the VT subsystem:**
- fbcon renders text cells onto the GPU framebuffer; `console=tty0` mirrors printk
  there; keyboard arrives via the input layer into the foreground VT's N_TTY.
- `getty@tty1` runs the login in the window; VT switch Ctrl-Alt-Fn.
- A graphical session (gdm/Wayland) later takes the DRM device from fbcon.

`/dev/console` = the preferred console (last `console=`); init seeds fd 0/1/2 on it.

## 3. What we actually have (cited)

Real and Linux-shaped:

- **Serial tty** `/dev/ttyS0` (4:64): node `console/src/devnodes.rs:18`; `SerialFileOps`
  `console/src/serial.rs:68`; backed by a real `TtyStruct<SerialTtyDriver<..>>`
  `console/src/static_console.rs:57`.
- **N_TTY ldisc** `tty/src/ldisc/n_tty/` — defaults `ICANON|ECHO|ISIG`, `ICRNL`,
  `OPOST|ONLCR` (`state.rs:52`). Echo `state.rs:140`; canon `state.rs:317`; ISIG
  ^C/^\/^Z `state.rs:256` (raises via sched registry `static_console.rs:43`);
  input map ICRNL/INLCR `state.rs:359`; output OPOST/ONLCR `state.rs:378`; VMIN
  honored `ops.rs:84`.
- **termios ioctls** TCGETS/TCSETS{,W,F} wired to the ldisc `syscalls/016_ioctl/tty_ioctl.rs:116`
  (so login's echo-off + bash raw mode work).
- **UART** interrupt RX `drv-uart-16550/src/lib.rs:126` → `drv-serial deliver`
  → tty `receive_from_driver` → N_TTY. TX `emit` polls THR (`lib.rs:110`).
- **klog vs tty decoupled**: `klog::set_byte_sink(drv_serial::emit)` `kmain/runtime.rs:46`;
  the tty write path *also* ends at `drv_serial::emit`; they share the UART with
  **no lock** and interleave byte-wise — exactly Linux printk-vs-login. Opening
  `/dev/ttyS0` does NOT redirect klog.
- **VTs** `/dev/tty1..63` each a real `TtyStruct<VtConsoleDriver>` on the same
  N_TTY core `console/src/vt_tty.rs:126`; write → `fbcon::kernel::vt_write` →
  emulator → cell blit on virtio-gpu `fbcon/src/kernel/runtime.rs:89`.
- **Keyboard → ldisc**: virtio-input EV_KEY → bytes → `tty::live::input_push_byte`
  `drv-virtio-input/.../key_event.rs:90` → `console::kbd_input` → **foreground VT's**
  `receive_from_driver` (`console/src/serial.rs:100`). Cooked+echoed on the fb.
- **`/dev/console`** (5:1) `console/src/vt_console.rs:154` routes each I/O by
  `cmdline::preferred_console()` → serial or fg-VT. `console=` parsed at
  `cmdline/src/lib.rs:85` (last-wins `preferred_console_in`). init fd 0/1/2 seeded
  on `/dev/console` `vt_console.rs:205`.
- **fbcon klog mirror**: `klog::set_aux_sink(fbcon::kernel::vt_console_sink)`
  `drv-virtio-gpu/src/post_init/scanout.rs:247`.

## 4. The observed symptoms, reconciled

- **"serial shell works but I had to press Enter"** → that's `debug-shell.service`
  (`systemd.debug_shell=ttyS0`), started early. N_TTY echo/canonical are real, so
  once it prompts it behaves normally. The "press Enter to see it" is just the
  prompt having scrolled under boot output — cosmetic.
- **"GTK window is blank"** → two independent reasons, must be split:
  1. **No getty runs there yet.** The boot stalls at sysinit (userdb loop,
     `poll.md`) *before* `getty.target`, so `getty@tty1` never starts → no login
     prompt in the window. This is the dominant reason and is NOT a console bug.
  2. **Open question: does fbcon actually scan out?** printk has an aux sink to
     fbcon, so kernel boot lines *should* appear in the window even pre-getty. If
     the window is **totally** blank (no kernel text at all), the virtio-gpu
     scanout/flush is not live and that IS a real console bug. **Must verify.**
- **"console output stops ~20s"** → not a hang and not a console redirect: the
  boot simply stalls (nothing new logs) and the periodic debug tick goes quiet
  when the system idles. System is alive (shell responds).

## 5. Real divergences from Linux (the actual gap list)

**RE-AUDIT 2026-07-10 (session b18a1478): G3(x86)/G4/G5/G6 are all CLOSED since
this doc was written; G1 is closed by observation; only the pl011/aarch64 baud
item remains, gated on DTB-clock parsing.** Status column updated below.

| # | Gap | Where | Status 2026-07-10 |
|---|---|---|---|
| G1 | fbcon scanout present to the virtio-gpu window | `drv-virtio-gpu/src/post_init/scanout.rs`, `fbcon/src/kernel/runtime.rs` | **CLOSED (observed):** the window shows scrolling kernel log + updates live during userland (console2.md ground truth) → fbcon scans out. Blank *login* is G2, not a console bug. |
| G2 | No `getty@tty1` / `serial-getty@ttyS0` reached because boot stalls at sysinit | boot blocker = systemd-userdb loop (`[[desktop-blocker-tmpfiles-userdbd]]`) | OPEN, but USERSPACE (not console): stock systemd `[SUCCESS=merge]` GetMemberships loop in `../images`; kernel af_unix path verified correct. |
| G3 | TCSETS baud reprogram | x86 `serialtty/src/lib.rs` + `drv-uart-16550`; arm `drv-uart-pl011` | **x86 CLOSED:** `set_termios`→`set_baud(c_ospeed)`→16550 divisor reprogram (fixed 1.8432 MHz clock). **arm CLOSED (F698):** `dtb::pl011_clock_hz()` walks the `arm,pl011` node's `clocks` phandle → clock node `clock-frequency` (Linux `clk_get_rate`), boot publishes it to `hal_aarch64::pl011::uartclk_hz()`, and `pl011` `set_baud` computes IBRD/FBRD against the real DTB UARTCLK (24 MHz fallback). No longer an assumed constant. |
| G4 | printk console set data-driven per `console=` token | `kmain/kmain/runtime.rs:49`, `scanout.rs:251`, `cmdline` `console_classes()` | **CLOSED:** serial byte sink gated on `console_classes().0`, fbcon aux sink on `console_classes().1`, both parsed from every `console=` token (Linux `register_console` per token). |
| G5 | `VMIN`/`VTIME` blocking policy (all 4 cases + inter-byte timer) | `tty/src/core/tty.rs` `read_raw` (drives `park_commit_deadline` off `vtime()`) | **CLOSED:** full VMIN/VTIME lives in the tty core `read_raw`; the n_tty `ops.rs` fast path is VMIN-gated as designed (comment at `ops.rs:80`). |
| G6 | kbd-sink doc comment | `tty/src/live.rs:29` | **CLOSED:** comment now correctly says foreground-VT `TtyStruct`, NOT serial `static_console`. |

**VT/console ioctl surface — audited complete + real (not stubs)** (`syscalls/016_ioctl/vt.rs`):
KDGETMODE/KDSETMODE (KD_TEXT/KD_GRAPHICS handoff), KDGKBMODE/KDSKBMODE, KDGKBTYPE
(KB_101), KDSIGACCEPT, VT_OPENQRY, VT_GETSTATE, VT_ACTIVATE (real switch),
VT_WAITACTIVE (blocks on the VT_PROCESS/VT_RELDISP handshake, EINTR-safe),
VT_GETMODE/VT_SETMODE/VT_RELDISP (full process-mode switch protocol with vpid+tid
ownership checks), VT_DISALLOCATE, VT_LOCK/UNLOCKSWITCH, VT_RESIZE/RESIZEX (raises
SIGWINCH on the fg pgrp), KD{G,S}ETLED/KD{G,S}KBLED, KDFONTOP/PIO_UNIMAP (setfont),
TIOCLINUX; TIOCGWINSZ/TIOCSWINSZ/TIOCSCTTY/TIOCNOTTY on the tty core. VT_SENDSIG→
EINVAL is a documented Linux-parity decision (Linux `vt_ioctl` has no case for it).
This is the full getty/login/logind/X VT-handshake set — Goal-1 "usable VT login"
is kernel-ready; it only awaits G2 (userspace) so `getty@tty1` actually starts.

## 6. Plan — the Linux way, ordered by impact

**Step 0 — Verify G1 before touching code (no guessing).**
Boot and look at the actual virtio-gpu window (or dump the scanout buffer):
does it show the kernel boot text (fbcon aux sink) or is it *totally* blank?
- If it shows kernel text → fbcon works; the window "blank" is only G2 (no getty)
  → G1 is closed, focus shifts entirely to the `poll.md` boot blocker.
- If totally blank → fix virtio-gpu scanout: confirm the driver creates a scanout
  resource, attaches the framebuffer, and issues `RESOURCE_FLUSH`/`SET_SCANOUT` on
  each fbcon update (`scanout.rs`). This is the only console item that blocks
  "visible graphics."

**Step 1 — Unblock the boot so gettys actually start (the real "usable" gate).**
This is `poll.md`'s territory (userdb `GetMemberships` loop), not console. Until
sysinit completes, `getty.target` → `getty@tty1` / `serial-getty@ttyS0` never run,
so neither the window nor the serial ever shows a *login*. Fixing the boot stall
is what makes the console "usable" in the Linux sense.

**Step 2 — Data-drive the printk console set from `console=` (G4).**
`register_console` per parsed `console=` token instead of hardcoding byte/aux
sinks. Small, makes `console=` behave exactly like Linux and removes a latent
"added a UART but printk doesn't use it" trap. Not blocking.

**Step 3 — Minor termios/UART fidelity (G3, G5) + doc fix (G6).**
Reprogram the UART divisor on `set_termios` baud; implement `VTIME` inter-byte
timing; correct the stale kbd-sink comment. Low priority, do when touching those
files.

## 7. What NOT to do

- Do not "rewrite the console" — the ldisc/VT/fbcon stack is already Linux-shaped.
- Do not attribute the blank window to the tty layer before verifying G1.
- Do not chase the "hang at ~20s" as a console/timer bug — it is the sysinit
  stall (`poll.md`) making the console idle-quiet.

## Bottom line

**RE-AUDIT 2026-07-10: the console is ~100% Linux-correct at the kernel level.**
G1 is closed by observation (fbcon scans out — the window shows live kernel log),
G3(x86)/G4/G5/G6 are all implemented (see the updated §5 status column), and the
full VT/KD ioctl handshake surface (VT_ACTIVATE/WAITACTIVE/SETMODE/RELDISP,
KDSETMODE graphics handoff, VT_RESIZE→SIGWINCH, etc.) is real, not stubbed — a
getty/login in the window is *kernel-ready*. **UPDATE 2026-07-10 (F698): the pl011
UARTCLK is now DTB-sourced — the console kernel stack has ZERO remaining Linux
divergences.** The ONLY remaining console-layer
divergence is **pl011/aarch64 TCSETS baud reprogram**, correctly deferred on DTB-
clock (`UARTCLK`) parsing — not a lazy stub (writing a divisor without the real
UARTCLK programs a *wrong* baud, and qemu's host chardev ignores the rate, so the
item has zero observable effect until DTB-clock parsing lands). "Visible graphics"
is now gated by exactly ONE thing: **G2**, the sysinit boot stall — which this
session proved is a stock-systemd userspace issue (`[SUCCESS=merge]` GetMemberships
loop in `../images`), with every kernel af_unix/epoll/tty path verified correct.
Nothing in the console kernel stack blocks the login; it awaits userspace.
