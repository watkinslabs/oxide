1. **Make `/dev/fb0` a real fbdev device**
   - Implement real fbdev data access instead of fake EOF/success behavior.
   - Add proper backing for userspace drawing, including mmap-style access or equivalent VFS support.
   - Handle the missing Linux fbdev ioctls: `FBIOGETCMAP`, `FBIOPUTCMAP`, `FBIOGET_VBLANK`, `FBIO_WAITFORVSYNC`.
   - Stop accepting `FBIOPUT_VSCREENINFO`, `FBIOPAN_DISPLAY`, and `FBIOBLANK` as silent no-ops unless they really work.
   - Support multiple framebuffer nodes (`/dev/fb1..N`) if multiple devices/CRTCs exist.

2. **Render actual terminal glyphs, not just ASCII**
   - The VT emulator stores Unicode and DEC special-graphics correctly, but the renderer collapses non-ASCII to `?`.
   - Add real glyph coverage for UTF-8, box drawing, and DEC line-drawing so the screen matches emulator state.
   - Wire in actual font/unicode mapping instead of keeping PSF structures unused.

3. **Fix cursor visibility and cursor repaint behavior**
   - Respect `vc.cursor_visible`; `?25l` currently changes state but not what gets drawn.
   - Repaint the old cursor cell when the cursor moves so reverse-video cursor artifacts do not remain behind.

4. **Unify VT switching so ioctls switch the real display**
   - `VT_ACTIVATE` currently updates VT bookkeeping only.
   - The visible framebuffer switch and input foreground switch happen separately in the keyboard path.
   - Make ioctl-driven VT switches update the active VT, framebuffer view, and input foreground through one shared path.

5. **Implement terminal query/response behavior**
   - CSI `n` / DSR / CPR requests currently do nothing useful.
   - Add Linux-like terminal replies for status and cursor-position queries so interactive programs behave correctly.

6. **Fill out the missing VT/KD ioctl surface**
   - Important Linux console ioctls are still unimplemented in the syscall layer.
   - Priorities: `VT_GETMODE`, `VT_SETMODE`, `VT_RELDISP`, `VT_SENDSIG`, `VT_RESIZE`, `VT_RESIZEX`, `TIOCLINUX`, `KDFONTOP`, and LED-related ioctls.

7. **Expose scrollback through real user-visible paths**
   - Scrollback exists internally in `Vc`, but I did not find a real control path exposing it to userspace or normal keyboard actions.
   - Add actual scrollback control plumbing if Linux-console compatibility is the goal.

8. **Turn the `vt` crate from a state shell into the real VT control plane**
   - Right now `drivers/vt` mostly stores metadata: active VT number, per-VT mode bits, keyboard mode, LED state, rows/cols, lock bit, and allocation state.
   - That is not enough for Linux compatibility. Linux VT behavior is not just a table of flags; it is the control plane that drives real console switching, process-mode handoff, release/acquire signaling, resize propagation, KD mode changes, and console-side ioctl behavior.
   - The current crate declares the Linux constants and wire structs, but most of the hard behavior behind them is missing or lives elsewhere.
   - `VT_ACTIVATE` currently changes bookkeeping, but does not itself switch the visible framebuffer VT or the live input foreground.
   - `VT_PROCESS` / `VT_ACKACQ` are effectively just enum values right now. There is no full process-controlled switch protocol with rel/acq signal delivery and handoff state.
   - `VT_SETMODE`, `VT_GETMODE`, `VT_RELDISP`, `VT_SENDSIG`, `VT_RESIZE`, `VT_RESIZEX`, `VT_GETHIFONTMASK`, `TIOCLINUX`, font ioctls, and LED ioctls need real implementation, not just constants.
   - Per-VT geometry is still basically static bookkeeping. It needs to be driven from the actual console geometry and resize path.
   - In practice this crate needs to become the single place that owns VT policy: activate/deactivate, process-mode switching, visible console routing, keyboard/LED mode state, size state, and ioctl semantics.

9. **Collapse onto one real TTY stack; remove the split between `tty` core and legacy `tty::live`**
   - The repo currently has two TTY paths:
     - the newer `TtyStruct` + `NTty` core in `kernel/tty/src/core.rs` and `ldisc/n_tty.rs`
     - the older per-VT `tty::live` path with its own ring buffers, line editing, termios store, pgrp/session store, wake queues, and canonical input handling
   - That split is a design problem. It means termios behavior, signal behavior, blocking rules, EOF handling, foreground-pgrp logic, and VT input semantics can diverge depending on which path a device is using.
   - The newer TTY core is the right direction: one lock-aware tty object, one N_TTY implementation, one wait model, one ioctl surface, one source of truth for winsize / fg pgrp / sid.
   - But it is not the sole owner yet. `tty::live` still carries real behavior, and some console paths still depend on it.
   - `tty::init()` still returns `NotImplemented`, which is another sign the subsystem is not fully consolidated under the new core.
   - `TtyStruct::ioctl()` is also thinner than it should be on its own; most of the meaningful ioctl behavior lives in the decoded helper / syscall layer instead of the core object surface.
   - The PTY layer still has simplified Linux semantics: partial termios behavior, simplified `VTIME`, simplified flow control, approximate canonical editing, and thin hangup behavior.
   - The old `tty::live` path also has explicit shortcuts like a `'\0'` EOF sentinel and best-effort session/pgrp behavior. That is legacy scaffolding now, not a final Linux-compatible implementation.
   - The fix is architectural, not cosmetic:
     - route console, serial, and pty behavior through the same `TtyStruct` / `NTty` model
     - move remaining `tty::live` responsibilities into the unified tty core or the VT control layer
     - make one authoritative source of truth for termios, winsize, session, foreground pgrp, blocking reads, and signal generation
     - then delete the duplicate legacy path

10. **Finish missing Linux TTY semantics in the unified core**
   - Blocking tty reads should be signal-interruptible the Linux way, not just input/EOF wakeups.
   - Full noncanonical termios timing semantics (`VMIN` + `VTIME`) need to be implemented; `VTIME` is still explicitly simplified away.
   - Driver lifecycle hooks (`open`, `close`, `hangup`) need real ownership and call sites, not just empty trait methods waiting to matter.
   - PTY flow control and hangup behavior need to stop being simplified approximations and become Linux-like behavior.
