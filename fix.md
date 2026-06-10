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
