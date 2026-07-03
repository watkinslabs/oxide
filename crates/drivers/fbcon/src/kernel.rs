// Kernel-side per-VT framebuffer consoles (tty-rebuild-plan §3-P3).
//
// Linux model: `vc_cons[MAX_NR_CONSOLES]` each holding a `vc_data`
// (screen buffer + emulator state), one `fg_console` index, and ONE
// physical framebuffer driven by the `consw` of whichever VT is
// foreground. printk (`vt_console_print`) writes to `fg_console`.
//
// This module realizes that:
//   * `VcCell` = { vc: Vc, em: Emulator } — one per VT, LAZILY allocated
//     (each `Vc` carries RGB cells + 1000-line scrollback, so eager ×63
//     would blow the heap). Index 0 = the system/printk console built by
//     `kernel_init`. Indices 1..=N_VT = the numbered `/dev/ttyN` devices.
//   * ONE shared `VcRenderer` (the single physical FB) + an `fg` index.
//     Only the FG vc is blitted to the FB; offscreen VTs update their
//     `Vc` only (no blit).
//   * `vt_write(vt, bytes)` — device write to a numbered VT (real lock).
//     Any DSR/CPR answerback the emulator produces is QUEUED (not injected)
//     for deferred, lock-safe delivery — see the answerback-queue block.
//   * `vt_console_sink(bytes)` — printk; writes to the CURRENT fg VT
//     (Linux `vt_console_print` → `fg_console`), best-effort `try_lock`.
//     NEVER produces an answerback (printk text carries no query).
//   * `drain_answerback()` — tick-driven (`flush_to_ldisc` analogue) drain
//     of the per-VT answerback queues into the tty input rings, lock-free.
//   * `switch_vt(n)` — set fg=n + full repaint from vc_cons[n].
//
// Re-entrancy: `vt_console_sink` is best-effort (skips its blit if the
// lock is held by a device write); the SERIAL console is a SEPARATE klog
// slot (`drv_serial::emit`), so durable serial logs never depend on the
// fbcon blit. One `Spinlock` guards the whole state (array + fg +
// renderer) — single lock-order, no per-slot deadlock surface.

extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use sync::{Spinlock, Tty as TtyClass};
use vtdata::{Consw, Emulator, Vc, N_VT};

use crate::vcrender::VcRenderer;

/// One virtual console: screen buffer (`Vc`) + ECMA-48 emulator. The
/// shared `VcRenderer` lives in `VtState`, not here, since only the fg
/// VT is ever blitted.
struct VcCell {
    vc: Vc,
    em: Emulator,
}

/// Total `vc_cons` slots: index 0 = system/printk console, 1..=N_VT =
/// the numbered `/dev/ttyN` devices (matches `ConsoleInode.vt`).
/// # C: const.
const N_SLOTS: usize = N_VT + 1;

/// Per-VT framebuffer console state. `vc_cons[i]` is lazily allocated on
/// first write/switch to VT `i`. `fg` is the foreground VT (0..N_SLOTS);
/// only `vc_cons[fg]` is blitted to `renderer`. `cols`/`rows` size newly
/// allocated VTs to the physical framebuffer's cell grid.
struct VtState {
    vc_cons: [Option<Box<VcCell>>; N_SLOTS],
    fg: u8,
    renderer: VcRenderer,
    cols: u16,
    rows: u16,
}

impl VtState {
    /// Ensure `vc_cons[vt]` exists, allocating a blank `Vc`+`Emulator`
    /// sized to the renderer's cell grid on first touch. Out-of-range
    /// `vt` clamps to a valid slot. Returns the resolved index.
    /// # C: O(cols*rows) on first alloc, else O(1).
    fn ensure(&mut self, vt: u8) -> usize {
        let i = (vt as usize).min(N_SLOTS - 1);
        if self.vc_cons[i].is_none() {
            self.vc_cons[i] = Some(Box::new(VcCell {
                vc: Vc::new(self.cols, self.rows),
                em: Emulator::new(),
            }));
        }
        i
    }
}

static VT_STATE: Spinlock<Option<VtState>, TtyClass> = Spinlock::new(None);

/// Reinterpret a 0x00RRGGBB pixel slice as a BGRA32 byte slice for the
/// flush thunk. On a little-endian target the native u32 byte order is
/// B,G,R,0 which matches the BGRA32 framebuffer the thunk expects.
/// # C: O(1).
fn pixels_as_bytes(px: &[u32]) -> &[u8] {
    // SAFETY: u32 slice reinterpreted as a 4x-longer u8 slice of the same allocation; pixels are plain data with no padding and the lifetime is tied to `px`.
    unsafe { core::slice::from_raw_parts(px.as_ptr() as *const u8, px.len() * 4) }
}

/// Flush thunk: copies fbcon's pixel buffer to the live FB and pokes the
/// GPU to repaint. Provided by drv-virtio-gpu at boot.
pub type FlushFn = fn(pixels: &[u8]);
static FLUSH_FN: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

// Terminal answerback (DSR/CPR reply per `CSI n`) delivery lives in the
// host-testable `crate::answerback` module: the Linux flip-buffer model
// (`tty_insert_flip_string` queue + deferred `flush_to_ldisc` drain). The
// write path here QUEUES (`answerback::queue`); the timer tick DRAINS
// (`drain_answerback` → `answerback::drain`) into the tty input rings with
// no console write lock held and outside printk context.

/// Deferred answerback drain sink type (re-export of `answerback::ReplyFn`).
pub type ReplyFn = crate::answerback::ReplyFn;

/// Register the deferred answerback drain sink (boot wiring, once). The
/// sink injects queued reply bytes into the tty INPUT ring and is invoked
/// ONLY from the tick drain — never from a write/printk path.
/// # C: O(1).
pub fn set_reply_sink(f: ReplyFn) {
    crate::answerback::set_sink(f);
}

/// Queue an emulator answerback for `vt` for deferred delivery (Linux
/// `tty_insert_flip_string`). Per-VT answerback lock only — safe under the
/// console write lock. No-op for empty `bytes`.
/// # C: O(N) bytes.
fn queue_answerback(vt: u8, bytes: &[u8]) {
    crate::answerback::queue(vt, bytes);
}

/// Drain all queued answerbacks into the tty input rings via the registered
/// sink (Linux `flush_to_ldisc`). Runs from the timer tick: deferred, NO
/// console write lock held, NOT printk context, input-only.
/// # C: O(total queued bytes).
pub fn drain_answerback() {
    crate::answerback::drain();
}

/// True once `kernel_init` has finished. All sinks no-op before.
static READY: AtomicBool = AtomicBool::new(false);

/// Set when the fg screen changed since the last flush. Drained by the
/// softirq — deferring the GPU flush off the printk hot path is
/// essential (a full-frame transfer + virtio flush per line is slow).
static DIRTY: AtomicBool = AtomicBool::new(false);

/// Softirq handler installed at `kernel_init`. Runs in process-level
/// context with IRQs unmasked, so the virtio-gpu submit can wait on the
/// device's used-idx ack without deadlocking.
/// # C: O(xres*yres) on a dirty frame.
fn flush_softirq() {
    if !DIRTY.swap(false, Ordering::AcqRel) {
        return;
    }
    repaint();
}

/// Initialize the per-VT fbcon console layer. Called once by the
/// virtio-gpu boot probe after the scanout is active. Builds the shared
/// renderer sized to the framebuffer's cell grid, allocates vc_cons[0]
/// (the system console), sets fg=0, registers the softirq flush handler
/// + flush thunk, and paints the (blank) screen once.
/// # C: O(cols*rows) — renderer surface alloc + clear.
pub fn kernel_init(xres: u32, yres: u32, flush: FlushFn) {
    softirq::set_handler(softirq::Slot::FbconFlush, flush_softirq);
    // Cell dims are font-driven: default 8×16 → same grid as before; a wider
    // font loaded at boot grids correctly. (CELL_W/CELL_H are the fallback.)
    let font = crate::font::active();
    let (cell_w, cell_h) = (font.width.max(1), font.height.max(1));
    let cols = (xres / cell_w).max(1) as u16;
    let rows = (yres / cell_h).max(1) as u16;
    let mut renderer = VcRenderer::new();
    renderer.con_init(cols as u32, rows as u32);
    let mut sys = Box::new(VcCell {
        vc: Vc::new(cols, rows),
        em: Emulator::new(),
    });
    // Paint the blank system console once (full repaint).
    vtdata::switch(&mut sys.vc, &mut renderer);
    let mut vc_cons: [Option<Box<VcCell>>; N_SLOTS] = [const { None }; N_SLOTS];
    // Linux device parity: fbcon slot N == /dev/ttyN (1-based). Slot 1 is
    // the default foreground VT (`tty1`) — what `/dev/console` aliases, where
    // boot/printk render, and what the keyboard targets. (Slot 0 is unused;
    // there is no `/dev/tty0` VT, only the fg alias.) This keeps ONE notion of
    // "foreground": fbcon fg == vt_tty foreground == keyboard target == 1.
    vc_cons[1] = Some(sys);
    *VT_STATE.lock() = Some(VtState {
        vc_cons,
        fg: 1,
        renderer,
        cols,
        rows,
    });
    FLUSH_FN.store(flush as *mut (), Ordering::Release);
    READY.store(true, Ordering::Release);
    DIRTY.store(true, Ordering::Release);
    repaint();
}

/// Detach fbcon from a disappearing framebuffer. The VT contents are dropped
/// with the framebuffer console because there is no live consw target left;
/// serial remains the durable console.
/// # C: O(1)
pub fn kernel_unregister() {
    READY.store(false, Ordering::Release);
    DIRTY.store(false, Ordering::Release);
    FLUSH_FN.store(core::ptr::null_mut(), Ordering::Release);
    crate::answerback::clear_sink();
    *VT_STATE.lock() = None;
}

/// System-console grid `(rows, cols)` derived from the framebuffer geometry
/// (yres/CELL_H × xres/CELL_W), or `None` pre-init. Boot seeds `/dev/console`'s
/// winsize from this so full-screen apps (htop/btop) see the real fbcon size
/// instead of the 24×80 `default_pty` fallback.
/// # C: O(1)
pub fn console_dims() -> Option<(u16, u16)> {
    VT_STATE.lock().as_ref().map(|st| (st.rows, st.cols))
}

/// `klog::ConsoleSink` registered as the fbcon printk console. Linux
/// `vt_console_print` writes to **`fg_console`** — so feed `bytes`
/// through the CURRENT foreground VT's emulator into its `Vc`, render
/// the dirtied cells via `consw`, and raise the flush softirq.
///
/// Re-entrancy: this can run from the printk path in any context (early
/// boot, IRQ). BEST-EFFORT — if the state lock is already held (a
/// re-entrant printk, or a concurrent device write), it skips THIS blit
/// and returns. The serial console copy is a SEPARATE klog slot, so
/// durable serial output is never affected by a skipped fbcon blit.
/// # C: O(N_bytes + dirty_rows*cols).
pub fn vt_console_sink(bytes: &[u8]) {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    if let Some(mut g) = VT_STATE.try_lock() {
        if let Some(st) = g.as_mut() {
            let i = st.ensure(st.fg);
            if let Some(cell) = st.vc_cons[i].as_mut() {
                // printk emits bare LF; the emulator's Linefeed moves down but
                // (correctly, xterm LNM-off) does NOT reset the column, so raw
                // printk output staircases. Like Linux `vt_console_print`, the
                // printk console path emits CR+LF for each LF. The tty device
                // path (`vt_write`) is separate and already ONLCR-processed.
                let mut start = 0;
                for k in 0..bytes.len() {
                    if bytes[k] == b'\n' {
                        cell.em.feed_bytes(&mut cell.vc, &bytes[start..k]);
                        cell.em.feed_bytes(&mut cell.vc, b"\r\n");
                        start = k + 1;
                    }
                }
                if start < bytes.len() { cell.em.feed_bytes(&mut cell.vc, &bytes[start..]); }
                vtdata::render(&mut cell.vc, &mut st.renderer);
                DIRTY.store(true, Ordering::Release);
                // printk NEVER produces a terminal answerback — its text
                // carries no DSR/CPR query — so the printk console path does
                // NOT queue a reply (Linux `vt_console_print` likewise has
                // no respond path). Discard any stray reply byte so it can't
                // carry into the next device write on this fg VT.
                let _ = cell.em.take_reply();
            }
        }
    }
    // Always raise — even if we skipped the blit under contention, the
    // next emit marks dirty and this slot dedupes naturally.
    softirq::raise(softirq::Slot::FbconFlush);
}

/// Per-tick fbcon work driven from `tick_poll_combined`. The GPU flush is
/// handled by `softirq::Slot::FbconFlush`; this drains the deferred VT
/// answerback queues into the tty input rings (our `flush_to_ldisc` work
/// item — deferred, holds no console write lock, runs outside printk).
/// # C: O(queued answerback bytes).
pub fn tick_drain() { drain_answerback(); }

/// Push the current rendered (fg) pixels to the GPU via the installed
/// flush thunk. No-op if the thunk isn't installed.
/// # C: O(xres*yres) — full-frame transfer.
fn repaint() {
    let raw = FLUSH_FN.load(Ordering::Acquire);
    if raw.is_null() {
        return;
    }
    // SAFETY: FLUSH_FN is only populated via kernel_init with a non-null FlushFn cast through `as *mut ()`; reverse-cast restores the identical fn signature, and the flush thunk reads its &[u8] argument by length.
    let f: FlushFn = unsafe { core::mem::transmute::<*mut (), FlushFn>(raw) };
    let guard = VT_STATE.lock();
    if let Some(st) = guard.as_ref() {
        f(pixels_as_bytes(st.renderer.pixels()));
    }
}

/// Write `bytes` to virtual console `vt`'s screen (numbered-VT device
/// write path). Feeds `bytes` through `vc_cons[vt]`'s emulator → `Vc`
/// (lazy-alloc on first touch). If `vt == fg`, renders the dirtied cells
/// to the shared renderer + raises the flush softirq; if `vt != fg`, the
/// VT is offscreen so its `Vc` is updated but NOT blitted. Uses a REAL
/// lock — device writes must not be silently dropped.
/// # C: O(N_bytes + dirty_rows*cols) on fg, else O(N_bytes).
pub fn vt_write(vt: u8, bytes: &[u8]) {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    let mut blitted = false;
    let mut reply: Option<vtdata::ReplyBytes> = None;
    {
        let mut guard = VT_STATE.lock();
        if let Some(st) = guard.as_mut() {
            let i = st.ensure(vt);
            let is_fg = i == st.fg as usize;
            if let Some(cell) = st.vc_cons[i].as_mut() {
                cell.em.feed_bytes(&mut cell.vc, bytes);
                if is_fg {
                    vtdata::render(&mut cell.vc, &mut st.renderer);
                    DIRTY.store(true, Ordering::Release);
                    blitted = true;
                }
                // Drain any DSR/CPR answerback the emulator produced (even
                // for an offscreen VT — the program reading it still expects
                // its reply). QUEUE it under the per-VT answerback lock for
                // DEFERRED delivery (Linux `tty_insert_flip_string`); the
                // bytes do NOT reach the tty input ring here, inside the
                // console write lock — the tick drain (`drain_answerback`,
                // our `flush_to_ldisc`) injects them later, lock-free.
                let r = cell.em.take_reply();
                if !r.is_empty() { reply = Some(r); }
            }
        }
    }
    // Queue (don't inject) after releasing VT_STATE. queue_answerback takes
    // only the per-VT answerback lock — never a tty lock — so even calling
    // it under VT_STATE would be safe; placed here to keep the hot path
    // short. The deferred tick drain performs the actual RX injection.
    if let Some(r) = reply {
        queue_answerback(vt, r.as_slice());
    }
    if blitted {
        softirq::raise(softirq::Slot::FbconFlush);
    }
}

/// Switch the foreground VT to `n` (Linux `vc_switch` / `set_console`).
/// Lazy-allocates `vc_cons[n]`, sets `fg = n`, then full-repaints the
/// shared renderer from `vc_cons[n]`'s `Vc` (`vtdata::switch`) and raises
/// the flush softirq. Exported `pub` so the kbd Ctrl-Alt-Fn handler (and
/// tests) can drive it. No-op before `kernel_init`.
/// # C: O(cols*rows) — full-screen repaint.
pub fn switch_vt(n: u8) {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    {
        let mut guard = VT_STATE.lock();
        if let Some(st) = guard.as_mut() {
            let i = st.ensure(n);
            st.fg = i as u8;
            if let Some(cell) = st.vc_cons[i].as_mut() {
                vtdata::switch(&mut cell.vc, &mut st.renderer);
                DIRTY.store(true, Ordering::Release);
            }
        }
    }
    softirq::raise(softirq::Slot::FbconFlush);
}

/// Force a full repaint of the foreground VT (Linux `do_unblank_screen` →
/// `update_screen` / `redraw_screen`). Marks the surface dirty and raises the
/// flush softirq so the next tick reblits every cell from the fg `Vc`. Used by
/// TIOCL_UNBLANKSCREEN to bring the console back after a blank request. No-op
/// pre-init. NOTE: this does NOT implement pixel-level screen blanking (we have
/// no blank/DPMS hardware path) — it only re-asserts the live screen content.
/// # C: O(cols*rows) — full-screen repaint.
pub fn force_repaint() {
    if !READY.load(Ordering::Acquire) { return; }
    {
        let mut guard = VT_STATE.lock();
        if let Some(st) = guard.as_mut() {
            let fg = st.fg as usize;
            if let Some(cell) = st.vc_cons[fg].as_mut() {
                vtdata::switch(&mut cell.vc, &mut st.renderer);
                DIRTY.store(true, Ordering::Release);
            }
        }
    }
    softirq::raise(softirq::Slot::FbconFlush);
}

/// Scroll the FOREGROUND VT's view by `lines` (Linux `con_scrolldelta` /
/// Shift+PgUp/PgDn): positive scrolls UP into scrollback history, negative
/// scrolls back DOWN toward the live bottom. The `Vc` already holds the
/// history + clamps `view_offset`; this adjusts it and full-repaints the fg
/// (the renderer's `visible_glyph_at` honours the offset). No-op pre-init.
/// # C: O(cols*rows) — full-screen repaint.
pub fn scrolldelta(lines: isize) {
    if !READY.load(Ordering::Acquire) || lines == 0 {
        return;
    }
    {
        let mut guard = VT_STATE.lock();
        if let Some(st) = guard.as_mut() {
            let fg = st.fg as usize;
            if let Some(cell) = st.vc_cons[fg].as_mut() {
                if lines > 0 { cell.vc.scroll_view_up(lines as usize); }
                else { cell.vc.scroll_view_down((-lines) as usize); }
                // Full repaint from the (possibly scrolled) view.
                vtdata::switch(&mut cell.vc, &mut st.renderer);
                DIRTY.store(true, Ordering::Release);
            }
        }
    }
    softirq::raise(softirq::Slot::FbconFlush);
}

/// Snapshot the foreground VT's screen for `/dev/vcs*` (Linux `vcs_read`).
/// `with_attr` = false → `/dev/vcs`: `rows*cols` glyph bytes (Latin-1, no
/// newlines). `with_attr` = true → `/dev/vcsa`: a 4-byte header
/// `[rows, cols, cursor_x, cursor_y]` then `rows*cols` pairs of
/// `[glyph, attr]` (attr = VGA fg/bg nibble approximation). Reads the LIVE
/// bottom (view_offset ignored, as Linux vcs does). Empty pre-init.
/// # C: O(rows*cols).
pub fn screen_dump(with_attr: bool) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::new();
    let guard = VT_STATE.lock();
    let st = match guard.as_ref() { Some(s) => s, None => return out };
    let fg = st.fg as usize;
    let cell = match st.vc_cons[fg].as_ref() { Some(c) => c, None => return out };
    let (rows, cols) = (st.rows, st.cols);
    if with_attr {
        out.push(rows.min(255) as u8);
        out.push(cols.min(255) as u8);
        out.push(cell.vc.x.min(255) as u8);
        out.push(cell.vc.y.min(255) as u8);
    }
    for r in 0..rows {
        for c in 0..cols {
            let g = cell.vc.glyph_at(c, r);
            out.push(if (0x20..0x7f).contains(&g) { g as u8 } else { b' ' });
            if with_attr { out.push(0x07); } // default light-grey-on-black
        }
    }
    out
}

/// Live-resize VT `vt`'s text grid (Linux `fbcon_resize`). The physical
/// framebuffer scanout is a FIXED size, so the text grid can only ever be
/// made SMALLER than (or equal to) the native cell grid computed at
/// `kernel_init` (`xres/CELL_W` × `yres/CELL_H`, stored in `st.cols/rows`):
/// a request wider OR taller than native is REJECTED (`false`), exactly as
/// `fbcon_resize` rejects a var that exceeds the fb's `xres/yres`.
///
/// When it fits, `vc_cons[vt]`'s `Vc` is reflowed via `Vc::resize`. The
/// shared renderer (the scanout) stays at native size — we do NOT shrink
/// the scanout; the unused fb area beyond the smaller grid simply stays
/// blank. If `vt` is the foreground VT, a full repaint (`vtdata::switch`)
/// redraws the resized `Vc` within the native fb. No-op pre-init → `false`.
/// # C: O(cols*rows) — Vc realloc + (fg) repaint.
pub fn resize_vt(vt: u8, cols: u16, rows: u16) -> bool {
    if !READY.load(Ordering::Acquire) { return false; }
    if cols == 0 || rows == 0 { return false; }
    let mut blitted = false;
    {
        let mut guard = VT_STATE.lock();
        let st = match guard.as_mut() { Some(s) => s, None => return false };
        // Fixed scanout: reject anything larger than the native cell grid.
        if cols > st.cols || rows > st.rows { return false; }
        let i = st.ensure(vt);
        let is_fg = i == st.fg as usize;
        if let Some(cell) = st.vc_cons[i].as_mut() {
            // The Emulator holds only parser state (no cached geometry); all
            // rows/cols live in the Vc, so resizing the Vc is sufficient.
            cell.vc.resize(cols, rows);
            if is_fg {
                // Renderer stays native-sized; repaint the resized Vc within it.
                vtdata::switch(&mut cell.vc, &mut st.renderer);
                DIRTY.store(true, Ordering::Release);
                blitted = true;
            }
        }
    }
    if blitted { softirq::raise(softirq::Slot::FbconFlush); }
    true
}

/// Currently-foreground fbcon VT index (0 = system console). Test/diag.
/// # C: O(1).
pub fn foreground() -> u8 {
    VT_STATE
        .lock()
        .as_ref()
        .map(|st| st.fg)
        .unwrap_or(0)
}

/// Read a keyboard-relevant mode from the FOREGROUND VT's emulator (Linux
/// `applkey` consults `vc_cons[fg_console]`). Best-effort: returns `false`
/// if the state lock is contended or the VT isn't allocated yet.
/// # C: O(1).
fn fg_em_mode(f: impl Fn(&Emulator) -> bool) -> bool {
    if let Some(mut g) = VT_STATE.try_lock() {
        if let Some(st) = g.as_mut() {
            let i = st.ensure(st.fg);
            if let Some(cell) = st.vc_cons[i].as_ref() {
                return f(&cell.em);
            }
        }
    }
    false
}

/// DECCKM (application cursor keys) state of the foreground VT — the
/// keyboard layer reads this to encode arrows as `ESC O x` vs `ESC [ x`.
/// # C: O(1).
pub fn fg_app_cursor() -> bool {
    fg_em_mode(|em| em.app_cursor())
}

/// Bracketed-paste (`?2004`) state of the foreground VT — the
/// selection-paste path wraps the payload in `ESC[200~`…`ESC[201~`.
/// # C: O(1).
pub fn fg_bracketed_paste() -> bool {
    fg_em_mode(|em| em.bracketed_paste())
}
