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
//   * `vt_console_sink(bytes)` — printk; writes to the CURRENT fg VT
//     (Linux `vt_console_print` → `fg_console`), best-effort `try_lock`.
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

use crate::vcrender::{VcRenderer, CELL_H, CELL_W};

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
    let cols = (xres / CELL_W).max(1) as u16;
    let rows = (yres / CELL_H).max(1) as u16;
    let mut renderer = VcRenderer::new();
    renderer.con_init(cols as u32, rows as u32);
    let mut sys = Box::new(VcCell {
        vc: Vc::new(cols, rows),
        em: Emulator::new(),
    });
    // Paint the blank system console once (full repaint).
    vtdata::switch(&mut sys.vc, &mut renderer);
    let mut vc_cons: [Option<Box<VcCell>>; N_SLOTS] = [const { None }; N_SLOTS];
    vc_cons[0] = Some(sys);
    *VT_STATE.lock() = Some(VtState {
        vc_cons,
        fg: 0,
        renderer,
        cols,
        rows,
    });
    FLUSH_FN.store(flush as *mut (), Ordering::Release);
    READY.store(true, Ordering::Release);
    DIRTY.store(true, Ordering::Release);
    repaint();
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
                cell.em.feed_bytes(&mut cell.vc, bytes);
                vtdata::render(&mut cell.vc, &mut st.renderer);
                DIRTY.store(true, Ordering::Release);
            }
        }
    }
    // Always raise — even if we skipped the blit under contention, the
    // next emit marks dirty and this slot dedupes naturally.
    softirq::raise(softirq::Slot::FbconFlush);
}

/// Legacy no-op kept for API stability — the softirq mechanism in
/// `flush_softirq` is the only drain path.
/// # C: O(1).
pub fn tick_drain() { /* superseded by softirq::Slot::FbconFlush */ }

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
            }
        }
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

/// Currently-foreground fbcon VT index (0 = system console). Test/diag.
/// # C: O(1).
pub fn foreground() -> u8 {
    VT_STATE
        .lock()
        .as_ref()
        .map(|st| st.fg)
        .unwrap_or(0)
}
