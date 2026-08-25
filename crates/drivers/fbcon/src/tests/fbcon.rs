use crate::*;
use crate::damage::FlushRect;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::kernel::CONSOLE_TEST_DOMAIN;
static FLUSH_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Rect of the most recent flush, so a test can assert the SCOPE of the
/// upload and not merely that one happened.
static LAST_X: AtomicU32 = AtomicU32::new(0);
static LAST_Y: AtomicU32 = AtomicU32::new(0);
static LAST_W: AtomicU32 = AtomicU32::new(0);
static LAST_H: AtomicU32 = AtomicU32::new(0);
/// Pixel-buffer length the sink was handed, to prove the rect is the small
/// part of a large surface rather than the surface itself.
static LAST_LEN: AtomicUsize = AtomicUsize::new(0);
static GEOMETRY_COUNT: AtomicUsize = AtomicUsize::new(0);
static GEOMETRY_ROWS: AtomicU32 = AtomicU32::new(0);
static GEOMETRY_COLS: AtomicU32 = AtomicU32::new(0);
static GEOMETRY_YPIXEL: AtomicU32 = AtomicU32::new(0);

fn count_flush(pixels: &[u8], rect: FlushRect) {
    FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);
    LAST_X.store(rect.x, Ordering::Relaxed);
    LAST_Y.store(rect.y, Ordering::Relaxed);
    LAST_W.store(rect.w, Ordering::Relaxed);
    LAST_H.store(rect.h, Ordering::Relaxed);
    LAST_LEN.store(pixels.len(), Ordering::Relaxed);
}

fn capture_geometry(rows: u16, cols: u16, ypixel: u16) {
    GEOMETRY_COUNT.fetch_add(1, Ordering::Relaxed);
    GEOMETRY_ROWS.store(u32::from(rows), Ordering::Relaxed);
    GEOMETRY_COLS.store(u32::from(cols), Ordering::Relaxed);
    GEOMETRY_YPIXEL.store(u32::from(ypixel), Ordering::Relaxed);
}

fn last_rect() -> (u32, u32, u32, u32) {
    (
        LAST_X.load(Ordering::Relaxed),
        LAST_Y.load(Ordering::Relaxed),
        LAST_W.load(Ordering::Relaxed),
        LAST_H.load(Ordering::Relaxed),
    )
}

fn flushes() -> usize {
    FLUSH_COUNT.load(Ordering::Relaxed)
}

fn arm_flush_probe() {
    FLUSH_COUNT.store(0, Ordering::Relaxed);
    for c in [&LAST_X, &LAST_Y, &LAST_W, &LAST_H] {
        c.store(0, Ordering::Relaxed);
    }
    LAST_LEN.store(0, Ordering::Relaxed);
}

fn arm_geometry_probe() {
    GEOMETRY_COUNT.store(0, Ordering::Relaxed);
    GEOMETRY_ROWS.store(0, Ordering::Relaxed);
    GEOMETRY_COLS.store(0, Ordering::Relaxed);
    GEOMETRY_YPIXEL.store(0, Ordering::Relaxed);
}

/// Run the pending `FbconFlush` softirq.
fn drain_flush() {
    // SAFETY: hosted unit test owns the fbcon flush slot under CONSOLE_TEST_DOMAIN.
    unsafe { softirq::run_pending(); }
}

// Test console geometry: 640x480 with the built-in 8x16 font is an 80x30
// grid, so one text row is 16 scanlines of a 480-scanline surface.
const TEST_XRES: u32 = 640;
const TEST_YRES: u32 = 480;
const NATIVE_XRES: u32 = 1024;
const NATIVE_YRES: u32 = 768;
const TEST_CELL_H: u32 = 16;


#[path = "fbcon/parser.rs"]
mod parser;
#[path = "fbcon/geometry.rs"]
mod geometry;
#[path = "fbcon/damage.rs"]
mod damage;
