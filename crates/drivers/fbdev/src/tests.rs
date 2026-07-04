use super::*;
use core::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};

static LAST_FLUSH: AtomicU32 = AtomicU32::new(u32::MAX);
static LAST_BLANK: AtomicU32 = AtomicU32::new(u32::MAX);
static LAST_UNBLANK: AtomicU32 = AtomicU32::new(u32::MAX);

fn record_flush(key: u32) { LAST_FLUSH.store(key, AtomicOrdering::SeqCst); }
fn record_blank(key: u32) { LAST_BLANK.store(key, AtomicOrdering::SeqCst); }
fn record_unblank(key: u32) { LAST_UNBLANK.store(key, AtomicOrdering::SeqCst); }

#[test]
fn fb_var_default_bgra32() {
    let v = FbVarScreeninfo::default();
    assert_eq!(v.bits_per_pixel, 32);
    assert_eq!(v.red.offset, 16);
    assert_eq!(v.green.offset, 8);
    assert_eq!(v.blue.offset, 0);
    assert_eq!(v.transp.offset, 24);
}

#[test]
fn fb_fix_default_truecolor() {
    let f = FbFixScreeninfo::default();
    assert_eq!(f.ty, FB_TYPE_PACKED_PIXELS);
    assert_eq!(f.visual, FB_VISUAL_TRUECOLOR);
    assert_eq!(f.accel, FB_ACCEL_NONE);
}

#[test]
fn fb_var_layout() { assert_eq!(core::mem::size_of::<FbVarScreeninfo>(), 160); }

#[test]
fn fb_vblank_layout() { assert_eq!(core::mem::size_of::<FbVblank>(), 32); }

#[test]
fn fb_cmap_layout() { assert_eq!(core::mem::size_of::<FbCmap>(), 40); }

#[test]
fn cmap_pack_unpack_roundtrip_bgra32() {
    let v = FbVarScreeninfo::default();
    for &(r, g, b) in &[
        (0xFFFFu16, 0x0000u16, 0x0000u16),
        (0x0000, 0xFFFF, 0x0000),
        (0xABAB, 0xCDCD, 0xEFEF),
        (0x1212, 0x3434, 0x5656),
    ] {
        let px = pack_pseudo(&v, r, g, b);
        assert_eq!(unpack_pseudo(&v, px), (r, g, b), "px={px:#010x}");
    }
}

#[test]
fn cmap_pack_places_channels_in_bgra_fields() {
    let v = FbVarScreeninfo::default();
    assert_eq!(pack_pseudo(&v, 0xFFFF, 0, 0), 0x00FF_0000);
    assert_eq!(pack_pseudo(&v, 0, 0xFFFF, 0), 0x0000_FF00);
    assert_eq!(pack_pseudo(&v, 0, 0, 0xFFFF), 0x0000_00FF);
}

#[test]
fn pan_check_validates_against_virtual() {
    let mut v = FbVarScreeninfo::default();
    v.xres = 800;
    v.yres = 600;
    v.xres_virtual = 800;
    v.yres_virtual = 600;
    assert!(pan_check(&v, 0, 0).is_ok());
    assert!(pan_check(&v, 0, 1).is_err());
    assert!(pan_check(&v, 1, 0).is_err());
    v.yres_virtual = 1200;
    assert!(pan_check(&v, 0, 600).is_ok());
    assert!(pan_check(&v, 0, 601).is_err());
    assert!(pan_check(&v, 0, 0).is_ok());
}

#[test]
fn vblank_wait_returns_when_seq_advances() {
    let start = VBLANK_SEQ.load(Ordering::Relaxed);
    vblank_tick();
    let got = wait_vblank(start);
    assert_ne!(got, start);
    assert!(got >= start + 1);
}

#[test]
fn vblank_wait_bounded_when_no_advance() {
    let start = VBLANK_SEQ.load(Ordering::Relaxed);
    let got = wait_vblank(start);
    assert!(got >= start);
}

#[test]
fn line_length_alignment() {
    assert_eq!(line_length(800, 32), 3200);
    assert_eq!(line_length(1366, 32), 5504);
    assert_eq!(line_length(1024, 16), 2048);
}

#[test]
fn blank_level_validation() {
    assert!(is_blank_level(FB_BLANK_UNBLANK));
    assert!(is_blank_level(FB_BLANK_POWERDOWN));
    assert!(!is_blank_level(99));
}

#[test]
fn init_scanout_populates_geometry_and_backing() {
    FBS.lock().clear();
    let bytes = 800u64 * 600 * 4;
    let idx = init_scanout(0xdead_0000, 0xffff_8000_dead_0000, bytes, 800 * 4, 800, 600);
    assert_eq!(idx, 0);
    let v = var_of(0).unwrap();
    assert_eq!((v.xres, v.yres, v.bits_per_pixel), (800, 600, 32));
    let f = fix_of(0).unwrap();
    assert_eq!(f.smem_start, 0xdead_0000);
    assert_eq!(f.smem_len, bytes as u32);
    assert_eq!(f.line_length, 800 * 4);
    assert_eq!(backing_of(0), Some((0xdead_0000, bytes)));
    assert_eq!(kva_of(0), Some((0xffff_8000_dead_0000, bytes)));
    FBS.lock().clear();
}

#[test]
fn backing_none_without_real_fb() {
    FBS.lock().clear();
    register(0, 1, FbVarScreeninfo::default(), FbFixScreeninfo::default());
    assert_eq!(backing_of(0), None);
    assert_eq!(kva_of(0), None);
    FBS.lock().clear();
}

#[test]
fn register_count_roundtrip() {
    FBS.lock().clear();
    let mut v = FbVarScreeninfo::default();
    v.xres = 800;
    v.yres = 600;
    let idx = register(0, 1, v, FbFixScreeninfo::default());
    assert_eq!(idx, 0);
    assert_eq!(count(), 1);
    assert_eq!(var_of(0).unwrap().xres, 800);
    FBS.lock().clear();
}

#[test]
fn fb_ops_are_per_instance() {
    FBS.lock().clear();
    LAST_FLUSH.store(u32::MAX, AtomicOrdering::SeqCst);
    LAST_BLANK.store(u32::MAX, AtomicOrdering::SeqCst);
    LAST_UNBLANK.store(u32::MAX, AtomicOrdering::SeqCst);

    let bytes = 16u64;
    let fb0 = init_scanout(0x1000, 0xffff_8000_0000_1000, bytes, 16, 1, 1);
    let fb1 = init_scanout(0x2000, 0xffff_8000_0000_2000, bytes, 16, 1, 1);
    assert_ne!(fb0, fb1);
    assert!(set_ops(fb0, FbOps {
        driver_key: 11,
        flush: record_flush,
        blank: record_blank,
        unblank: record_unblank,
    }));
    assert!(set_ops(fb1, FbOps {
        driver_key: 22,
        flush: record_flush,
        blank: record_blank,
        unblank: record_unblank,
    }));

    flush(fb1);
    assert_eq!(LAST_FLUSH.load(AtomicOrdering::SeqCst), 22);
    apply_blank(fb0, FB_BLANK_NORMAL);
    assert_eq!(LAST_BLANK.load(AtomicOrdering::SeqCst), 11);
    apply_blank(fb1, FB_BLANK_NORMAL);
    assert_eq!(LAST_BLANK.load(AtomicOrdering::SeqCst), 22);
    apply_blank(fb1, FB_BLANK_UNBLANK);
    assert_eq!(LAST_UNBLANK.load(AtomicOrdering::SeqCst), 22);

    assert!(clear_ops(fb1));
    LAST_FLUSH.store(u32::MAX, AtomicOrdering::SeqCst);
    flush(fb1);
    assert_eq!(LAST_FLUSH.load(AtomicOrdering::SeqCst), u32::MAX);
    FBS.lock().clear();
}
