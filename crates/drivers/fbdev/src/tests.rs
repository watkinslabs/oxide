use super::*;
use core::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};

static LAST_FLUSH: AtomicU32 = AtomicU32::new(u32::MAX);
static LAST_BLANK: AtomicU32 = AtomicU32::new(u32::MAX);
static LAST_UNBLANK: AtomicU32 = AtomicU32::new(u32::MAX);

fn fb_key(raw: u32) -> FbDriverKey { FbDriverKey::from_raw(raw).unwrap() }

fn record_flush(key: FbDriverKey) { LAST_FLUSH.store(key.raw(), AtomicOrdering::SeqCst); }
fn record_blank(key: FbDriverKey) { LAST_BLANK.store(key.raw(), AtomicOrdering::SeqCst); }
fn record_unblank(key: FbDriverKey) { LAST_UNBLANK.store(key.raw(), AtomicOrdering::SeqCst); }

#[test]
fn fb_var_default_bgra32() {
    let _fbdev = crate::test_claim::claim_fbdev();
    let v = FbVarScreeninfo::default();
    assert_eq!(v.bits_per_pixel, 32);
    assert_eq!(v.red.offset, 16);
    assert_eq!(v.green.offset, 8);
    assert_eq!(v.blue.offset, 0);
    assert_eq!(v.transp.offset, 24);
}

#[test]
fn fb_fix_default_truecolor() {
    let _fbdev = crate::test_claim::claim_fbdev();
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
    let _fbdev = crate::test_claim::claim_fbdev();
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
    let _fbdev = crate::test_claim::claim_fbdev();
    let v = FbVarScreeninfo::default();
    assert_eq!(pack_pseudo(&v, 0xFFFF, 0, 0), 0x00FF_0000);
    assert_eq!(pack_pseudo(&v, 0, 0xFFFF, 0), 0x0000_FF00);
    assert_eq!(pack_pseudo(&v, 0, 0, 0xFFFF), 0x0000_00FF);
}

#[test]
fn pan_check_validates_against_virtual() {
    let _fbdev = crate::test_claim::claim_fbdev();
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
    let _fbdev = crate::test_claim::claim_fbdev();
    let start = VBLANK_SEQ.load(Ordering::Relaxed);
    vblank_tick();
    let got = wait_vblank(start);
    assert_ne!(got, start);
    assert!(got >= start + 1);
}

#[test]
fn vblank_wait_bounded_when_no_advance() {
    let _fbdev = crate::test_claim::claim_fbdev();
    let start = VBLANK_SEQ.load(Ordering::Relaxed);
    let got = wait_vblank(start);
    assert!(got >= start);
}

#[test]
fn line_length_alignment() {
    let _fbdev = crate::test_claim::claim_fbdev();
    assert_eq!(line_length(800, 32), 3200);
    assert_eq!(line_length(1366, 32), 5504);
    assert_eq!(line_length(1024, 16), 2048);
}

#[test]
fn blank_level_validation() {
    let _fbdev = crate::test_claim::claim_fbdev();
    assert!(is_blank_level(FB_BLANK_UNBLANK));
    assert!(is_blank_level(FB_BLANK_POWERDOWN));
    assert!(!is_blank_level(99));
}

#[test]
fn init_scanout_populates_geometry_and_backing() {
    let _fbdev = crate::test_claim::claim_fbdev();
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
}

#[test]
fn backing_none_without_real_fb() {
    let _fbdev = crate::test_claim::claim_fbdev();
    register(0, 1, FbVarScreeninfo::default(), FbFixScreeninfo::default());
    assert_eq!(backing_of(0), None);
    assert_eq!(kva_of(0), None);
}

#[test]
fn register_count_roundtrip() {
    let _fbdev = crate::test_claim::claim_fbdev();
    let mut v = FbVarScreeninfo::default();
    v.xres = 800;
    v.yres = 600;
    let idx = register(0, 1, v, FbFixScreeninfo::default());
    assert_eq!(idx, 0);
    assert_eq!(count(), 1);
    assert_eq!(var_of(0).unwrap().xres, 800);
}

#[test]
fn register_unwinds_record_when_model_publication_conflicts() {
    let _fbdev = crate::test_claim::claim_fbdev();
    let conflict = drv::try_device_add(alloc::sync::Arc::new(
        drv::Device::new("graphics", alloc::string::String::from("fb0"), 0, 0, 0)
            .with_devnode("graphics", alloc::string::String::from("fb0"), Some((29, 0))),
    ))
    .expect("conflict device registration");

    let idx = register(0, 1, FbVarScreeninfo::default(), FbFixScreeninfo::default());
    assert_eq!(idx, INVALID_FB_INDEX);
    assert_eq!(count(), 0);
    assert!(var_of(0).is_none());
    assert_eq!(
        drv::devices()
            .iter()
            .filter(|d| d.bus == "graphics" && d.addr == "fb0")
            .count(),
        1
    );

    drv::device_del(&conflict);
}

#[test]
fn fb_ops_are_per_instance() {
    let _fbdev = crate::test_claim::claim_fbdev();
    LAST_FLUSH.store(u32::MAX, AtomicOrdering::SeqCst);
    LAST_BLANK.store(u32::MAX, AtomicOrdering::SeqCst);
    LAST_UNBLANK.store(u32::MAX, AtomicOrdering::SeqCst);

    let bytes = 16u64;
    let fb0 = init_scanout(0x1000, 0xffff_8000_0000_1000, bytes, 16, 1, 1);
    let fb1 = init_scanout(0x2000, 0xffff_8000_0000_2000, bytes, 16, 1, 1);
    assert_ne!(fb0, fb1);
    assert!(set_ops(fb0, FbOps {
        driver_key: fb_key(11),
        flush: record_flush,
        blank: record_blank,
        unblank: record_unblank,
    }));
    assert!(set_ops(fb1, FbOps {
        driver_key: fb_key(22),
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
}

#[test]
fn fbdev_ioctls_route_flush_blank_by_fb_inode_record() {
    let _fbdev = crate::test_claim::claim_fbdev();
    LAST_FLUSH.store(u32::MAX, AtomicOrdering::SeqCst);
    LAST_BLANK.store(u32::MAX, AtomicOrdering::SeqCst);
    LAST_UNBLANK.store(u32::MAX, AtomicOrdering::SeqCst);

    let bytes = 16u64;
    let fb0 = init_scanout(0x3000, 0xffff_8000_0000_3000, bytes, 16, 1, 1);
    let fb1 = init_scanout(0x4000, 0xffff_8000_0000_4000, bytes, 16, 1, 1);
    assert_ne!(fb0, fb1);
    assert!(set_ops(fb0, FbOps {
        driver_key: fb_key(33),
        flush: record_flush,
        blank: record_blank,
        unblank: record_unblank,
    }));
    assert!(set_ops(fb1, FbOps {
        driver_key: fb_key(44),
        flush: record_flush,
        blank: record_blank,
        unblank: record_unblank,
    }));

    let fb0_inode = devfs::make_fb_inode(fb0);
    let fb1_inode = devfs::make_fb_inode(fb1);

    assert_eq!(devfs::handle_fbdev_ioctl(&fb0_inode, FBIOBLANK, FB_BLANK_NORMAL as u64), Some(0));
    assert_eq!(LAST_BLANK.load(AtomicOrdering::SeqCst), 33);
    assert_eq!(devfs::handle_fbdev_ioctl(&fb1_inode, FBIOBLANK, FB_BLANK_NORMAL as u64), Some(0));
    assert_eq!(LAST_BLANK.load(AtomicOrdering::SeqCst), 44);

    set_yield_hook(vblank_tick);
    assert_eq!(devfs::handle_fbdev_ioctl(&fb1_inode, FBIO_WAITFORVSYNC, 0), Some(0));
    clear_wait_hooks();
    assert_eq!(LAST_FLUSH.load(AtomicOrdering::SeqCst), 44);
    assert_eq!(LAST_UNBLANK.load(AtomicOrdering::SeqCst), u32::MAX);

}

#[test]
fn fbio_usercopy_rejects_overflowing_user_ranges() {
    let _fbdev = crate::test_claim::claim_fbdev();
    let fb0_inode = devfs::make_fb_inode(0);
    let efault = -(syscall::errno::Errno::Efault.as_i32() as i64);

    assert_eq!(
        devfs::handle_fbdev_ioctl(&fb0_inode, FBIOGET_VSCREENINFO, hal::USER_VA_END - 80),
        Some(efault)
    );

    let mut green = [0u16; 1];
    let mut blue = [0u16; 1];
    let cm = FbCmap {
        start: 0,
        len: 1,
        red: hal::USER_VA_END - 1,
        green: green.as_mut_ptr() as u64,
        blue: blue.as_mut_ptr() as u64,
        transp: 0,
    };

    assert_eq!(
        devfs::handle_fbdev_ioctl(&fb0_inode, FBIOPUTCMAP, (&cm as *const FbCmap) as u64),
        Some(efault)
    );
}

#[test]
fn fbio_getcmap_rejects_invalid_transparency_pointer() {
    let _fbdev = crate::test_claim::claim_fbdev();
    let fb0_inode = devfs::make_fb_inode(0);
    let efault = -(syscall::errno::Errno::Efault.as_i32() as i64);
    let mut red = [0u16; 1];
    let mut green = [0u16; 1];
    let mut blue = [0u16; 1];
    let cm = FbCmap {
        start: 0,
        len: 1,
        red: red.as_mut_ptr() as u64,
        green: green.as_mut_ptr() as u64,
        blue: blue.as_mut_ptr() as u64,
        transp: hal::USER_VA_END - 1,
    };

    assert_eq!(
        devfs::handle_fbdev_ioctl(&fb0_inode, FBIOGETCMAP, (&cm as *const FbCmap) as u64),
        Some(efault)
    );
}
