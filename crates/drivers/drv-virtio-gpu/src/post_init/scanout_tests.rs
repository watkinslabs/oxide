use super::*;

fn key(raw: u32) -> virtio::VirtioChildDeviceKey { virtio::VirtioChildDeviceKey::from_raw(raw) }

fn ctx(device_key: virtio::VirtioChildDeviceKey) -> ScanoutCtx {
    ScanoutCtx {
        device_key, cfg_va: 0, w: 640, h: 480, fb_va: 0, fb_dma: 0, fb_map_bytes: 0, fb_bytes: 0,
        fb_order: pmm::Order(0), res_id: BOOT_SCANOUT_RES_ID, ctrlq: None, cursorq: None,
        cmd_buf_va: 0, cmd_buf_pa: 0, cmd_buf_dma: 0,
        bdf: pci::Bdf { segment: 0, bus: 0, device: 0, function: 0 }, hhdm: 0,
        fbdev_idx: None, quiesced: false, bound: None,
    }
}

fn reset_publication_state() {
    CONSOLE_OWNER_KEY.store(NO_CONSOLE_OWNER_KEY, Ordering::Release);
    ctx_lock().clear();
    fbdev::FBS.lock().clear();
}

#[test]
fn fbdev_idx_is_stored_and_taken_by_owner_key() {
    let _guard = super::super::TEST_LOCK.lock();
    reset_publication_state();
    ctx_lock().push(ctx(key(0x10)));
    ctx_lock().push(ctx(key(0x20)));
    assert!(set_scanout_fbdev_idx(key(0x10), Some(3)));
    assert!(set_scanout_fbdev_idx(key(0x20), Some(7)));
    assert!(!set_scanout_fbdev_idx(key(0x30), Some(9)));
    assert_eq!(take_scanout_fbdev_idx(key(0x20)), Some(7));
    assert_eq!(take_scanout_fbdev_idx(key(0x20)), None);
    assert_eq!(take_scanout_fbdev_idx(key(0x10)), Some(3));
    assert_eq!(take_scanout_fbdev_idx(key(0x30)), None);
    reset_publication_state();
}

#[test]
fn console_owner_commits_after_fbdev_idx_is_stored() {
    let _guard = super::super::TEST_LOCK.lock();
    reset_publication_state();
    ctx_lock().push(ctx(key(0x10)));
    let idx = install_console_fbdev(key(0x10)).unwrap();
    assert_eq!(console_owner_key(), None);
    assert_eq!(ctx_lock()[0].fbdev_idx, Some(idx));
    assert_eq!(fbdev::count(), 1);
    assert!(commit_console_owner_key(key(0x10), idx));
    assert_eq!(console_owner_key(), Some(key(0x10)));
    reset_publication_state();
}

#[test]
fn console_owner_commit_failure_unwinds_stored_fbdev_idx() {
    let _guard = super::super::TEST_LOCK.lock();
    reset_publication_state();
    ctx_lock().push(ctx(key(0x10)));
    CONSOLE_OWNER_KEY.store(key(0x20).raw(), Ordering::Release);
    let idx = install_console_fbdev(key(0x10)).unwrap();
    assert!(!commit_console_owner_key(key(0x10), idx));
    assert_eq!(console_owner_key(), Some(key(0x20)));
    assert_eq!(ctx_lock()[0].fbdev_idx, None);
    assert_eq!(fbdev::count(), 0);
    reset_publication_state();
}

#[test]
fn shutdown_scanout_quiesces_without_dropping_publication_metadata() {
    let _guard = super::super::TEST_LOCK.lock();
    reset_publication_state();
    let mut ctx = ctx(key(0x10));
    ctx.fb_va = 0xffff_8000_0000_4000;
    ctx.fb_bytes = 0x2000;
    ctx.fb_order = pmm::Order(1);
    ctx.cmd_buf_pa = 0x9000;
    let idx = fbdev::init_scanout(0x4000, ctx.fb_va, ctx.fb_bytes, 128, 32, 16);
    ctx.fbdev_idx = Some(idx);
    ctx_lock().push(ctx);
    assert!(shutdown_scanout(key(0x10)));
    let guard = ctx_lock();
    assert_eq!(guard.len(), 1);
    assert!(guard[0].quiesced);
    assert_eq!(guard[0].fbdev_idx, Some(idx));
    assert_eq!(guard[0].fb_va, 0xffff_8000_0000_4000);
    assert_eq!(guard[0].fb_bytes, 0x2000);
    assert_eq!(guard[0].fb_order, pmm::Order(1));
    assert_eq!(guard[0].cmd_buf_pa, 0x9000);
    drop(guard);
    assert_eq!(fbdev::count(), 1);
    reset_publication_state();
}
