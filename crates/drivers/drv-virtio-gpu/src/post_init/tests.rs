use super::*;

const fn key(raw: u32) -> virtio::VirtioChildDeviceKey {
    virtio::VirtioChildDeviceKey::from_raw(raw)
}

fn test_ctrlq() -> virtio::VirtQueueResource {
    virtio::VirtQueueResource {
        index: 0,
        size: 1,
        desc_pa: 0,
        driver_pa: 0,
        device_pa: 0,
        notify_va: 0,
        notify_off: 0,
    }
}

fn test_scanout_ctx(device_key: virtio::VirtioChildDeviceKey, bdf: u32) -> ScanoutCtx {
    ScanoutCtx {
        device_key,
        bdf,
        cfg_va: 0,
        w: 640,
        h: 480,
        fb_va: 0,
        fb_bytes: 0,
        fb_order: pmm::Order(0),
        res_id: 1,
        ctrlq: test_ctrlq(), cursorq: test_ctrlq(),
        cmd_buf_va: 0,
        cmd_buf_pa: 0,
        hhdm: 0,
        fbdev_idx: None,
        quiesced: false,
    }
}

fn test_gpu_dev(device_key: virtio::VirtioChildDeviceKey, bdf: u32) -> crate::VirtioGpuDev {
    crate::VirtioGpuDev {
        device_key,
        bdf,
        card_id: 0,
        cfg_va: 0,
        ctrlq: test_ctrlq(), cursorq: test_ctrlq(),
        features_negotiated: 0,
        display: crate::DisplayInfo::default(),
        resource_id_alloc: core::sync::atomic::AtomicU32::new(1),
        blob_uuid_alloc: core::sync::atomic::AtomicU64::new(1),
        capset_count: 0,
    }
}

#[test]
fn uninstall_scanout_removes_context_without_live_mmio_or_frames() {
    let _guard = TEST_LOCK.lock();
    CTX.lock().clear();
    CTX.lock().push(test_scanout_ctx(key(0x0010_0000), 0x0010_0000));

    assert!(uninstall_scanout(key(0x0010_0000)));
    assert!(CTX.lock().is_empty());
    assert!(!uninstall_scanout(key(0x0010_0000)));
}

#[test]
fn failed_probe_unwind_removes_only_matching_child_scanout() {
    let _guard = TEST_LOCK.lock();
    CTX.lock().clear();
    let mut first = test_scanout_ctx(key(1), 0x0010_0000);
    first.w = 640;
    first.h = 480;
    let mut second = test_scanout_ctx(key(2), 0x0010_0000);
    second.w = 800;
    second.h = 600;
    CTX.lock().push(first);
    CTX.lock().push(second);

    assert_eq!(dimensions_for_key(key(1)), Some((640, 480)));
    assert_eq!(dimensions_for_key(key(2)), Some((800, 600)));
    assert!(uninstall_scanout_after_failed_probe(key(1)));
    let guard = CTX.lock();
    assert_eq!(guard.len(), 1);
    assert_eq!(guard[0].device_key, key(2));
    assert_eq!(guard[0].bdf, 0x0010_0000);
    drop(guard);
    assert!(uninstall_scanout_after_failed_probe(key(2)));
    assert!(CTX.lock().is_empty());
}

#[test]
fn failed_probe_unwind_owns_probe_command_and_framebuffer_state() {
    let _guard = TEST_LOCK.lock();
    CTX.lock().clear();
    let mut cmd = ProbeCommandBuffer {
        pa: 0,
        va: core::ptr::null_mut(),
        owned: true,
    };
    let mut fb = ProbeFramebufferRun {
        base_pa: 0,
        order: pmm::Order(0),
        owned: true,
    };
    cmd.disarm();
    fb.disarm();

    assert!(!cmd.owned);
    assert!(!fb.owned);
    assert!(install_scanout_ctx(
        key(0x10),
        0x0010_0000,
        32,
        16,
        0,
        0xffff_8000_0000_4000,
        0x1000,
        fb.order,
        1,
        test_ctrlq(),
        test_ctrlq(),
        0,
        cmd.pa,
        0xffff_8000_0000_4000,
    ));
    {
        let guard = CTX.lock();
        assert_eq!(guard.len(), 1);
        assert_eq!(guard[0].cmd_buf_pa, 0);
        assert_eq!(guard[0].fb_va, 0xffff_8000_0000_4000);
        assert_eq!(guard[0].fb_bytes, 0x1000);
        assert_eq!(guard[0].fb_order, pmm::Order(0));
    }

    assert!(uninstall_scanout_after_failed_probe(key(0x10)));
    assert!(CTX.lock().is_empty());
}

#[test]
fn hot_remove_attempts_scanout_when_device_state_is_missing() {
    let _guard = TEST_LOCK.lock();
    CTX.lock().clear();
    crate::device::DEVICES.lock().clear();
    CTX.lock().push(test_scanout_ctx(key(0x0010_0000), 0x0010_0000));

    let result = crate::hot_remove(key(0x0010_0000));

    assert_eq!(result.device_removed, false);
    assert_eq!(result.scanout_removed, true);
    assert!(CTX.lock().is_empty());
}

#[test]
fn hot_remove_attempts_device_and_scanout_cleanup() {
    let _guard = TEST_LOCK.lock();
    CTX.lock().clear();
    crate::device::DEVICES.lock().clear();
    crate::install(test_gpu_dev(key(0x0010_0000), 0x0010_0000)).unwrap();
    CTX.lock().push(test_scanout_ctx(key(0x0010_0000), 0x0010_0000));

    let result = crate::hot_remove(key(0x0010_0000));

    assert_eq!(result.device_removed, true);
    assert_eq!(result.scanout_removed, true);
    assert!(crate::device::DEVICES.lock().is_empty());
    assert!(CTX.lock().is_empty());
}
