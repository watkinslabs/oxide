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

#[test]
fn uninstall_scanout_removes_context_without_live_mmio_or_frames() {
    CTX.lock().clear();
    CTX.lock().push(ScanoutCtx {
        device_key: key(0x0010_0000),
        bdf: 0x0010_0000,
        cfg_va: 0,
        w: 640,
        h: 480,
        fb_va: 0,
        fb_bytes: 0,
        fb_pages_alloc: 0,
        res_id: 1,
        ctrlq: test_ctrlq(),
        cmd_buf_va: 0,
        cmd_buf_pa: 0,
        hhdm: 0,
        fbdev_idx: None,
        quiesced: false,
    });

    assert!(uninstall_scanout(key(0x0010_0000)));
    assert!(CTX.lock().is_empty());
    assert!(!uninstall_scanout(key(0x0010_0000)));
}

#[test]
fn failed_probe_unwind_removes_only_matching_child_scanout() {
    CTX.lock().clear();
    CTX.lock().push(ScanoutCtx {
        device_key: key(0x0010_0000),
        bdf: 0x0010_0000,
        cfg_va: 0,
        w: 640,
        h: 480,
        fb_va: 0,
        fb_bytes: 0,
        fb_pages_alloc: 0,
        res_id: 1,
        ctrlq: test_ctrlq(),
        cmd_buf_va: 0,
        cmd_buf_pa: 0,
        hhdm: 0,
        fbdev_idx: None,
        quiesced: false,
    });
    CTX.lock().push(ScanoutCtx {
        device_key: key(0x0020_0000),
        bdf: 0x0020_0000,
        cfg_va: 0,
        w: 800,
        h: 600,
        fb_va: 0,
        fb_bytes: 0,
        fb_pages_alloc: 0,
        res_id: 2,
        ctrlq: test_ctrlq(),
        cmd_buf_va: 0,
        cmd_buf_pa: 0,
        hhdm: 0,
        fbdev_idx: None,
        quiesced: false,
    });

    assert!(uninstall_scanout_after_failed_probe(key(0x0010_0000)));
    let guard = CTX.lock();
    assert_eq!(guard.len(), 1);
    assert_eq!(guard[0].device_key, key(0x0020_0000));
    assert_eq!(guard[0].bdf, 0x0020_0000);
    drop(guard);
    assert!(uninstall_scanout_after_failed_probe(key(0x0020_0000)));
    assert!(CTX.lock().is_empty());
}
