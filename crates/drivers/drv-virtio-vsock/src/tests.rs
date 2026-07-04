use sync::{Spinlock, TaskList as DriverLockClass};

use crate::{
    present, present_for, shutdown, uninstall, Ctx, RX_RING_BUFS,
};

static TEST_LOCK: Spinlock<(), DriverLockClass> = Spinlock::new(());

fn queue(index: u16) -> virtio::VirtQueueResource {
    virtio::VirtQueueResource {
        index,
        size: 8,
        desc_pa: 0,
        driver_pa: 0,
        device_pa: 0,
        notify_va: 0,
        notify_off: 0,
    }
}

fn key(raw: u32) -> virtio::VirtioChildDeviceKey {
    virtio::VirtioChildDeviceKey::from_raw(raw)
}

fn ctx(device_key: virtio::VirtioChildDeviceKey) -> Ctx {
    Ctx {
        device_key,
        cfg_va: 0,
        hhdm: 0,
        guest_cid: device_key.raw() as u64,
        rxq: queue(0),
        txq: queue(1),
        rx_avail_idx: 0,
        rx_used_seen: 0,
        rx_bufs: [0; RX_RING_BUFS],
        tx_avail_idx: 0,
        tx_used_seen: 0,
        tx_buf_pa: 0,
    }
}

#[test]
fn removing_one_vsock_context_keeps_shared_softirq_owned() {
    let _guard = TEST_LOCK.lock();
    crate::registry::clear_ctxs_for_tests();
    {
        let mut ctxs = crate::registry::CTX.lock();
        ctxs.push(ctx(key(0x0010_0000)));
        ctxs.push(ctx(key(0x0020_0000)));
    }

    let Some((removed, empty_after)) = crate::registry::remove_ctx(key(0x0010_0000)) else {
        panic!("expected first context removal");
    };
    assert_eq!(removed.device_key, key(0x0010_0000));
    assert!(!empty_after);
    assert!(present_for(key(0x0020_0000)));
    crate::registry::clear_ctxs_for_tests();
}

#[test]
fn removing_last_vsock_context_releases_shared_softirq_owner() {
    let _guard = TEST_LOCK.lock();
    crate::registry::clear_ctxs_for_tests();
    crate::registry::CTX.lock().push(ctx(key(0x0010_0000)));

    let Some((removed, empty_after)) = crate::registry::remove_ctx(key(0x0010_0000)) else {
        panic!("expected last context removal");
    };
    assert_eq!(removed.device_key, key(0x0010_0000));
    assert!(empty_after);
    assert!(!present());
}

#[test]
fn missing_vsock_context_removal_leaves_live_contexts() {
    let _guard = TEST_LOCK.lock();
    crate::registry::clear_ctxs_for_tests();
    crate::registry::CTX.lock().push(ctx(key(0x0020_0000)));

    assert!(crate::registry::remove_ctx(key(0x0010_0000)).is_none());
    assert!(present_for(key(0x0020_0000)));
    crate::registry::clear_ctxs_for_tests();
}

#[test]
fn uninstall_clears_endpoint_without_primary_context() {
    fn tx_stub(_owner: u32, _packet: &[u8]) -> bool { true }

    let _guard = TEST_LOCK.lock();
    crate::registry::clear_ctxs_for_tests();
    assert!(net::vsock::driver_install(0x0010_0000, 3, tx_stub));

    assert!(uninstall(key(0x0010_0000)));
    assert!(!net::vsock::driver_uninstall(0x0010_0000));
    assert!(!uninstall(key(0x0010_0000)));
}

#[test]
fn shutdown_quiesces_endpoint_without_primary_context() {
    fn tx_stub(_owner: u32, _packet: &[u8]) -> bool { true }

    let _guard = TEST_LOCK.lock();
    crate::registry::clear_ctxs_for_tests();
    assert!(net::vsock::driver_install(0x0010_0000, 3, tx_stub));

    assert!(shutdown(key(0x0010_0000)));
    assert!(shutdown(key(0x0010_0000)));
    let _ = net::vsock::driver_uninstall(0x0010_0000);
}
