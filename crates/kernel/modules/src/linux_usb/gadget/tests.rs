use super::*;
use core::ptr::{null, null_mut};
use core::sync::atomic::{AtomicUsize, Ordering};

static QUEUES: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn queue(_ep: *mut UsbEndpoint, req: *mut UsbRequest, _gfp: u32) -> i32 {
    unsafe {
        (*req).actual = (*req).length;
        (*req).status = LINUX_OK;
    }
    QUEUES.fetch_add(1, Ordering::Relaxed);
    LINUX_OK
}

#[test]
fn request_alloc_queue_free_uses_endpoint_ops() {
    let _modules = crate::test_serial::claim();
    QUEUES.store(0, Ordering::Relaxed);
    let ops = UsbEpOps { enable: None, disable: None, alloc_request: None, free_request: None, queue: Some(queue), dequeue: None };
    let mut ep = test_ep(&ops);
    let req = unsafe { usb_ep_alloc_request(&mut ep, 0) };
    assert!(!req.is_null());
    unsafe {
        (*req).length = 64;
        assert_eq!(usb_ep_queue(&mut ep, req, 0), LINUX_OK);
        assert_eq!((*req).actual, 64);
        assert_eq!(usb_ep_dequeue(&mut ep, req), LINUX_OK);
        assert_eq!((*req).status, -LINUX_ENOENT);
        usb_ep_free_request(&mut ep, req);
    }
    assert_eq!(QUEUES.load(Ordering::Relaxed), 1);
}

#[test]
fn gadget_state_helpers_update_flags() {
    let _modules = crate::test_serial::claim();
    let mut gadget = test_gadget();
    assert_eq!(usb_gadget_set_selfpowered(&mut gadget), LINUX_OK);
    assert_eq!(usb_gadget_set_remote_wakeup(&mut gadget, 1), LINUX_OK);
    assert_eq!(usb_gadget_vbus_draw(&mut gadget, 250), LINUX_OK);
    assert_eq!(usb_gadget_deactivate(&mut gadget), LINUX_OK);
    usb_gadget_set_state(&mut gadget, 3);
    assert_eq!(gadget.is_selfpowered, 1);
    assert_eq!(gadget.remote_wakeup, 1);
    assert_eq!(gadget.vbus_draw_ma, 250);
    assert_eq!(gadget.deactivated, 1);
    assert_eq!(gadget.connected, 0);
    assert_eq!(gadget.state, 3);
    assert_eq!(usb_gadget_activate(&mut gadget), LINUX_OK);
    assert_eq!(gadget.connected, 1);
}

#[test]
fn endpoint_match_checks_direction_type_and_packet_limit() {
    let _modules = crate::test_serial::claim();
    let ops = UsbEpOps { enable: None, disable: None, alloc_request: None, free_request: None, queue: None, dequeue: None };
    let mut ep = test_ep(&ops);
    let mut gadget = test_gadget();
    let desc = UsbEndpointDescriptor {
        b_endpoint_address: USB_DIR_IN | 1,
        bm_attributes: USB_ENDPOINT_XFER_BULK,
        w_max_packet_size: 512,
        ..UsbEndpointDescriptor::default()
    };
    assert_eq!(usb_gadget_ep_match_desc(&mut gadget, &mut ep, &desc, null()), 1);
    let too_large = UsbEndpointDescriptor { w_max_packet_size: 1024, ..desc };
    assert_eq!(usb_gadget_ep_match_desc(&mut gadget, &mut ep, &too_large, null()), 0);
}

#[test]
fn gadget_driver_registration_is_singleton() {
    let _modules = crate::test_serial::claim();
    GADGET_DRIVER.lock().take();
    let mut driver = UsbGadgetDriver {
        function: c"sample".as_ptr(), max_speed: USB_SPEED_HIGH, bind: None, unbind: None,
        setup: None, disconnect: None, suspend: None, resume: None, reset: None,
        driver: null_mut(),
    };
    assert_eq!(usb_gadget_register_driver_owner(&mut driver, null_mut()), LINUX_OK);
    assert_eq!(usb_gadget_register_driver_owner(&mut driver, null_mut()), -LINUX_EBUSY);
    usb_gadget_unregister_driver(&mut driver);
    assert!(GADGET_DRIVER.lock().is_none());
}

fn test_ep(ops: &UsbEpOps) -> UsbEndpoint {
    UsbEndpoint {
        name: c"ep1in".as_ptr(), ops, ep_list: ListHead::default(),
        caps: UsbEpCaps { type_control: 0, type_iso: 0, type_bulk: 1, type_int: 1, dir_in: 1, dir_out: 0 },
        maxpacket: 512, maxpacket_limit: 512, max_streams: 0, enabled: 0,
        address: USB_DIR_IN | 1, desc: null(), driver_data: null_mut(),
    }
}

fn test_gadget() -> UsbGadget {
    UsbGadget {
        ops: null(), ep0: null_mut(), ep_list: ListHead::default(),
        speed: USB_SPEED_HIGH, max_speed: USB_SPEED_HIGH, state: 0,
        name: c"sample-gadget".as_ptr(), dev: unsafe { core::mem::zeroed() },
        is_selfpowered: 0, deactivated: 0, connected: 0, remote_wakeup: 0,
        vbus_draw_ma: 0, driver: null_mut(),
    }
}
