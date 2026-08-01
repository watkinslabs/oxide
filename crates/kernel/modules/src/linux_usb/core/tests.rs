use super::*;
use core::sync::atomic::{AtomicUsize, Ordering};

const USB_CLASS_HID: u8 = 3;
const TEST_VENDOR: u16 = 0x1af4;
const TEST_PRODUCT: u16 = 0x1050;

static PROBES: AtomicUsize = AtomicUsize::new(0);
static COMPLETES: AtomicUsize = AtomicUsize::new(0);
static DISCONNECTS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn probe(intf: *mut UsbInterface, id: *const UsbDeviceId) -> i32 {
    assert!(!intf.is_null());
    assert!(!id.is_null());
    PROBES.fetch_add(1, Ordering::Relaxed);
    LINUX_OK
}

unsafe extern "C" fn complete(_urb: *mut UsbUrb) {
    COMPLETES.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn disconnect(intf: *mut UsbInterface) {
    assert!(!intf.is_null());
    DISCONNECTS.fetch_add(1, Ordering::Relaxed);
}

fn bulk_ok(_dev: *mut UsbDevice, _pipe: u32, _data: *mut c_void, len: i32, actual: *mut i32, _timeout: i32) -> i32 {
    if !actual.is_null() { unsafe { *actual = len; } }
    LINUX_OK
}

fn submit_ok(urb: *mut UsbUrb) -> i32 {
    if !urb.is_null() { unsafe { (*urb).actual_length = (*urb).transfer_buffer_length; } }
    LINUX_OK
}

#[test]
fn register_driver_binds_matching_interface() {
    let _modules = crate::test_serial::claim();
    PROBES.store(0, Ordering::Relaxed);
    DRIVERS.lock().clear();
    INTERFACES.lock().clear();
    let mut dev = test_device();
    let mut alt = test_alt();
    let mut intf = test_interface(&mut dev, &mut alt);
    let ids = [
        UsbDeviceId {
            match_flags: USB_DEVICE_ID_MATCH_VENDOR | USB_DEVICE_ID_MATCH_PRODUCT | USB_DEVICE_ID_MATCH_INT_CLASS,
            id_vendor: TEST_VENDOR,
            id_product: TEST_PRODUCT,
            b_interface_class: USB_CLASS_HID,
            ..UsbDeviceId::default()
        },
        UsbDeviceId::default(),
    ];
    let mut driver = UsbDriver { name: c"usb-test".as_ptr(), probe: Some(probe), disconnect: None, id_table: ids.as_ptr() };
    unsafe { assert_eq!(install_interface(&mut intf), LINUX_OK); }
    assert_eq!(usb_register_driver(&mut driver), LINUX_OK);
    assert_eq!(PROBES.load(Ordering::Relaxed), 1);
    assert_eq!(intf.driver, &mut driver as *mut UsbDriver);
}

#[test]
fn uninstall_interface_disconnects_bound_driver() {
    let _modules = crate::test_serial::claim();
    PROBES.store(0, Ordering::Relaxed);
    DISCONNECTS.store(0, Ordering::Relaxed);
    DRIVERS.lock().clear();
    INTERFACES.lock().clear();
    let mut dev = test_device();
    let mut alt = test_alt();
    let mut intf = test_interface(&mut dev, &mut alt);
    let ids = [
        UsbDeviceId {
            match_flags: USB_DEVICE_ID_MATCH_VENDOR | USB_DEVICE_ID_MATCH_PRODUCT | USB_DEVICE_ID_MATCH_INT_CLASS,
            id_vendor: TEST_VENDOR,
            id_product: TEST_PRODUCT,
            b_interface_class: USB_CLASS_HID,
            ..UsbDeviceId::default()
        },
        UsbDeviceId::default(),
    ];
    let mut driver = UsbDriver { name: c"usb-test".as_ptr(), probe: Some(probe), disconnect: Some(disconnect), id_table: ids.as_ptr() };
    assert_eq!(usb_register_driver(&mut driver), LINUX_OK);
    unsafe { assert_eq!(install_interface(&mut intf), LINUX_OK); }
    assert_eq!(PROBES.load(Ordering::Relaxed), 1);
    unsafe { uninstall_interface(&mut intf); }
    assert_eq!(DISCONNECTS.load(Ordering::Relaxed), 1);
    assert!(intf.driver.is_null());
    assert_eq!(intf.registered, 0);
}

#[test]
fn transfers_use_transport_or_enodev() {
    let _modules = crate::test_serial::claim();
    clear_transport();
    let mut dev = test_device();
    let mut actual = 7;
    assert_eq!(usb_bulk_msg(&mut dev, 0, null_mut(), 4, &mut actual, 10), -LINUX_ENODEV);
    assert_eq!(actual, 0);
    set_transport(UsbTransport { bulk: Some(bulk_ok), submit: Some(submit_ok), control: None, interrupt: None });
    assert_eq!(usb_bulk_msg(&mut dev, 0, null_mut(), 4, &mut actual, 10), LINUX_OK);
    assert_eq!(actual, 4);
}

#[test]
fn urb_submit_records_status_and_completion() {
    let _modules = crate::test_serial::claim();
    COMPLETES.store(0, Ordering::Relaxed);
    set_transport(UsbTransport { bulk: None, submit: Some(submit_ok), control: None, interrupt: None });
    let urb = usb_alloc_urb(0, 0);
    assert!(!urb.is_null());
    unsafe {
        (*urb).transfer_buffer_length = 8;
        (*urb).complete = Some(complete);
        assert_eq!(usb_submit_urb(urb, 0), LINUX_OK);
        assert_eq!((*urb).actual_length, 8);
        assert_eq!((*urb).status, LINUX_OK);
        usb_free_urb(urb);
    }
    assert_eq!(COMPLETES.load(Ordering::Relaxed), 1);
}

#[test]
fn coherent_alloc_returns_dma_handle() {
    let _modules = crate::test_serial::claim();
    let mut dma = 0u64;
    let p = usb_alloc_coherent(null_mut(), 64, 0, &mut dma);
    assert!(!p.is_null());
    assert_ne!(dma, 0);
    usb_free_coherent(null_mut(), 64, p, dma);
}

fn test_device() -> UsbDevice {
    UsbDevice {
        dev: unsafe { core::mem::zeroed() },
        descriptor: UsbDeviceDescriptor { id_vendor: TEST_VENDOR, id_product: TEST_PRODUCT, bcd_device: 1, ..UsbDeviceDescriptor::default() },
        devnum: 1,
        speed: 0,
        maxchild: 0,
        driver_data: null_mut(),
        refcnt: 1,
    }
}

fn test_alt() -> UsbHostInterface {
    UsbHostInterface {
        desc: UsbInterfaceDescriptor { b_interface_class: USB_CLASS_HID, ..UsbInterfaceDescriptor::default() },
        endpoint: null_mut(),
        extra: null(),
        extralen: 0,
    }
}

fn test_interface(dev: &mut UsbDevice, alt: &mut UsbHostInterface) -> UsbInterface {
    UsbInterface {
        dev: unsafe { core::mem::zeroed() },
        altsetting: alt,
        cur_altsetting: alt,
        num_altsetting: 1,
        usb_dev: dev,
        intfdata: null_mut(),
        registered: 0,
        driver: null_mut(),
    }
}
