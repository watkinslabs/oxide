use crate::linux_device::types::LinuxDevice;
use core::ffi::{c_char, c_void};

pub(super) const LINUX_OK: i32 = 0;
pub(super) const LINUX_EINVAL: i32 = 22;
pub(super) const LINUX_ENODEV: i32 = 19;
pub(super) const LINUX_EBUSY: i32 = 16;
pub(super) const LINUX_ENOENT: i32 = 2;

pub(super) const USB_DEVICE_ID_MATCH_VENDOR: u16 = 0x0001;
pub(super) const USB_DEVICE_ID_MATCH_PRODUCT: u16 = 0x0002;
pub(super) const USB_DEVICE_ID_MATCH_DEV_LO: u16 = 0x0004;
pub(super) const USB_DEVICE_ID_MATCH_DEV_HI: u16 = 0x0008;
pub(super) const USB_DEVICE_ID_MATCH_DEV_CLASS: u16 = 0x0010;
pub(super) const USB_DEVICE_ID_MATCH_DEV_SUBCLASS: u16 = 0x0020;
pub(super) const USB_DEVICE_ID_MATCH_DEV_PROTOCOL: u16 = 0x0040;
pub(super) const USB_DEVICE_ID_MATCH_INT_CLASS: u16 = 0x0080;
pub(super) const USB_DEVICE_ID_MATCH_INT_SUBCLASS: u16 = 0x0100;
pub(super) const USB_DEVICE_ID_MATCH_INT_PROTOCOL: u16 = 0x0200;
pub(super) const PAGE_SIZE: usize = 4096;

pub(super) type UsbProbeFn = unsafe extern "C" fn(*mut UsbInterface, *const UsbDeviceId) -> i32;
pub(super) type UsbDisconnectFn = unsafe extern "C" fn(*mut UsbInterface);
pub(super) type UrbCompleteFn = unsafe extern "C" fn(*mut UsbUrb);

#[repr(C)]
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub(super) struct UsbDeviceId {
    pub(super) match_flags: u16,
    pub(super) id_vendor: u16,
    pub(super) id_product: u16,
    pub(super) bcd_device_lo: u16,
    pub(super) bcd_device_hi: u16,
    pub(super) b_device_class: u8,
    pub(super) b_device_sub_class: u8,
    pub(super) b_device_protocol: u8,
    pub(super) b_interface_class: u8,
    pub(super) b_interface_sub_class: u8,
    pub(super) b_interface_protocol: u8,
    pub(super) driver_info: usize,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub(super) struct UsbDeviceDescriptor {
    pub(super) b_length: u8,
    pub(super) b_descriptor_type: u8,
    pub(super) bcd_usb: u16,
    pub(super) b_device_class: u8,
    pub(super) b_device_sub_class: u8,
    pub(super) b_device_protocol: u8,
    pub(super) b_max_packet_size0: u8,
    pub(super) id_vendor: u16,
    pub(super) id_product: u16,
    pub(super) bcd_device: u16,
    pub(super) i_manufacturer: u8,
    pub(super) i_product: u8,
    pub(super) i_serial_number: u8,
    pub(super) b_num_configurations: u8,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub(super) struct UsbEndpointDescriptor {
    pub(super) b_length: u8,
    pub(super) b_descriptor_type: u8,
    pub(super) b_endpoint_address: u8,
    pub(super) bm_attributes: u8,
    pub(super) w_max_packet_size: u16,
    pub(super) b_interval: u8,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub(super) struct UsbInterfaceDescriptor {
    pub(super) b_length: u8,
    pub(super) b_descriptor_type: u8,
    pub(super) b_interface_number: u8,
    pub(super) b_alternate_setting: u8,
    pub(super) b_num_endpoints: u8,
    pub(super) b_interface_class: u8,
    pub(super) b_interface_sub_class: u8,
    pub(super) b_interface_protocol: u8,
    pub(super) i_interface: u8,
}

#[repr(C)]
pub(super) struct UsbHostInterface {
    pub(super) desc: UsbInterfaceDescriptor,
    pub(super) endpoint: *mut UsbEndpointDescriptor,
    pub(super) extra: *const u8,
    pub(super) extralen: i32,
}

#[repr(C)]
pub(super) struct UsbDevice {
    pub(super) dev: LinuxDevice,
    pub(super) descriptor: UsbDeviceDescriptor,
    pub(super) devnum: i32,
    pub(super) speed: i32,
    pub(super) maxchild: i32,
    pub(super) driver_data: *mut c_void,
    pub(super) refcnt: u32,
}

#[repr(C)]
pub(super) struct UsbInterface {
    pub(super) dev: LinuxDevice,
    pub(super) altsetting: *mut UsbHostInterface,
    pub(super) cur_altsetting: *mut UsbHostInterface,
    pub(super) num_altsetting: u32,
    pub(super) usb_dev: *mut UsbDevice,
    pub(super) intfdata: *mut c_void,
    pub(super) registered: u32,
    pub(super) driver: *mut UsbDriver,
}

#[repr(C)]
pub(super) struct UsbDriver {
    pub(super) name: *const c_char,
    pub(super) probe: Option<UsbProbeFn>,
    pub(super) disconnect: Option<UsbDisconnectFn>,
    pub(super) id_table: *const UsbDeviceId,
}

#[repr(C)]
pub(super) struct UsbUrb {
    pub(super) dev: *mut UsbDevice,
    pub(super) pipe: u32,
    pub(super) status: i32,
    pub(super) transfer_flags: u32,
    pub(super) transfer_buffer: *mut c_void,
    pub(super) transfer_buffer_length: i32,
    pub(super) actual_length: i32,
    pub(super) setup_packet: *mut u8,
    pub(super) context: *mut c_void,
    pub(super) complete: Option<UrbCompleteFn>,
    pub(super) interval: i32,
    pub(super) number_of_packets: i32,
}

#[derive(Copy, Clone)]
pub struct UsbTransport {
    pub control: Option<fn(*mut UsbDevice, u32, u8, u8, u16, u16, *mut c_void, u16, i32) -> i32>,
    pub bulk: Option<fn(*mut UsbDevice, u32, *mut c_void, i32, *mut i32, i32) -> i32>,
    pub interrupt: Option<fn(*mut UsbDevice, u32, *mut c_void, i32, *mut i32, i32) -> i32>,
    pub submit: Option<fn(*mut UsbUrb) -> i32>,
}
