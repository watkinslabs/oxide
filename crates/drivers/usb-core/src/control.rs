//! USB control-transfer setup-packet contracts.

/// USB device descriptor type. # C: O(1)
pub const DESC_DEVICE: u8 = 1;
/// USB configuration descriptor type. # C: O(1)
pub const DESC_CONFIGURATION: u8 = 2;
/// USB hub descriptor type. # C: O(1)
pub const DESC_HUB: u8 = 0x29;

const REQUEST_GET_STATUS: u8 = 0;
const REQUEST_CLEAR_FEATURE: u8 = 1;
const REQUEST_SET_FEATURE: u8 = 3;
const REQUEST_GET_DESCRIPTOR: u8 = 6;
const REQUEST_SET_CONFIGURATION: u8 = 9;
const REQUEST_SET_IDLE: u8 = 10;
const REQUEST_SET_PROTOCOL: u8 = 11;
const REQUEST_GET_MAX_LUN: u8 = 0xfe;
const TYPE_STANDARD_DEVICE_IN: u8 = 0x80;
const TYPE_STANDARD_DEVICE_OUT: u8 = 0;
const TYPE_HID_INTERFACE_IN: u8 = 0x81;
const TYPE_HID_INTERFACE_OUT: u8 = 0x21;
const TYPE_MASS_STORAGE_INTERFACE_IN: u8 = 0xa1;
const TYPE_HUB_DEVICE_IN: u8 = 0xa0;
const TYPE_HUB_PORT_IN: u8 = 0xa3;
const TYPE_HUB_PORT_OUT: u8 = 0x23;
const DESC_HID_REPORT: u8 = 0x22;

/// USB setup-stage wire fields, before host-controller encoding. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ControlSetup { pub request_type: u8, pub request: u8, pub value: u16, pub index: u16, pub length: u16 }

impl ControlSetup {
    /// Construct one standard descriptor request. # C: O(1)
    pub const fn descriptor(request_type: u8, descriptor: u8, index: u8, length: u16) -> Self {
        Self { request_type, request: REQUEST_GET_DESCRIPTOR, value: u16::from_le_bytes([index, descriptor]), index: 0, length }
    }
}

/// Standard device-descriptor request for address-zero enumeration. # C: O(1)
pub const fn get_device_descriptor(length: u16) -> ControlSetup { ControlSetup::descriptor(TYPE_STANDARD_DEVICE_IN, DESC_DEVICE, 0, length) }
/// Standard configuration-descriptor request. # C: O(1)
pub const fn get_configuration_descriptor(index: u8, length: u16) -> ControlSetup { ControlSetup::descriptor(TYPE_STANDARD_DEVICE_IN, DESC_CONFIGURATION, index, length) }
/// Hub-class descriptor request. # C: O(1)
pub const fn get_hub_descriptor(length: u16) -> ControlSetup { ControlSetup::descriptor(TYPE_HUB_DEVICE_IN, DESC_HUB, 0, length) }
/// Hub-port status request, rejecting the invalid zero recipient. # C: O(1)
pub const fn get_hub_port_status(port: u8, length: u16) -> Option<ControlSetup> {
    if port == 0 { return None; }
    Some(ControlSetup { request_type: TYPE_HUB_PORT_IN, request: REQUEST_GET_STATUS, value: 0, index: port as u16, length })
}
/// Hub-port feature mutation, rejecting the invalid zero recipient. # C: O(1)
pub const fn hub_port_feature(port: u8, feature: u16, set: bool) -> Option<ControlSetup> {
    if port == 0 { return None; }
    Some(ControlSetup { request_type: TYPE_HUB_PORT_OUT, request: if set { REQUEST_SET_FEATURE } else { REQUEST_CLEAR_FEATURE }, value: feature, index: port as u16, length: 0 })
}
/// HID report-descriptor request for one interface. # C: O(1)
pub const fn get_hid_report_descriptor(interface: u8, length: u16) -> ControlSetup {
    ControlSetup { request_type: TYPE_HID_INTERFACE_IN, request: REQUEST_GET_DESCRIPTOR, value: u16::from_le_bytes([0, DESC_HID_REPORT]), index: interface as u16, length }
}
/// HID class idle-rate request for one interface. # C: O(1)
pub const fn set_hid_idle(interface: u8) -> ControlSetup { ControlSetup { request_type: TYPE_HID_INTERFACE_OUT, request: REQUEST_SET_IDLE, value: 0, index: interface as u16, length: 0 } }
/// Standard no-data configuration selection, rejecting configuration zero. # C: O(1)
pub const fn set_configuration(value: u8) -> Option<ControlSetup> {
    if value == 0 { return None; }
    Some(ControlSetup { request_type: TYPE_STANDARD_DEVICE_OUT, request: REQUEST_SET_CONFIGURATION, value: value as u16, index: 0, length: 0 })
}
/// HID Boot protocol selection for one interface. # C: O(1)
pub const fn set_hid_boot_protocol(interface: u8) -> ControlSetup { ControlSetup { request_type: TYPE_HID_INTERFACE_OUT, request: REQUEST_SET_PROTOCOL, value: 0, index: interface as u16, length: 0 } }
/// Bulk-Only Transport GET_MAX_LUN request for one configured interface. # C: O(1)
pub const fn get_mass_storage_max_lun(interface: u8) -> ControlSetup {
    ControlSetup { request_type: TYPE_MASS_STORAGE_INTERFACE_IN, request: REQUEST_GET_MAX_LUN, value: 0, index: interface as u16, length: 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumeration_and_hid_setup_packets_are_exact() {
        assert_eq!(get_device_descriptor(18), ControlSetup { request_type: 0x80, request: 6, value: 0x0100, index: 0, length: 18 });
        assert_eq!(get_configuration_descriptor(2, 34), ControlSetup { request_type: 0x80, request: 6, value: 0x0202, index: 0, length: 34 });
        assert_eq!(get_hid_report_descriptor(3, 52), ControlSetup { request_type: 0x81, request: 6, value: 0x2200, index: 3, length: 52 });
        assert_eq!(set_hid_idle(3), ControlSetup { request_type: 0x21, request: 10, value: 0, index: 3, length: 0 });
        assert_eq!(set_hid_boot_protocol(3), ControlSetup { request_type: 0x21, request: 11, value: 0, index: 3, length: 0 });
        assert_eq!(get_mass_storage_max_lun(3), ControlSetup { request_type: 0xa1, request: 0xfe, value: 0, index: 3, length: 1 });
    }

    #[test]
    fn hub_and_configuration_reject_invalid_recipients() {
        assert_eq!(get_hub_descriptor(9), ControlSetup { request_type: 0xa0, request: 6, value: 0x2900, index: 0, length: 9 });
        assert_eq!(get_hub_port_status(0, 4), None);
        assert_eq!(hub_port_feature(0, 8, true), None);
        assert_eq!(set_configuration(0), None);
        assert_eq!(get_hub_port_status(2, 4), Some(ControlSetup { request_type: 0xa3, request: 0, value: 0, index: 2, length: 4 }));
        assert_eq!(hub_port_feature(2, 8, true), Some(ControlSetup { request_type: 0x23, request: 3, value: 8, index: 2, length: 0 }));
    }
}
