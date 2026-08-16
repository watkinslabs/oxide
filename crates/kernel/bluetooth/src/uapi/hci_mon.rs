//! Monitor channel ABI: the record header and the opcodes that name what each
//! record carries. A monitor socket receives a copy of every frame on every
//! controller, each wrapped in this header, which is what a live protocol trace
//! is made of.

/// `struct hci_mon_hdr`: opcode, controller index, payload length.
pub const HCI_MON_HDR_SIZE: usize = 6;
pub const MON_HDR_OPCODE_OFF: usize = 0;
pub const MON_HDR_INDEX_OFF:  usize = 2;
pub const MON_HDR_LEN_OFF:    usize = 4;

pub const HCI_MON_NEW_INDEX:    u16 = 0;
pub const HCI_MON_DEL_INDEX:    u16 = 1;
pub const HCI_MON_COMMAND_PKT:  u16 = 2;
pub const HCI_MON_EVENT_PKT:    u16 = 3;
pub const HCI_MON_ACL_TX_PKT:   u16 = 4;
pub const HCI_MON_ACL_RX_PKT:   u16 = 5;
pub const HCI_MON_SCO_TX_PKT:   u16 = 6;
pub const HCI_MON_SCO_RX_PKT:   u16 = 7;
pub const HCI_MON_OPEN_INDEX:   u16 = 8;
pub const HCI_MON_CLOSE_INDEX:  u16 = 9;
pub const HCI_MON_INDEX_INFO:   u16 = 10;
pub const HCI_MON_VENDOR_DIAG:  u16 = 11;
pub const HCI_MON_SYSTEM_NOTE:  u16 = 12;
pub const HCI_MON_USER_LOGGING: u16 = 13;
pub const HCI_MON_CTRL_OPEN:    u16 = 14;
pub const HCI_MON_CTRL_CLOSE:   u16 = 15;
pub const HCI_MON_CTRL_COMMAND: u16 = 16;
pub const HCI_MON_CTRL_EVENT:   u16 = 17;
pub const HCI_MON_ISO_TX_PKT:   u16 = 18;
pub const HCI_MON_ISO_RX_PKT:   u16 = 19;

/// `struct hci_mon_new_index`: controller type, bus, address, short name.
pub const HCI_MON_NEW_INDEX_SIZE: usize = 16;
pub const MON_NEW_INDEX_TYPE_OFF:   usize = 0;
pub const MON_NEW_INDEX_BUS_OFF:    usize = 1;
pub const MON_NEW_INDEX_BDADDR_OFF: usize = 2;
pub const MON_NEW_INDEX_NAME_OFF:   usize = 8;
pub const MON_NEW_INDEX_NAME_LEN:   usize = 8;

/// `struct hci_mon_index_info`: address and manufacturer.
pub const HCI_MON_INDEX_INFO_SIZE: usize = 8;
pub const MON_INDEX_INFO_BDADDR_OFF:       usize = 0;
pub const MON_INDEX_INFO_MANUFACTURER_OFF: usize = 6;

#[cfg(test)]
#[path = "tests/hci_mon.rs"]
mod tests;
