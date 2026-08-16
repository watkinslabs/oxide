//! HCI wire ABI: the H:4 packet-type prefixes, the four packet headers, the
//! buffer ceilings, the link and bus taxonomies, and the controller status
//! byte. Opcodes live in `uapi::hci_cmd`, event codes in `uapi::hci_evt`.

/// H:4 packet-type prefix, the first byte of every frame on the transport.
pub const HCI_COMMAND_PKT: u8 = 0x01;
pub const HCI_ACLDATA_PKT: u8 = 0x02;
pub const HCI_SCODATA_PKT: u8 = 0x03;
pub const HCI_EVENT_PKT:   u8 = 0x04;
pub const HCI_ISODATA_PKT: u8 = 0x05;
pub const HCI_DIAG_PKT:    u8 = 0xf0;
pub const HCI_DRV_PKT:     u8 = 0xf1;
pub const HCI_VENDOR_PKT:  u8 = 0xff;

/// Header widths, excluding the H:4 prefix byte.
pub const HCI_COMMAND_HDR_SIZE:  usize = 3;
pub const HCI_EVENT_HDR_SIZE:    usize = 2;
pub const HCI_ACL_HDR_SIZE:      usize = 4;
pub const HCI_SCO_HDR_SIZE:      usize = 3;
pub const HCI_ISO_HDR_SIZE:      usize = 4;

/// Payload ceilings.
pub const HCI_MAX_ACL_SIZE:   usize = 1024;
pub const HCI_MAX_SCO_SIZE:   usize = 255;
pub const HCI_MAX_ISO_SIZE:   usize = 251;
pub const HCI_MAX_EVENT_SIZE: usize = 260;
/// Largest frame including the H:4 prefix and the widest header.
pub const HCI_MAX_FRAME_SIZE: usize = HCI_MAX_ACL_SIZE + 4;
pub const HCI_MAX_NAME_LENGTH: usize = 248;
pub const HCI_MAX_EIR_LENGTH:  usize = 240;
pub const HCI_MAX_AD_LENGTH:   usize = 31;

/// Baseband link type carried by a connection.
pub const SCO_LINK:     u8 = 0x00;
pub const ACL_LINK:     u8 = 0x01;
pub const ESCO_LINK:    u8 = 0x02;
pub const LE_LINK:      u8 = 0x80;
pub const CIS_LINK:     u8 = 0x82;
pub const BIS_LINK:     u8 = 0x83;
pub const PA_LINK:      u8 = 0x84;
pub const INVALID_LINK: u8 = 0xff;

/// Transport bus the controller is attached by, reported to the monitor and to
/// `HCIGETDEVINFO`.
pub const HCI_VIRTUAL: u8 = 0;
pub const HCI_USB:     u8 = 1;
pub const HCI_PCCARD:  u8 = 2;
pub const HCI_UART:    u8 = 3;
pub const HCI_RS232:   u8 = 4;
pub const HCI_PCI:     u8 = 5;
pub const HCI_SDIO:    u8 = 6;
pub const HCI_SPI:     u8 = 7;
pub const HCI_I2C:     u8 = 8;
pub const HCI_SMD:     u8 = 9;

/// Controller status byte. Success is zero; every other value is a refusal the
/// host maps onto an errno or a management status.
pub const HCI_SUCCESS:                    u8 = 0x00;
pub const HCI_ERROR_UNKNOWN_CONN_ID:      u8 = 0x02;
pub const HCI_ERROR_AUTH_FAILURE:         u8 = 0x05;
pub const HCI_ERROR_PIN_OR_KEY_MISSING:   u8 = 0x06;
pub const HCI_ERROR_MEMORY_EXCEEDED:      u8 = 0x07;
pub const HCI_ERROR_CONNECTION_TIMEOUT:   u8 = 0x08;
pub const HCI_ERROR_COMMAND_DISALLOWED:   u8 = 0x0c;
pub const HCI_ERROR_REJ_LIMITED_RESOURCES: u8 = 0x0d;
pub const HCI_ERROR_REJ_BAD_ADDR:         u8 = 0x0f;
pub const HCI_ERROR_INVALID_PARAMETERS:   u8 = 0x12;
pub const HCI_ERROR_REMOTE_USER_TERM:     u8 = 0x13;
pub const HCI_ERROR_REMOTE_LOW_RESOURCES: u8 = 0x14;
pub const HCI_ERROR_REMOTE_POWER_OFF:     u8 = 0x15;
pub const HCI_ERROR_LOCAL_HOST_TERM:      u8 = 0x16;
pub const HCI_ERROR_PAIRING_NOT_ALLOWED:  u8 = 0x18;
pub const HCI_ERROR_UNSUPPORTED_REMOTE_FEATURE: u8 = 0x1a;
pub const HCI_ERROR_INVALID_LL_PARAMS:    u8 = 0x1e;
pub const HCI_ERROR_UNSPECIFIED:          u8 = 0x1f;
pub const HCI_ERROR_ADVERTISING_TIMEOUT:  u8 = 0x3c;
pub const HCI_ERROR_CANCELLED_BY_HOST:    u8 = 0x44;

/// ACL packet-boundary and broadcast flags, packed with the handle in the ACL
/// header's first word.
pub const ACL_START_NO_FLUSH: u16 = 0x00;
pub const ACL_CONT:           u16 = 0x01;
pub const ACL_START:          u16 = 0x02;
pub const ACL_ACTIVE_BCAST:   u16 = 0x04;
pub const ACL_PICO_BCAST:     u16 = 0x08;

/// Handle field width in the ACL/SCO header word; the remaining bits are flags.
pub const HCI_HANDLE_BITS: u32 = 12;
pub const HCI_HANDLE_MASK: u16 = (1 << HCI_HANDLE_BITS) - 1;

/// Split an ACL header word into its handle and its flag nibble. # C: O(1)
pub fn acl_unpack(word: u16) -> (u16, u16) { (word & HCI_HANDLE_MASK, word >> HCI_HANDLE_BITS) }

/// Pack a handle and flag nibble into an ACL header word. # C: O(1)
pub fn acl_pack(handle: u16, flags: u16) -> u16 {
    (handle & HCI_HANDLE_MASK) | (flags << HCI_HANDLE_BITS)
}

/// Link policy bits.
pub const HCI_LP_RSWITCH: u16 = 0x0001;
pub const HCI_LP_HOLD:    u16 = 0x0002;
pub const HCI_LP_SNIFF:   u16 = 0x0004;
pub const HCI_LP_PARK:    u16 = 0x0008;

/// Link mode bits, as reported by `HCIGETCONNINFO` and requested by `HCI_LM`.
pub const HCI_LM_ACCEPT:  u16 = 0x8000;
pub const HCI_LM_MASTER:  u16 = 0x0001;
pub const HCI_LM_AUTH:    u16 = 0x0002;
pub const HCI_LM_ENCRYPT: u16 = 0x0004;
pub const HCI_LM_TRUSTED: u16 = 0x0008;
pub const HCI_LM_RELIABLE: u16 = 0x0010;
pub const HCI_LM_SECURE:  u16 = 0x0020;
pub const HCI_LM_FIPS:    u16 = 0x0040;

/// SCO/eSCO packet-type bits, as negotiated by a synchronous connection setup.
pub const ESCO_HV1:  u16 = 0x0001;
pub const ESCO_HV2:  u16 = 0x0002;
pub const ESCO_HV3:  u16 = 0x0004;
pub const ESCO_EV3:  u16 = 0x0008;
pub const ESCO_EV4:  u16 = 0x0010;
pub const ESCO_EV5:  u16 = 0x0020;
pub const ESCO_2EV3: u16 = 0x0040;
pub const ESCO_3EV3: u16 = 0x0080;
pub const ESCO_2EV5: u16 = 0x0100;
pub const ESCO_3EV5: u16 = 0x0200;
pub const SCO_ESCO_MASK: u16 = ESCO_HV1 | ESCO_HV2 | ESCO_HV3;
pub const EDR_ESCO_MASK: u16 = ESCO_2EV3 | ESCO_3EV3 | ESCO_2EV5 | ESCO_3EV5;

/// Air-coding field of a synchronous link's voice setting.
pub const SCO_AIRMODE_MASK:   u16 = 0x0003;
pub const SCO_AIRMODE_CVSD:   u16 = 0x0000;
pub const SCO_AIRMODE_TRANSP: u16 = 0x0003;

/// Extended-inquiry / advertising data field types.
pub const EIR_FLAGS:         u8 = 0x01;
pub const EIR_UUID16_SOME:   u8 = 0x02;
pub const EIR_UUID16_ALL:    u8 = 0x03;
pub const EIR_UUID32_SOME:   u8 = 0x04;
pub const EIR_UUID32_ALL:    u8 = 0x05;
pub const EIR_UUID128_SOME:  u8 = 0x06;
pub const EIR_UUID128_ALL:   u8 = 0x07;
pub const EIR_NAME_SHORT:    u8 = 0x08;
pub const EIR_NAME_COMPLETE: u8 = 0x09;
pub const EIR_TX_POWER:      u8 = 0x0a;
pub const EIR_CLASS_OF_DEV:  u8 = 0x0d;
pub const EIR_SSP_HASH_C192: u8 = 0x0e;
pub const EIR_SSP_RAND_R192: u8 = 0x0f;
pub const EIR_DEVICE_ID:     u8 = 0x10;
pub const EIR_SERVICE_DATA:  u8 = 0x16;
pub const EIR_APPEARANCE:    u8 = 0x19;
pub const EIR_LE_BDADDR:     u8 = 0x1b;
pub const EIR_LE_ROLE:       u8 = 0x1c;
pub const EIR_SSP_HASH_C256: u8 = 0x1d;
pub const EIR_SSP_RAND_R256: u8 = 0x1e;
pub const EIR_LE_SC_CONFIRM: u8 = 0x22;
pub const EIR_LE_SC_RANDOM:  u8 = 0x23;

/// Class-of-device field width, in every ABI struct that carries one.
pub const DEV_CLASS_LEN: usize = 3;

/// Timers, in milliseconds. A command that draws no completion within
/// `HCI_CMD_TIMEOUT` has lost its credit and the controller is declared wedged.
pub const HCI_CMD_TIMEOUT_MS:      u64 = 2_000;
pub const HCI_NCMD_TIMEOUT_MS:     u64 = 4_000;
pub const HCI_INIT_TIMEOUT_MS:     u64 = 10_000;
pub const HCI_ACL_TX_TIMEOUT_MS:   u64 = 45_000;
pub const HCI_DISCONN_TIMEOUT_MS:  u64 = 2_000;
pub const HCI_PAIRING_TIMEOUT_MS:  u64 = 60_000;
pub const HCI_AUTO_OFF_TIMEOUT_MS: u64 = 2_000;
pub const HCI_ACL_CONN_TIMEOUT_MS: u64 = 20_000;
pub const HCI_LE_CONN_TIMEOUT_MS:  u64 = 20_000;

/// The one command credit a controller grants at a time. The host holds at most
/// one outstanding command; a completion restores the credit to exactly this
/// value rather than incrementing, so a controller that double-reports cannot
/// inflate the host's allowance.
pub const HCI_CMD_CREDIT_ONE: u16 = 1;

#[cfg(test)]
#[path = "tests/hci.rs"]
mod tests;
