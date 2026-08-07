// PCI configuration-space header ABI: register offsets, header types and
// the sizes userspace observes through the `config` sysfs blob.

/// Config-space offset of the 16-bit command register.
pub const COMMAND_OFF: u8 = 0x04;
/// Config-space offset of the 8-bit revision id.
pub const REVISION_ID_OFF: u8 = 0x08;
/// Config-space offset of the 8-bit header type (bit 7 = multifunction).
pub const HEADER_TYPE_OFF: u8 = 0x0e;
/// Config-space offset of the type-0 subsystem vendor id (16-bit).
pub const SUBSYSTEM_VENDOR_ID_OFF: u8 = 0x2c;
/// Config-space offset of the type-0 subsystem device id (16-bit).
pub const SUBSYSTEM_ID_OFF: u8 = 0x2e;
/// Config-space offset of the type-2 (CardBus) subsystem vendor id.
pub const CB_SUBSYSTEM_VENDOR_ID_OFF: u8 = 0x40;
/// Config-space offset of the type-2 (CardBus) subsystem device id.
pub const CB_SUBSYSTEM_ID_OFF: u8 = 0x42;
/// Config-space offset of the 8-bit interrupt line register.
pub const INTERRUPT_LINE_OFF: u8 = 0x3c;
/// Config-space offset of the 8-bit interrupt pin register.
pub const INTERRUPT_PIN_OFF: u8 = 0x3d;

/// Header-type field mask (bit 7 carries the multifunction flag).
pub const HEADER_TYPE_MASK: u8 = 0x7f;
/// Header type 0: ordinary endpoint function.
pub const HEADER_TYPE_NORMAL: u8 = 0x00;
/// Header type 1: PCI-to-PCI bridge.
pub const HEADER_TYPE_BRIDGE: u8 = 0x01;
/// Header type 2: CardBus bridge.
pub const HEADER_TYPE_CARDBUS: u8 = 0x02;

/// Config-space offset of the type-1 primary bus number.
pub const PRIMARY_BUS_OFF: u8 = 0x18;
/// Config-space offset of the type-1 secondary bus number.
pub const SECONDARY_BUS_OFF: u8 = 0x19;
/// Config-space offset of the type-1 subordinate bus number.
pub const SUBORDINATE_BUS_OFF: u8 = 0x1a;

/// Standard BAR count of a type-0 function.
pub const STD_NUM_BARS: usize = 6;
/// Resource index of the expansion-ROM window, one past the last BAR.
pub const ROM_RESOURCE_INDEX: usize = STD_NUM_BARS;
/// Resource rows a function publishes: every standard BAR plus the ROM.
pub const NUM_RESOURCE_ROWS: usize = ROM_RESOURCE_INDEX + 1;
/// First resource index reserved for PCI-to-PCI bridge forwarding windows.
pub const BRIDGE_RESOURCE_INDEX: usize = NUM_RESOURCE_ROWS;
/// Bridge I/O forwarding window resource index.
pub const BRIDGE_IO_RESOURCE_INDEX: usize = BRIDGE_RESOURCE_INDEX;
/// Bridge non-prefetchable memory forwarding window resource index.
pub const BRIDGE_MEM_RESOURCE_INDEX: usize = BRIDGE_RESOURCE_INDEX + 1;
/// Bridge prefetchable-memory forwarding window resource index.
pub const BRIDGE_PREF_MEM_RESOURCE_INDEX: usize = BRIDGE_RESOURCE_INDEX + 2;
/// Rows a PCI-to-PCI bridge publishes in its `resource` file.
pub const P2P_BRIDGE_RESOURCE_ROWS: usize = BRIDGE_PREF_MEM_RESOURCE_INDEX + 1;

/// PCI-to-PCI bridge I/O base/limit register pair.
pub const BRIDGE_IO_BASE_OFF: u8 = 0x1c;
/// PCI-to-PCI bridge non-prefetchable memory base register.
pub const BRIDGE_MEM_BASE_OFF: u8 = 0x20;
/// PCI-to-PCI bridge non-prefetchable memory limit register.
pub const BRIDGE_MEM_LIMIT_OFF: u8 = 0x22;
/// PCI-to-PCI bridge prefetchable-memory base register.
pub const BRIDGE_PREF_MEM_BASE_OFF: u8 = 0x24;
/// PCI-to-PCI bridge prefetchable-memory limit register.
pub const BRIDGE_PREF_MEM_LIMIT_OFF: u8 = 0x26;
/// PCI-to-PCI bridge prefetchable-memory upper-base register.
pub const BRIDGE_PREF_BASE_UPPER_OFF: u8 = 0x28;
/// PCI-to-PCI bridge prefetchable-memory upper-limit register.
pub const BRIDGE_PREF_LIMIT_UPPER_OFF: u8 = 0x2c;
/// PCI-to-PCI bridge I/O upper-base register.
pub const BRIDGE_IO_BASE_UPPER_OFF: u8 = 0x30;
/// PCI-to-PCI bridge I/O upper-limit register.
pub const BRIDGE_IO_LIMIT_UPPER_OFF: u8 = 0x32;

/// Class-code value (`class >> 8`) of an undefined-class VGA device.
pub const CLASS_NOT_DEFINED_VGA: u32 = 0x0001;
/// Class-code value (`class >> 8`) of a VGA-compatible display controller.
pub const CLASS_DISPLAY_VGA: u32 = 0x0300;
/// Class-code value (`class >> 8`) of a non-VGA display controller.
pub const CLASS_DISPLAY_OTHER: u32 = 0x0380;

/// Complete PCIe configuration-space window exposed by ECAM.
pub const CFG_SPACE_SIZE: usize = 4096;
/// Config-space window an unprivileged reader observes. Reads past it return
/// short, so a device that locks up on undefined-register reads is only ever
/// poked by a privileged caller.
pub const CFG_SPACE_UNPRIV_SIZE: usize = 64;
/// Unprivileged window for a CardBus bridge, whose socket registers live
/// inside the first 128 bytes.
pub const CFG_SPACE_UNPRIV_CARDBUS_SIZE: usize = 128;
