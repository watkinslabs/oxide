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

/// Class-code value (`class >> 8`) of an undefined-class VGA device.
pub const CLASS_NOT_DEFINED_VGA: u32 = 0x0001;
/// Class-code value (`class >> 8`) of a VGA-compatible display controller.
pub const CLASS_DISPLAY_VGA: u32 = 0x0300;
/// Class-code value (`class >> 8`) of a non-VGA display controller.
pub const CLASS_DISPLAY_OTHER: u32 = 0x0380;

/// Conventional config-space size — every byte a `ConfigSpaceReader`
/// addresses. The extended 4 KiB PCIe window is not addressable through the
/// 8-bit register offset the accessor takes.
pub const CFG_SPACE_SIZE: usize = 256;
/// Config-space window an unprivileged reader observes. Reads past it return
/// short, so a device that locks up on undefined-register reads is only ever
/// poked by a privileged caller.
pub const CFG_SPACE_UNPRIV_SIZE: usize = 64;
/// Unprivileged window for a CardBus bridge, whose socket registers live
/// inside the first 128 bytes.
pub const CFG_SPACE_UNPRIV_CARDBUS_SIZE: usize = 128;
