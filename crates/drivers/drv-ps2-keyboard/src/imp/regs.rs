// i8042 hardware contract: port numbers, status/config bits, and the
// controller + keyboard-device command bytes.

/// i8042 data port (read scancodes / write keyboard commands).
pub(super) const DATA: u16 = 0x60;
/// i8042 status (read) / command (write) port.
pub(super) const CMD: u16 = 0x64;

// Status register bits.
pub(super) const STS_OUTPUT_FULL: u8 = 1 << 0; // bit0: output buffer has a byte
pub(super) const STS_INPUT_FULL: u8 = 1 << 1; // bit1: input buffer busy

// Controller commands (written to 0x64).
pub(super) const CMD_READ_CONFIG: u8 = 0x20;
pub(super) const CMD_WRITE_CONFIG: u8 = 0x60;
pub(super) const CMD_DISABLE_PORT2: u8 = 0xA7;
pub(super) const CMD_DISABLE_PORT1: u8 = 0xAD;
pub(super) const CMD_ENABLE_PORT1: u8 = 0xAE;
pub(super) const CMD_SELF_TEST: u8 = 0xAA; // → 0x55 on pass
pub(super) const SELF_TEST_PASS: u8 = 0x55;
pub(super) const CMD_TEST_PORT1: u8 = 0xAB; // → 0x00 on pass

// Keyboard (device) commands (written to 0x60).
pub(super) const KBD_RESET: u8 = 0xFF; // → 0xFA ACK then 0xAA BAT-pass
pub(super) const KBD_SET_SCANCODE: u8 = 0xF0; // followed by set number
pub(super) const KBD_SCANCODE_SET_1: u8 = 0x01;
pub(super) const KBD_ENABLE_SCAN: u8 = 0xF4;
pub(super) const KBD_DISABLE_SCAN: u8 = 0xF5;
pub(super) const KBD_ACK: u8 = 0xFA;
pub(super) const KBD_BAT_OK: u8 = 0xAA;

// Config byte bits (controller "command byte").
pub(super) const CFG_PORT1_IRQ: u8 = 1 << 0; // first-port interrupt (IRQ1) enable
pub(super) const CFG_PORT1_TRANSLATE: u8 = 1 << 6; // scancode-set-1 translation

/// Spin budget for "input buffer clear" before a controller/device write.
pub(super) const WAIT_WRITABLE_SPINS: u32 = 100_000;
/// Spin budget for a single bounded output-buffer read.
pub(super) const READ_BLOCKING_SPINS: u32 = 200_000;
/// Bytes discarded per stale-output flush.
pub(super) const FLUSH_MAX_BYTES: u32 = 64;
/// Scancode bytes drained per interrupt, so one IRQ cannot starve the CPU.
pub(super) const DRAIN_MAX_BYTES: u32 = 64;

/// Legacy ISA IRQ line owned by the keyboard.
pub(super) const KBD_ISA_IRQ: u8 = 1;
/// Fallback GSI when the MADT declares no override for IRQ1 (identity-mapped).
pub(super) const KBD_ISA_IRQ_GSI: u32 = 1;
/// ACPI MADT interrupt-override polarity/trigger field width and the
/// active-low / level-triggered encodings within it.
pub(super) const MADT_FLAG_MASK: u32 = 0x3;
pub(super) const MADT_POLARITY_ACTIVE_LOW: u32 = 3;
pub(super) const MADT_TRIGGER_SHIFT: u32 = 2;
pub(super) const MADT_TRIGGER_LEVEL: u32 = 3;

/// Low 32 bits of a physical address, used to place the I/O APIC inside the
/// kernel device window.
pub(super) const DEVICE_WINDOW_PA_MASK: u64 = 0xffff_ffff;
