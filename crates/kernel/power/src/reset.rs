// The x86 machine-reset ladder.
//
// A reset is a sequence of attempts, not one mechanism: each rung is a write
// the platform may or may not honour, and the next rung runs when the machine
// is still executing afterwards. The order mirrors the reference's — the
// firmware-described register first, then the legacy keyboard controller, then
// the chipset reset port, and a triple fault as the terminal rung that no
// x86 implementation can decline.
//
// Two rungs the reference has are genuinely absent here rather than skipped:
// there is no EFI runtime-services call (this kernel exits boot services and
// keeps no runtime pointer) and no real-mode BIOS entry (the boot contract
// forbids returning to real mode). Both are recorded in the known-issues
// ledger rather than silently dropped.

// Module manifest:
// - this file: the ladder's order and port encodings — no target gate, host-tested.
// - `x86`:     the privileged writes each rung performs on the kernel target.

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub mod x86;

/// A rung of the ladder, in the order it is attempted.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResetRung {
    /// The reset register the FADT described.
    Firmware,
    /// Pulse the legacy keyboard controller's reset line.
    KeyboardController,
    /// The chipset reset-control port.
    ResetControl,
    /// Triple fault. Always last; always effective.
    TripleFault,
}

/// Legacy keyboard-controller command port and its CPU-reset pulse.
pub const KBD_COMMAND_PORT: u16 = 0x64;
pub const KBD_STATUS_INPUT_FULL: u8 = 0x02;
pub const KBD_PULSE_RESET: u8 = 0xfe;
/// Number of pulses the reference sends before giving up on the controller.
pub const KBD_PULSE_ATTEMPTS: u32 = 10;

/// Chipset reset-control port. Bit 1 requests a reset; the code byte selects
/// a warm (`0x06`) or cold (`0x0e`) one, and is masked out of the read-back
/// before the request bit is set so a stale code cannot trigger early.
pub const RESET_CONTROL_PORT: u16 = 0x0cf9;
pub const RESET_CONTROL_REQUEST: u8 = 0x02;
pub const RESET_CONTROL_COLD: u8 = 0x0e;

/// Microseconds the reference waits between the paired port writes, and
/// after the firmware register, so a platform that resets slowly is not
/// raced by the next rung.
pub const RESET_SETTLE_US: u64 = 50;
pub const FIRMWARE_SETTLE_US: u64 = 15_000;

/// The ladder, in attempt order. `firmware_available` is whether the FADT
/// authorised a reset register; when it did not, that rung is not attempted
/// at all rather than attempted as a no-op — a rung that cannot act must not
/// consume the settle delay that follows it.
///
/// # C: O(1)
pub fn ladder(firmware_available: bool) -> &'static [ResetRung] {
    const WITH_FIRMWARE: [ResetRung; 4] = [
        ResetRung::Firmware,
        ResetRung::KeyboardController,
        ResetRung::ResetControl,
        ResetRung::TripleFault,
    ];
    const WITHOUT_FIRMWARE: [ResetRung; 3] = [
        ResetRung::KeyboardController,
        ResetRung::ResetControl,
        ResetRung::TripleFault,
    ];
    if firmware_available { &WITH_FIRMWARE } else { &WITHOUT_FIRMWARE }
}

/// The two bytes written to the reset-control port, in order: the request,
/// then the reset code. `current` is the port's read-back value, whose reset
/// code bits are cleared first so a stale code cannot fire on the first write.
///
/// # C: O(1)
pub fn reset_control_writes(current: u8) -> (u8, u8) {
    let base = current & !RESET_CONTROL_COLD;
    (base | RESET_CONTROL_REQUEST, base | RESET_CONTROL_COLD)
}

#[cfg(test)]
mod tests;
