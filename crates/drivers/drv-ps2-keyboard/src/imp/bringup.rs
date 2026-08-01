// Controller + keyboard bring-up, IRQ-bit policy, and the teardown/quiesce
// sequences that hand the i8042 back.

use core::sync::atomic::Ordering;

use super::ports::*;
use super::regs::*;
use super::state::*;

/// Inner bring-up. Returns true iff the keyboard answered the self-test
/// + reset handshake.
///
/// Sequence (Linux `i8042`/`atkbd` order, condensed):
///   1. disable both ports (stop traffic during config)
///   2. flush the stale output buffer
///   3. read config byte; clear port-1 IRQ + set scancode translation
///      (controller translates set-2 → set-1 for us), write it back
///   4. controller self-test (0xAA → 0x55)
///   5. enable keyboard port (0xAE) + port-1 interface test (0xAB → 0)
///   6. keyboard reset (0xFF → 0xFA ACK, 0xAA BAT-pass)
///   7. select scancode set 1 (0xF0 0x01) + enable scanning (0xF4)
/// A non-responding controller (no QEMU PS/2, real serial-only box)
/// leaves PRESENT=false and the platform device unbound.
///
/// # SAFETY: post-LAPIC boot, single-CPU, IRQs masked. Performs CPL=0
/// port I/O to the i8042 controller; no other path touches 0x60/0x64.
/// # C: O(spin) bounded by the controller's response latency.
pub(super) unsafe fn bringup() -> bool {
    // SAFETY: bounded CPL=0 port I/O to the i8042 in the documented order; single-CPU boot, no concurrent accessor.
    unsafe {
        write_cmd(CMD_DISABLE_PORT1);
        write_cmd(CMD_DISABLE_PORT2);
        flush_output();

        // Config byte: keep port-1 IRQ masked while command handshakes run;
        // enable translation so the keyboard's set-2 stream arrives as set-1.
        write_cmd(CMD_READ_CONFIG);
        let mut cfg = match read_blocking() {
            Some(c) => c,
            None => return false,
        };
        cfg &= !CFG_PORT1_IRQ;
        cfg |= CFG_PORT1_TRANSLATE;
        write_cmd(CMD_WRITE_CONFIG);
        write_data(cfg);

        // Controller self-test.
        write_cmd(CMD_SELF_TEST);
        if read_blocking() != Some(SELF_TEST_PASS) {
            return false;
        }
        // Re-write the config byte: the self-test can reset it.
        write_cmd(CMD_WRITE_CONFIG);
        write_data(cfg);

        // Enable keyboard port + interface test.
        write_cmd(CMD_ENABLE_PORT1);
        write_cmd(CMD_TEST_PORT1);
        // A 0x00 = pass; tolerate a missing reply on lenient emulators.
        let _ = read_blocking();
        flush_output();

        // Keyboard reset + BAT (basic-assurance-test) self-check.
        if !kbd_cmd(KBD_RESET) {
            return false;
        }
        // RESET replies 0xFA (ACK, consumed in kbd_cmd) then 0xAA (BAT
        // OK). Some emulators ACK only — accept either next byte.
        match read_blocking() {
            Some(KBD_BAT_OK) | Some(KBD_ACK) | None => {}
            Some(_) => {}
        }

        // Select scancode set 1 explicitly (translation already gives us
        // set-1 codes; this pins it for keyboards that default elsewhere).
        let _ = kbd_cmd(KBD_SET_SCANCODE);
        let _ = kbd_cmd(KBD_SCANCODE_SET_1);

        // Enable scanning so keypresses start streaming.
        let _ = kbd_cmd(KBD_ENABLE_SCAN);
        flush_output();
        true
    }
}

/// Enable or disable the controller's port-1 IRQ bit while preserving the
/// remaining command-byte policy. # C: O(spin)
pub(super) unsafe fn set_controller_irq(enable: bool) -> bool {
    // SAFETY: bounded CPL=0 i8042 command-byte read/modify/write.
    unsafe {
        write_cmd(CMD_READ_CONFIG);
        let mut cfg = match read_blocking() {
            Some(c) => c,
            None => return false,
        };
        if enable {
            cfg |= CFG_PORT1_IRQ;
        } else {
            cfg &= !CFG_PORT1_IRQ;
        }
        cfg |= CFG_PORT1_TRANSLATE;
        write_cmd(CMD_WRITE_CONFIG);
        write_data(cfg);
        true
    }
}

/// Mask the owned I/O APIC pin, if one is still published. Idempotent: the
/// swap hands the pin to exactly one caller, so a concurrent teardown path
/// cannot mask a pin this driver no longer owns.
/// # C: O(1)
pub(super) fn take_and_mask_pin() {
    let pin = IRQ_PIN.swap(NO_IRQ_PIN, Ordering::AcqRel);
    if pin != NO_IRQ_PIN {
        // SAFETY: the I/O APIC was mapped and `set_base_va` published before
        // IRQ_PIN was stored, so a non-sentinel pin proves the register window
        // is live; the swap makes this caller the sole owner of that pin.
        unsafe { hal_x86_64::ioapic::mask(pin as u32); }
    }
}

/// Release the owned x86 vector, if one is still published. Idempotent for the
/// same reason as `take_and_mask_pin`. # C: O(1)
pub(super) fn take_and_free_vector() {
    let vec = IRQ_VEC.swap(NO_IRQ_VEC, Ordering::AcqRel);
    if vec != NO_IRQ_VEC {
        let _ = arch_irq::free_x86_vector(vec as u8);
    }
}

/// Stop the keyboard and disable the controller port owned by this driver.
/// # SAFETY: CPL=0 i8042 port I/O; driver-core remove owns teardown.
/// # C: O(spin) bounded by controller response latency.
pub(super) unsafe fn bringdown() {
    IRQ_ENABLED.store(false, Ordering::Release);
    // SAFETY: bounded CPL=0 port I/O to the i8042; no concurrent accessor.
    unsafe {
        let _ = set_controller_irq(false);
        let _ = kbd_cmd(KBD_DISABLE_SCAN);
        write_cmd(CMD_DISABLE_PORT1);
        flush_output();
    }
    take_and_mask_pin();
    take_and_free_vector();
    PRESENT.store(false, Ordering::Release);
}

/// Stop keyboard scan/IRQ delivery for terminal system shutdown while
/// keeping the bound platform device state intact.
/// # SAFETY: CPL=0 i8042 port I/O; driver-core shutdown owns quiesce.
/// # C: O(spin) bounded by controller response latency.
pub(super) unsafe fn shutdown_hw() {
    IRQ_ENABLED.store(false, Ordering::Release);
    // SAFETY: bounded CPL=0 port I/O to the i8042; no concurrent accessor.
    unsafe {
        let _ = set_controller_irq(false);
        let _ = kbd_cmd(KBD_DISABLE_SCAN);
        flush_output();
    }
    // Shutdown keeps the device bound, so the pin stays owned and published —
    // mask in place rather than surrendering it like `bringdown` does.
    let pin = IRQ_PIN.load(Ordering::Acquire);
    if pin != NO_IRQ_PIN {
        // SAFETY: a non-sentinel IRQ_PIN is only ever published after the I/O
        // APIC window was mapped and its base VA installed, so the register
        // access below targets a live mapping.
        unsafe { hal_x86_64::ioapic::mask(pin as u32); }
    }
}
