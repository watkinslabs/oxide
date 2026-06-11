#![no_std]
//! Real i8042 PS/2 keyboard driver (drivers-plan D3.4). x86_64 ONLY —
//! on aarch64 every entry point is an empty no-op so the workspace builds
//! and the arm boot is untouched (there is no i8042 on `qemu virt`).
//!
//! Pipeline: i8042 controller bring-up + keyboard reset/identify, then a
//! Scancode-Set-1 decoder that turns make/break codes (incl. 0xE0-prefixed
//! extended keys) into `(linux_keycode, pressed)` and feeds each through
//! the ONE shared input pipeline `drv_virtio_input::drain::handle_key_event`
//! — the same modifier / Ctrl-Alt-F<n> VT-switch / Shift-PgUp scrollback /
//! keymap→byte logic the virtio-input keyboard uses. No duplicate key logic.
//!
//! Input delivery is the timer-tick poll (`init` registers no IRQ1 line):
//! `poll()` is called from kmain's `tick_poll_combined`, draining the
//! controller output buffer while status bit0 (output-buffer-full) is set.
//! This mirrors the virtio-input + serial tick-poll backstop and avoids a
//! dedicated IRQ1 redirection-entry (the IOAPIC path exists but the poll is
//! the simple, race-free path for a boot-time static device).

// The real device + the bridge into the kernel input pipeline only exist
// on the kernel x86 target; host builds (hosted `cargo test` for the pure
// scancode decoder) and aarch64 use the no-op shell. Keeping the gate on
// `oxide-kernel` (not just `x86_64`) lets the scancode unit tests run on
// the dev host without dragging in the `oxide-kernel`-gated kernel crates.
// ---------------------------------------------------------- no-op shell
// aarch64 (no i8042), and host x86 test builds (no kernel crates). Every
// entry point is an empty fn so the workspace member always builds.
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
mod imp {
    /// No-op (no i8042 on this target). # C: O(1)
    pub fn init() {}
    /// No-op (no i8042 on this target). # C: O(1)
    /// # SAFETY: no hardware touched on this target; nothing to uphold.
    pub unsafe fn poll() {}
    /// Always false off the x86 kernel target. # C: O(1)
    pub fn present() -> bool { false }
}

// The pure Scancode-Set-1 decoder is host-testable (x86_64 host or kernel).
#[cfg(target_arch = "x86_64")]
mod scancode;

// ----------------------------------------------------------- real device
// `debug_boot!` is `#[macro_export]`ed by kmacros (gated on its
// `debug-boot` feature); pull it into crate scope for the real imp.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[macro_use]
extern crate kmacros;
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
extern crate alloc;

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
mod imp {
    use core::sync::atomic::{AtomicBool, Ordering};

    use crate::scancode::decode_byte;

    /// i8042 data port (read scancodes / write keyboard commands).
    const DATA: u16 = 0x60;
    /// i8042 status (read) / command (write) port.
    const CMD: u16 = 0x64;

    // Status register bits.
    const STS_OUTPUT_FULL: u8 = 1 << 0; // bit0: output buffer has a byte
    const STS_INPUT_FULL: u8 = 1 << 1; // bit1: input buffer busy

    // Controller commands (written to 0x64).
    const CMD_READ_CONFIG: u8 = 0x20;
    const CMD_WRITE_CONFIG: u8 = 0x60;
    const CMD_DISABLE_PORT2: u8 = 0xA7;
    const CMD_DISABLE_PORT1: u8 = 0xAD;
    const CMD_ENABLE_PORT1: u8 = 0xAE;
    const CMD_SELF_TEST: u8 = 0xAA; // → 0x55 on pass
    const SELF_TEST_PASS: u8 = 0x55;
    const CMD_TEST_PORT1: u8 = 0xAB; // → 0x00 on pass

    // Keyboard (device) commands (written to 0x60).
    const KBD_RESET: u8 = 0xFF; // → 0xFA ACK then 0xAA BAT-pass
    const KBD_SET_SCANCODE: u8 = 0xF0; // followed by set number
    const KBD_ENABLE_SCAN: u8 = 0xF4;
    const KBD_ACK: u8 = 0xFA;
    const KBD_BAT_OK: u8 = 0xAA;

    // Config byte bits (controller "command byte").
    const CFG_PORT1_IRQ: u8 = 1 << 0; // first-port interrupt (IRQ1) enable
    const CFG_PORT1_TRANSLATE: u8 = 1 << 6; // scancode-set-1 translation

    static PRESENT: AtomicBool = AtomicBool::new(false);

    /// # SAFETY: privileged port I/O legal at CPL=0; no memory effect.
    #[inline]
    unsafe fn inb(port: u16) -> u8 {
        let v: u8;
        // SAFETY: `in` at CPL=0 reads one byte from an x86 I/O port; the i8042 ports have no DMA/memory side effect on the caller's state.
        unsafe { core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags)); }
        v
    }
    /// # SAFETY: privileged port I/O legal at CPL=0; no memory effect.
    #[inline]
    unsafe fn outb(port: u16, v: u8) {
        // SAFETY: `out` at CPL=0 writes one byte to an x86 I/O port; the i8042 ports have no DMA/memory side effect on the caller's state.
        unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)); }
    }

    /// Spin until the input buffer is clear, so a controller/device write
    /// won't be dropped. Bounded so a dead controller can't wedge boot.
    /// # SAFETY: status-port read at CPL=0; single-CPU boot context.
    unsafe fn wait_writable() {
        let mut n = 0u32;
        // SAFETY: reading the i8042 status register (0x64) at CPL=0 has no side effect.
        while n < 100_000 && unsafe { inb(CMD) } & STS_INPUT_FULL != 0 {
            n += 1;
        }
    }

    /// Read one byte from the output buffer once it's full, bounded.
    /// Returns None if no byte arrives in the spin budget.
    /// # SAFETY: status + data port reads at CPL=0; single-CPU boot context.
    unsafe fn read_blocking() -> Option<u8> {
        let mut n = 0u32;
        loop {
            // SAFETY: reading the i8042 status register (0x64) at CPL=0 has no side effect.
            if unsafe { inb(CMD) } & STS_OUTPUT_FULL != 0 {
                // SAFETY: STS_OUTPUT_FULL set ⇒ the data port (0x60) holds a byte to read at CPL=0.
                return Some(unsafe { inb(DATA) });
            }
            n += 1;
            if n >= 200_000 {
                return None;
            }
        }
    }

    /// Write a controller command to port 0x64. # SAFETY: as `wait_writable`.
    unsafe fn write_cmd(c: u8) {
        // SAFETY: drain-then-write — wait_writable + the command write are CPL=0 port I/O to the i8042.
        unsafe {
            wait_writable();
            outb(CMD, c);
        }
    }

    /// Write a byte to the keyboard device (data port 0x60).
    /// # SAFETY: as `wait_writable`.
    unsafe fn write_data(b: u8) {
        // SAFETY: drain-then-write — wait_writable + the data write are CPL=0 port I/O to the i8042.
        unsafe {
            wait_writable();
            outb(DATA, b);
        }
    }

    /// Drain and discard any pending output bytes (flush stale state left
    /// by firmware before we take ownership). Bounded.
    /// # SAFETY: status + data reads at CPL=0; single-CPU boot context.
    unsafe fn flush_output() {
        let mut n = 0u32;
        // SAFETY: reading status (0x64) + data (0x60) at CPL=0 to drain stale bytes has no side effect beyond clearing the buffer.
        while n < 64 && unsafe { inb(CMD) } & STS_OUTPUT_FULL != 0 {
            // SAFETY: output-buffer-full ⇒ a byte is present at the data port; discard it.
            let _ = unsafe { inb(DATA) };
            n += 1;
        }
    }

    /// Bring up the i8042 controller + reset/identify the keyboard, then
    /// register the platform device in the D1a driver model.
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
    /// On success logs "[INFO] i8042 keyboard detected" and marks present.
    /// A non-responding controller (no QEMU PS/2, real serial-only box)
    /// leaves PRESENT=false and the poll becomes a no-op — harmless.
    ///
    /// # SAFETY: post-LAPIC boot, single-CPU, IRQs masked. Performs CPL=0
    /// port I/O to the i8042 controller; no other path touches 0x60/0x64.
    /// # C: O(spin) bounded by the controller's response latency.
    pub unsafe fn init() {
        // SAFETY: all of the bring-up is CPL=0 port I/O to the i8042 controller, single-CPU at boot with no concurrent accessor; each helper bounds its own spin so a dead controller cannot wedge boot.
        let ok = unsafe { bringup() };
        PRESENT.store(ok, Ordering::Release);
        if ok {
            debug_boot! { klog::write_raw(b"[INFO]  i8042 keyboard detected\n"); }
            register_model();
        }
    }

    /// Inner bring-up. Returns true iff the keyboard answered the self-test
    /// + reset handshake. # SAFETY: as `init`.
    unsafe fn bringup() -> bool {
        // SAFETY: bounded CPL=0 port I/O to the i8042 in the documented order; single-CPU boot, no concurrent accessor.
        unsafe {
            write_cmd(CMD_DISABLE_PORT1);
            write_cmd(CMD_DISABLE_PORT2);
            flush_output();

            // Config byte: disable port-1 IRQ (we poll), enable translation
            // so the keyboard's set-2 stream arrives as set-1 codes.
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
            let _ = kbd_cmd(0x01);

            // Enable scanning so keypresses start streaming.
            let _ = kbd_cmd(KBD_ENABLE_SCAN);
            flush_output();
            true
        }
    }

    /// Send a keyboard-device command and wait for the 0xFA ACK.
    /// Returns true on ACK. # SAFETY: as `init`.
    unsafe fn kbd_cmd(b: u8) -> bool {
        // SAFETY: CPL=0 data-port write then a bounded ACK read; single-CPU boot.
        unsafe {
            write_data(b);
            matches!(read_blocking(), Some(KBD_ACK))
        }
    }

    /// True once the i8042 keyboard was detected by `init`. # C: O(1)
    pub fn present() -> bool { PRESENT.load(Ordering::Acquire) }

    /// Timer-tick poll: drain every pending scancode from the output buffer
    /// and route decoded keys into the shared input pipeline. Bounded per
    /// tick so a key-repeat storm can't starve the tick.
    /// # SAFETY: timer-ISR / tick context, CPL=0 port I/O; BSP owns the i8042.
    /// # C: O(bytes pending), ≤ 64 per tick.
    pub unsafe fn poll() {
        if !PRESENT.load(Ordering::Acquire) {
            return;
        }
        let mut n = 0u32;
        loop {
            // SAFETY: reading the i8042 status register (0x64) at CPL=0 has no side effect.
            if unsafe { inb(CMD) } & STS_OUTPUT_FULL == 0 {
                break;
            }
            // SAFETY: output-buffer-full ⇒ a scancode byte is present at the data port (0x60).
            let byte = unsafe { inb(DATA) };
            if let Some((keycode, pressed)) = decode_byte(byte) {
                drv_virtio_input::drain::handle_key_event(keycode, pressed);
            }
            n += 1;
            if n >= 64 {
                break;
            }
        }
    }

    // drivers-plan D1a: register the i8042 keyboard as a platform-bus
    // device + a real model Driver, mirroring the 8250 serial registration.
    struct Ps2KbdDriver;
    impl drv::Driver for Ps2KbdDriver {
        fn name(&self) -> &'static str { "i8042-kbd" }
        fn matches(&self, dev: &drv::Device) -> bool {
            dev.bus == "platform" && dev.addr == "i8042"
        }
    }
    static PS2_DRV: Ps2KbdDriver = Ps2KbdDriver;

    fn register_model() {
        let dev = drv::register_device(alloc::sync::Arc::new(drv::Device::new(
            "platform",
            alloc::string::String::from("i8042"),
            0,
            0,
            0,
        )));
        drv::register_driver(&PS2_DRV);
        drv::bind(&dev, drv::Driver::name(&PS2_DRV));
    }
}

pub use imp::{init, poll, present};
