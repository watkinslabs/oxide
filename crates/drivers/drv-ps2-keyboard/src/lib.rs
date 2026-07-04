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
//! Input delivery is IRQ1-owned by the i8042 driver. `probe()` programs the
//! I/O APIC redirection entry and enables the controller IRQ bit only after the
//! handler is installed; `remove()` disables scanning/IRQ delivery, masks the
//! line, frees the vector, and clears driver state.

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
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
    const KBD_DISABLE_SCAN: u8 = 0xF5;
    const KBD_ACK: u8 = 0xFA;
    const KBD_BAT_OK: u8 = 0xAA;

    // Config byte bits (controller "command byte").
    const CFG_PORT1_IRQ: u8 = 1 << 0; // first-port interrupt (IRQ1) enable
    const CFG_PORT1_TRANSLATE: u8 = 1 << 6; // scancode-set-1 translation

    static PRESENT: AtomicBool = AtomicBool::new(false);
    static IRQ_ENABLED: AtomicBool = AtomicBool::new(false);
    static BSP_APIC_ID: AtomicU64 = AtomicU64::new(0);
    static DEVICE_WINDOW_BASE: AtomicU64 = AtomicU64::new(0);
    static IRQ_VEC: AtomicU64 = AtomicU64::new(0);
    static IRQ_PIN: AtomicU64 = AtomicU64::new(u64::MAX);

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
    /// leaves PRESENT=false and the poll becomes a no-op — harmless.
    ///
    /// # SAFETY: post-LAPIC boot, single-CPU, IRQs masked. Performs CPL=0
    /// port I/O to the i8042 controller; no other path touches 0x60/0x64.
    /// # C: O(spin) bounded by the controller's response latency.
    unsafe fn bringup() -> bool {
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
            let _ = kbd_cmd(0x01);

            // Enable scanning so keypresses start streaming.
            let _ = kbd_cmd(KBD_ENABLE_SCAN);
            flush_output();
            true
        }
    }

    /// Enable or disable the controller's port-1 IRQ bit while preserving the
    /// remaining command-byte policy. # C: O(spin)
    unsafe fn set_controller_irq(enable: bool) -> bool {
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

    /// Drain pending scancode bytes from IRQ context into the shared input
    /// pipeline. Bounded so one IRQ cannot starve the CPU.
    /// # SAFETY: IRQ context with the i8042 line owned by this driver.
    /// # C: O(bytes pending), <= 64 per interrupt.
    unsafe fn drain_irq() {
        if !present() || !irq_enabled() {
            return;
        }
        let mut n = 0u32;
        loop {
            // SAFETY: reading the i8042 status register (0x64) at CPL=0 has no side effect.
            if unsafe { inb(CMD) } & STS_OUTPUT_FULL == 0 {
                break;
            }
            // SAFETY: output-buffer-full => a scancode byte is present at the data port (0x60).
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

    fn irq1_handler() {
        // SAFETY: installed only after probe owns IRQ1 and maps the I/O APIC.
        unsafe { drain_irq(); }
    }

    /// Program IRQ1 through the I/O APIC and enable the controller IRQ bit.
    /// # SAFETY: called from driver probe after i8042 bring-up, IRQs masked.
    /// # C: O(1)
    unsafe fn install_irq() -> bool {
        let ioapic_pa = firmware::ioapic_pa();
        if ioapic_pa == 0 {
            return false;
        }
        let mut ioapic_va = hal_x86_64::ioapic::base_va();
        if ioapic_va == 0 {
            let dev_window_base = DEVICE_WINDOW_BASE.load(Ordering::Acquire);
            if dev_window_base == 0 {
                return false;
            }
            ioapic_va = dev_window_base | (ioapic_pa & 0xffff_ffff);
            let pf = hal::PageFlags::READ
                | hal::PageFlags::WRITE
                | hal::PageFlags::NO_CACHE
                | hal::PageFlags::WRITE_THROUGH;
            // SAFETY: device-window VA disjoint from RAM; ioapic_pa is the MADT base; single-CPU probe.
            unsafe {
                <hal_x86_64::mmu_ops::X86Mmu as hal::MmuOps>::map(
                    hal::Va(ioapic_va),
                    hal::Pa(ioapic_pa),
                    pf,
                    hal::PageSize::P4K,
                );
            }
            hal_x86_64::ioapic::set_base_va(ioapic_va);
        }

        let vec = match arch_irq::alloc_x86_vector() {
            Some(v) => v,
            None => return false,
        };
        if arch_irq::register_msi_handler(vec, irq1_handler).is_err() {
            let _ = arch_irq::free_x86_vector(vec);
            return false;
        }
        let gsi = firmware::legacy_irq_gsi(1).unwrap_or(1);
        let base = firmware::ioapic_gsi_base();
        if gsi < base {
            let _ = arch_irq::free_x86_vector(vec);
            return false;
        }
        let pin = gsi - base;
        let flags = firmware::legacy_irq_flags(1).unwrap_or(0);
        let active_low = (flags & 0x3) == 3;
        let level = ((flags >> 2) & 0x3) == 3;
        let bsp_apic = BSP_APIC_ID.load(Ordering::Acquire) as u8;
        // SAFETY: I/O APIC mapped; vector has a registered handler; probe owns IRQ1 setup.
        unsafe { hal_x86_64::ioapic::program_redirect(pin, vec, bsp_apic, level, active_low); }
        IRQ_VEC.store(vec as u64, Ordering::Release);
        IRQ_PIN.store(pin as u64, Ordering::Release);
        // SAFETY: the IRQ handler/vector/redirection entry are installed.
        if !unsafe { set_controller_irq(true) } {
            IRQ_ENABLED.store(false, Ordering::Release);
            let pin = IRQ_PIN.swap(u64::MAX, Ordering::AcqRel);
            if pin != u64::MAX {
                // SAFETY: I/O APIC was mapped before IRQ_PIN was published.
                unsafe { hal_x86_64::ioapic::mask(pin as u32); }
            }
            let vec = IRQ_VEC.swap(0, Ordering::AcqRel);
            if vec != 0 {
                let _ = arch_irq::free_x86_vector(vec as u8);
            }
            return false;
        }
        IRQ_ENABLED.store(true, Ordering::Release);
        // Drain any byte that arrived between scan enable and IRQ enable.
        unsafe { drain_irq(); }
        true
    }

    /// Send a keyboard-device command and wait for the 0xFA ACK.
    /// Returns true on ACK. # SAFETY: as `Ps2KbdDriver::probe`.
    unsafe fn kbd_cmd(b: u8) -> bool {
        // SAFETY: CPL=0 data-port write then a bounded ACK read; single-CPU boot.
        unsafe {
            write_data(b);
            matches!(read_blocking(), Some(KBD_ACK))
        }
    }

    /// Stop the keyboard and disable the controller port owned by this driver.
    /// # SAFETY: CPL=0 i8042 port I/O; driver-core remove owns teardown.
    /// # C: O(spin) bounded by controller response latency.
    unsafe fn bringdown() {
        IRQ_ENABLED.store(false, Ordering::Release);
        // SAFETY: bounded CPL=0 port I/O to the i8042; no concurrent accessor.
        unsafe {
            let _ = set_controller_irq(false);
            let _ = kbd_cmd(KBD_DISABLE_SCAN);
            write_cmd(CMD_DISABLE_PORT1);
            flush_output();
        }
        let pin = IRQ_PIN.swap(u64::MAX, Ordering::AcqRel);
        if pin != u64::MAX {
            // SAFETY: I/O APIC mapping was installed before IRQ_PIN was published.
            unsafe { hal_x86_64::ioapic::mask(pin as u32); }
        }
        let vec = IRQ_VEC.swap(0, Ordering::AcqRel);
        if vec != 0 {
            let _ = arch_irq::free_x86_vector(vec as u8);
        }
        PRESENT.store(false, Ordering::Release);
    }

    /// Stop keyboard scan/IRQ delivery for terminal system shutdown while
    /// keeping the bound platform device state intact.
    /// # SAFETY: CPL=0 i8042 port I/O; driver-core shutdown owns quiesce.
    /// # C: O(spin) bounded by controller response latency.
    unsafe fn shutdown_hw() {
        IRQ_ENABLED.store(false, Ordering::Release);
        // SAFETY: bounded CPL=0 port I/O to the i8042; no concurrent accessor.
        unsafe {
            let _ = set_controller_irq(false);
            let _ = kbd_cmd(KBD_DISABLE_SCAN);
            flush_output();
        }
        let pin = IRQ_PIN.load(Ordering::Acquire);
        if pin != u64::MAX {
            // SAFETY: I/O APIC mapping was installed before IRQ_PIN was published.
            unsafe { hal_x86_64::ioapic::mask(pin as u32); }
        }
    }

    /// True once the i8042 keyboard was detected by `Ps2KbdDriver::probe`. # C: O(1)
    pub fn present() -> bool { PRESENT.load(Ordering::Acquire) }

    /// True while IRQ1 delivery may drain scancodes into the input pipeline.
    /// Shutdown/remove clear this before masking hardware so late vectors see a
    /// quiesced driver.
    /// # C: O(1)
    pub fn irq_enabled() -> bool { IRQ_ENABLED.load(Ordering::Acquire) }

    // Register the i8042 keyboard as a platform-bus driver. Binding runs the
    // hardware bring-up; failed detection leaves platform/i8042 unbound.
    struct Ps2KbdDriver;
    impl drv::Driver for Ps2KbdDriver {
        fn bus(&self) -> &'static str { "platform" }
        fn name(&self) -> &'static str { "i8042-kbd" }
        fn matches(&self, dev: &drv::Device) -> bool {
            dev.bus == "platform" && dev.addr == "i8042"
        }
        fn probe(&self, _dev: &Arc<drv::Device>) -> drv::KResult<()> {
            if present() {
                return Err(drv::Error::Busy);
            }
            // SAFETY: driver-core bind runs in the same boot window that
            // previously called init directly: single-CPU, IRQs masked, no
            // concurrent accessor for ports 0x60/0x64.
            if unsafe { bringup() } {
                PRESENT.store(true, Ordering::Release);
                if !unsafe { install_irq() } {
                    unsafe { bringdown(); }
                    return Err(drv::Error::ProbeFailed);
                }
                debug_boot! { klog::write_raw(b"[INFO]  i8042 keyboard detected\n"); }
                Ok(())
            } else {
                Err(drv::Error::ProbeFailed)
            }
        }

        fn remove(&self, _dev: &drv::Device) {
            if !present() {
                return;
            }
            // SAFETY: driver-core remove owns the bound platform/i8042 device.
            unsafe { bringdown(); }
        }

        fn shutdown(&self, _dev: &drv::Device) {
            if !present() {
                return;
            }
            // SAFETY: driver-core shutdown owns terminal platform-device quiesce.
            unsafe { shutdown_hw(); }
        }
    }
    static PS2_DRV: Ps2KbdDriver = Ps2KbdDriver;

    /// Driver-model handle for kmain platform-device registration. # C: O(1)
    pub fn driver() -> &'static dyn drv::Driver { &PS2_DRV }

    /// Boot-time platform data used by the driver's IRQ setup.
    /// # C: O(1)
    pub fn configure_probe(bsp_apic_id: u8, dev_window_base: u64) {
        BSP_APIC_ID.store(bsp_apic_id as u64, Ordering::Release);
        DEVICE_WINDOW_BASE.store(dev_window_base, Ordering::Release);
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub use imp::{configure_probe, driver};
pub use imp::present;
