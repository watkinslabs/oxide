//! x86 FADT SCI interrupt bridge.

use core::sync::atomic::{AtomicU32, Ordering};

static FIXED_EVDEV: AtomicU32 = AtomicU32::new(u32::MAX);

/// Install the platform input owner for ACPI power and sleep buttons before
/// the SCI enables any PM1 fixed source.
pub(crate) fn install_fixed_events() {
    let mut dev = input::VirtioInputDev::empty_platform_boxed(0xAC01_0001);
    dev.name[..10].copy_from_slice(b"ACPI fixed");
    dev.name_len = 10;
    dev.ev_bits[input::EV_KEY as usize / 8] |= 1 << (input::EV_KEY % 8);
    for key in [input::KEY_POWER, input::KEY_SLEEP] {
        dev.key_bits.bits[key as usize / 8] |= 1 << (key % 8);
    }
    let Some((_, evdev)) = input::install_and_publish(dev) else { return; };
    FIXED_EVDEV.store(evdev, Ordering::Release);
    let _ = firmware::acpi::events::register_fixed_event(8, power_button);
    let _ = firmware::acpi::events::register_fixed_event(9, sleep_button);
}

fn power_button() { queue_button(input::KEY_POWER); }
fn sleep_button() { queue_button(input::KEY_SLEEP); }

fn queue_button(key: u16) {
    let evdev = FIXED_EVDEV.load(Ordering::Acquire);
    if evdev == u32::MAX { return; }
    let _ = sched::live::workqueue::queue_work(emit_button, (evdev as usize) | ((key as usize) << 32));
}

fn emit_button(argument: usize) {
    let evdev = argument as u32;
    let key = (argument >> 32) as u16;
    let _ = input::push_evdev_event(evdev, input::EV_KEY, key, 1);
    let _ = input::push_evdev_event(evdev, input::EV_KEY, key, 0);
}

/// Route the FADT SCI through its MADT override and the owning I/O APIC.
/// # C: O(1)
pub fn install(interrupt: u16) -> bool {
    let Some(vector) = arch_irq::alloc_x86_vector() else { return false; };
    if arch_irq::register_irq_line_handler(u32::from(vector), irq).is_err() {
        let _ = arch_irq::free_x86_vector(vector);
        return false;
    }
    let (gsi, level, active_low) = match u8::try_from(interrupt) {
        Ok(source) if source < 16 => {
            let gsi = firmware::legacy_irq_gsi(source).unwrap_or(u32::from(source));
            let flags = firmware::legacy_irq_flags(source).unwrap_or(0);
            let (level, active_low) = firmware::acpi_sci_characteristics(flags);
            (gsi, level, active_low)
        }
        _ => (u32::from(interrupt), true, true),
    };
    // SAFETY: PCI boot mapped every MADT I/O APIC before this provider phase;
    // the line handler owns `vector` before the level source is unmasked.
    if unsafe { arch_irq::program_x86_intx_gsi(gsi, vector,
        arch_irq::lapic::local_apic_id(), level, active_low) }
        && arch_irq::irq_set_irq_wake(u32::from(vector), true).is_ok() { return true; }
    let _ = arch_irq::free_irq_line_handler(u32::from(vector));
    let _ = arch_irq::free_x86_vector(vector);
    false
}

/// Dispatch one SCI delivery through the firmware event owner.
/// # C: O(GPE register bytes) # Ctx: hard IRQ
pub(crate) fn irq(_vector: u32) -> arch_irq::IrqReport {
    let ret = if firmware::acpi::events::handle_sci_irq() { arch_irq::IrqRet::Handled }
        else { arch_irq::IrqRet::NotMine };
    arch_irq::IrqReport::hard(ret)
}
