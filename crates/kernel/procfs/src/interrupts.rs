// /proc/interrupts — per-CPU interrupt counters (Linux `show_interrupts`).
// CPU columns for each online CPU; one row per device line that has fired,
// plus the always-present LOC (local timer) and RES (resched IPI) summary
// rows. Counts come from arch_irq::irqstat (fed by the timer-IRQ dispatcher).
use alloc::vec::Vec;
use vfs::{Ino, InodeRef};

struct VecFmt<'a>(&'a mut Vec<u8>);
impl<'a> core::fmt::Write for VecFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result { self.0.extend_from_slice(s.as_bytes()); Ok(()) }
}

fn body() -> Vec<u8> {
        use core::fmt::Write;
        use arch_irq::irqstat;
        let ncpu = (cpu::smp::online_count() as usize).clamp(1, cpu::MAX_CPUS);
        let mut out: Vec<u8> = Vec::with_capacity(256 + ncpu * 16);
        // Header: left-pad for the label column, then "CPUn" per CPU.
        out.extend_from_slice(b"        ");
        for c in 0..ncpu {
            let _ = write!(VecFmt(&mut out), "CPU{c:<7}");
        }
        out.push(b'\n');
        // Active device descriptors stay visible before their first delivery.
        for idx in 0..irqstat::NLINES {
            let Some(line) = irqstat::device_line(idx) else { continue; };
            let _ = write!(VecFmt(&mut out), "{:>6}:", line.irq);
            for c in 0..ncpu {
                let _ = write!(VecFmt(&mut out), " {:>10}", irqstat::line(idx, c));
            }
            let _ = write!(VecFmt(&mut out), "   PCI-MSI   {}\n", line.action.name());
        }
        // Summary rows (always present).
        out.extend_from_slice(b"   LOC:");
        for c in 0..ncpu { let _ = write!(VecFmt(&mut out), " {:>10}", irqstat::timer(c)); }
        out.extend_from_slice(b"   Local timer interrupts\n");
        out.extend_from_slice(b"   RES:");
        for c in 0..ncpu { let _ = write!(VecFmt(&mut out), " {:>10}", irqstat::resched(c)); }
        out.extend_from_slice(b"   Rescheduling interrupts\n");
        out
}

/// `/proc/interrupts` inode (KEYSTONE struct-`Inode`). # C: O(1)
pub fn make_proc_interrupts() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::INTERRUPTS as Ino, body) }

#[cfg(test)]
mod tests {
    use alloc::format;
    use super::*;

    #[test]
    fn registered_virtio_line_is_named_before_its_first_delivery() {
        #[cfg(target_arch = "x86_64")]
        let irq = hal_x86_64::VEC_MSI_POOL_FIRST as u32 + 2;
        #[cfg(target_arch = "aarch64")]
        let irq = arch_irq::gic::LPI_BASE + 3;
        arch_irq::irqstat::unregister_msi(irq);
        assert!(arch_irq::irqstat::register_msi(irq, arch_irq::DeviceAction::VirtioPci));
        let text = alloc::string::String::from_utf8(body()).unwrap();
        assert!(text.lines().any(|line| line.contains("virtio-pci") && line.trim_start().starts_with(&format!("{irq}:"))));
        arch_irq::irqstat::unregister_msi(irq);
    }
}
