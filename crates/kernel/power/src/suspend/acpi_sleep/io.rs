// Performing what `plan.rs` decided, and publishing the resume address.
//
// Everything here is I/O; every decision it could have made lives in
// `plan.rs` or in the firmware crate's FACS decode. The executor is a loop
// over the plan in issue order — it must never reorder, coalesce or skip,
// because the ordering is the whole point of the split write.

use firmware::acpi::Gas;
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
use firmware::acpi::{SPACE_SYSTEM_IO, SPACE_SYSTEM_MEMORY};

use super::plan::SleepPlan;
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
use super::plan::PM1_WAKE_STATUS;

/// Page mask for turning a register address into the page that carries it.
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
const PAGE_MASK: u64 = !0xfff;
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
const PAGE_BYTES: u64 = 0x1000;

/// How long to wait for the platform to report the wake that ended a shallow
/// sleep. A deep sleep never gets here — it resumes through the waking
/// vector — so this bounds only the S1 path, and it is bounded at all
/// because firmware that never sets the bit must not wedge the machine.
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
const WAKE_STATUS_WAIT_NS: u64 = 5_000_000_000;

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
/// # SAFETY: the caller owns the sleep transition and the FADT admitted this port.
unsafe fn out8(port: u16, value: u8) {
    // SAFETY: the sleep path is CPL0 and the FADT admitted this I/O port.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags)); }
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
/// # SAFETY: the caller owns the sleep transition and the FADT admitted this port.
unsafe fn out16(port: u16, value: u16) {
    // SAFETY: the sleep path is CPL0 and the FADT admitted this I/O port.
    unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags)); }
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
/// # SAFETY: the caller owns the sleep transition and the FADT admitted this port.
unsafe fn in16(port: u16) -> u16 {
    let value: u16;
    // SAFETY: the sleep path is CPL0 and the FADT admitted this I/O port.
    unsafe { core::arch::asm!("in ax, dx", out("ax") value, in("dx") port, options(nomem, nostack, preserves_flags)); }
    value
}

/// Map `bytes` at a physical register address and return its kernel VA.
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn mapped(address: u64, bytes: u64) -> Option<u64> {
    let page = address & PAGE_MASK;
    let offset = address.checked_sub(page)?;
    let count = offset.checked_add(bytes)?.checked_add(PAGE_BYTES - 1)? / PAGE_BYTES;
    // SAFETY: firmware admitted a system-memory register here and the sleep path owns its access.
    let va = unsafe { mmio_map::map_pages(page, count) };
    (va != 0).then_some(va.checked_add(offset)?)
}

/// Write `value` to the register `gas` names, `width` bytes wide.
/// # C: O(1)
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub fn write_gas(gas: Gas, width: u8, value: u32) -> bool {
    match gas.space_id {
        SPACE_SYSTEM_IO => {
            let Some(port) = u16::try_from(gas.address).ok() else { return false; };
            // SAFETY: `gas` came from the FADT as a sleep or status register in port space.
            unsafe { if width <= 1 { out8(port, value as u8) } else { out16(port, value as u16) } }
            true
        }
        SPACE_SYSTEM_MEMORY => {
            let Some(va) = mapped(gas.address, width.max(1) as u64) else { return false; };
            // SAFETY: `mapped` returned a live mapping of exactly this register.
            unsafe {
                if width <= 1 { core::ptr::write_volatile(va as *mut u8, value as u8) }
                else { core::ptr::write_volatile(va as *mut u16, value as u16) }
            }
            true
        }
        _ => false,
    }
}

/// Read the 16-bit register `gas` names.
/// # C: O(1)
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub fn read_gas16(gas: Gas) -> Option<u16> {
    match gas.space_id {
        SPACE_SYSTEM_IO => {
            let port = u16::try_from(gas.address).ok()?;
            // SAFETY: `gas` came from the FADT as a PM1 register in port space.
            Some(unsafe { in16(port) })
        }
        SPACE_SYSTEM_MEMORY => {
            let va = mapped(gas.address, 2)?;
            // SAFETY: `mapped` returned a live two-byte mapping of this register.
            Some(unsafe { core::ptr::read_volatile(va as *const u16) })
        }
        _ => None,
    }
}

/// Issue every write in the plan, in order, stopping at the first refusal.
/// Returns how many were issued.
/// # C: O(plan length)
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub fn execute(plan: &SleepPlan) -> usize {
    let mut issued = 0usize;
    for index in 0..plan.len() {
        let Some(w) = plan.get(index) else { break; };
        if !write_gas(w.gas, w.width, w.value) { break; }
        issued += 1;
    }
    issued
}

/// Wait, bounded, for the PM1 status register to report the wake.
/// # C: O(1) amortised over a bounded spin
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub fn wait_wake_status(status: Gas) -> bool {
    use hal::TimerOps;
    let deadline = hal_x86_64::X86TimerOps::monotonic_ns().0.saturating_add(WAKE_STATUS_WAIT_NS);
    while hal_x86_64::X86TimerOps::monotonic_ns().0 < deadline {
        if read_gas16(status).is_some_and(|v| v & PM1_WAKE_STATUS != 0) { return true; }
        core::hint::spin_loop();
    }
    false
}

/// Publish the resume address in the FACS firmware waking vector.
///
/// Which fields are written is the firmware crate's decision — the 32-bit
/// vector always, the 64-bit one only on a table long enough and versioned
/// to have it, and explicitly zeroed otherwise. This only performs it.
/// # C: O(1)
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub fn publish_waking_vector(pa32: u32, pa64: u64) -> bool {
    use firmware::acpi::facs;
    let Some(f) = facs::facs() else { return false; };
    let Some(facs_pa) = facs::facs_pa() else { return false; };
    let writes = facs::waking_vector_writes(&f, pa32, pa64);
    let Some(base) = mapped(facs_pa, f.length as u64) else { return false; };
    // SAFETY: `mapped` covers the FACS's whole declared length, and both
    // offsets are inside it by the parse that produced `writes`.
    unsafe {
        core::ptr::write_volatile((base + facs::vector32_offset() as u64) as *mut u32, writes.vector32);
        if let Some(x) = writes.xvector {
            core::ptr::write_volatile((base + facs::xvector_offset() as u64) as *mut u64, x);
        }
    }
    true
}

/// Hosted build: no port space, no MMIO, nothing to write.
/// # C: O(1)
#[cfg(not(all(target_os = "oxide-kernel", target_arch = "x86_64")))]
pub fn write_gas(_gas: Gas, _width: u8, _value: u32) -> bool { false }

/// Hosted counterpart. # C: O(1)
#[cfg(not(all(target_os = "oxide-kernel", target_arch = "x86_64")))]
pub fn read_gas16(_gas: Gas) -> Option<u16> { None }

/// Hosted counterpart: the plan is inspected by the tests, not issued. # C: O(1)
#[cfg(not(all(target_os = "oxide-kernel", target_arch = "x86_64")))]
pub fn execute(_plan: &SleepPlan) -> usize { 0 }

/// Hosted counterpart. # C: O(1)
#[cfg(not(all(target_os = "oxide-kernel", target_arch = "x86_64")))]
pub fn wait_wake_status(_status: Gas) -> bool { false }

/// Hosted counterpart. # C: O(1)
#[cfg(not(all(target_os = "oxide-kernel", target_arch = "x86_64")))]
pub fn publish_waking_vector(_pa32: u32, _pa64: u64) -> bool { false }
