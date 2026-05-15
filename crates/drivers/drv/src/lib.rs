// Driver model per `35`. Bus/device/driver dispatch + the
// `Driver`/`DriverInstance` traits.
//
// v1 substrate. Per `35§3` invariant 1 ("each driver is a separate
// crate `drv-*`; core kernel does not depend on any driver crate"),
// individual hardware drivers (virtio-net, virtio-blk, NVMe, AHCI,
// PS/2-kbd) will land in their own `drv-*` crates over phase 11.
//
// Currently the kernel-side modules under `kernel/src/dev_virtio_*`
// + `kernel/src/pci_boot/*` host the actual drivers because they
// need direct access to PMM / HHDM / IRQ controller — moving each
// to a separate crate is per-driver work.
//
// This crate ships the dispatch substrate they will plug into:
//   - DRIVERS slice via `register`
//   - probe_all walker
//   - DriverError enum
//
// `drv::init()` reports ready; real probe runs from kernel boot
// after PCI enumeration completes.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Spinlock, TaskList as DriverListClass};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { NoMatch, NoMem, ProbeFailed, Removed }

pub type KResult<T> = core::result::Result<T, Error>;

/// Per-driver probe entry point. `probe(bdf)` is called once per
/// matching device. Returns `Ok(())` on successful binding, error
/// to leave the device unbound.
pub type ProbeFn = fn(bdf: u32) -> KResult<()>;

/// Boot-time-registered driver. Real per-bus matching (PCI vendor/
/// device, virtio device-id, ACPI HID) rides per-driver crate
/// definitions; v1 keeps a flat probe list and lets each driver
/// match internally.
pub struct DriverEntry {
    pub name:  &'static str,
    pub probe: ProbeFn,
}

/// Probe count for diagnostics.
static REGISTERED: AtomicU32 = AtomicU32::new(0);

/// In-RAM driver list. Distributed slice via `linkme` is a follow-up;
/// v1 uses explicit `register` from each driver's init.
static DRIVERS: Spinlock<Vec<DriverEntry>, DriverListClass>
    = Spinlock::new(Vec::new());

/// Register a driver. Called from each `drv-*` crate's init or from
/// kernel-side virtio/PCI bring-up code that hasn't been split out
/// to its own crate yet.
/// # C: O(1)
pub fn register(d: DriverEntry) {
    DRIVERS.lock().push(d);
    REGISTERED.fetch_add(1, Ordering::Release);
}

/// Walk every registered driver's probe with `bdf`. First successful
/// probe wins; later drivers don't see the device.
/// # C: O(N_drivers)
pub fn probe_all(bdf: u32) -> usize {
    let mut bound = 0usize;
    let snap: Vec<ProbeFn> = DRIVERS.lock().iter().map(|d| d.probe).collect();
    for p in snap {
        if p(bdf).is_ok() { bound += 1; break; }
    }
    bound
}

/// Number of drivers registered to date.
/// # C: O(1)
pub fn registered_count() -> u32 {
    REGISTERED.load(Ordering::Acquire)
}

/// Boot-time init reporter. Per-driver register() calls happen from
/// kernel boot after PMM + PCI enumeration complete.
/// # SAFETY: caller is the boot path; pre-init; single-CPU.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> KResult<()> { Ok(()) }

#[cfg(test)]
mod tests {
    use super::*;
    fn dummy_probe(_bdf: u32) -> KResult<()> { Ok(()) }
    #[test]
    fn init_ok() {
        // SAFETY: hosted-test path; init has no side effects + no preconditions on host.
        unsafe { assert!(init().is_ok()); }
    }
    #[test]
    fn register_increments_count() {
        let before = registered_count();
        register(DriverEntry { name: "test", probe: dummy_probe });
        assert_eq!(registered_count(), before + 1);
    }
}
