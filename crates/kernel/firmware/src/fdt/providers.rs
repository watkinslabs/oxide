//! Fixed DT clock, fixed-factor clock, and regulator provider registration.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use ::fdt::{FixedClock, FixedFactorClock, FixedProviders, FixedRegulator};
use sync::{Devices, Spinlock};
use vfs::{KResult, VfsError};

struct FixedClockOwner { rate_hz: u64 }

impl clk::ClockOps for FixedClockOwner {
    fn rate_hz(&self) -> Option<u64> { Some(self.rate_hz) }
    fn set_rate_hz(&self, rate_hz: u64) -> KResult<()> {
        (rate_hz == self.rate_hz).then_some(()).ok_or(VfsError::Einval)
    }
    fn rate_changeable(&self) -> bool { false }
}

struct FixedFactorOwner { parent: Arc<clk::Clock>, mult: u64, div: u64 }

impl clk::ClockOps for FixedFactorOwner {
    fn rate_hz(&self) -> Option<u64> { self.parent.rate_hz()?.checked_mul(self.mult)?.checked_div(self.div) }
    fn set_rate_hz(&self, rate_hz: u64) -> KResult<()> {
        (self.rate_hz() == Some(rate_hz)).then_some(()).ok_or(VfsError::Einval)
    }
    fn rate_changeable(&self) -> bool { false }
}

struct Regulator { voltage_uv: u32 }

static PENDING_FACTORS: Spinlock<Vec<FixedFactorClock>, Devices> = Spinlock::new(Vec::new());

impl regulator::RegulatorOps for Regulator {
    fn voltage_uv(&self) -> Option<u32> { Some(self.voltage_uv) }
    fn set_voltage(&self, voltage: regulator::Voltage) -> KResult<()> {
        (voltage.min_uv <= self.voltage_uv && self.voltage_uv <= voltage.max_uv)
            .then_some(()).ok_or(VfsError::Einval)
    }
}

/// Register all complete fixed providers from the retained device tree. # C: O(FDT²)
pub fn init() -> usize {
    clk::subscribe_availability(retry_factors);
    super::blob().map(::fdt::fixed_providers).map(register).unwrap_or(0)
}

fn register(providers: FixedProviders) -> usize {
    let mut added = 0usize;
    for FixedClock { phandle, rate_hz } in providers.clocks {
        let Some(spec) = clk::ClockSpec::new(phandle, alloc::vec![]) else { continue; };
        if clk::register(spec, Arc::new(FixedClockOwner { rate_hz })).is_ok() { added += 1; }
    }
    for FixedRegulator { phandle, voltage_uv } in providers.regulators {
        if regulator::register(phandle, Arc::new(Regulator { voltage_uv })).is_ok() { added += 1; }
    }
    PENDING_FACTORS.lock().extend(providers.factors);
    added + bind_factors()
}

fn retry_factors() { let _ = bind_factors(); }

fn bind_factors() -> usize {
    let mut waiting = core::mem::take(&mut *PENDING_FACTORS.lock());
    let mut added = 0usize;
    loop {
        let count = waiting.len();
        let mut next = Vec::with_capacity(count);
        for factor in waiting {
            let Some(spec) = clk::ClockSpec::new(factor.phandle, alloc::vec![]) else { continue; };
            if clk::by_spec(&spec).is_some() { continue; }
            let Some(parent_spec) = clk::ClockSpec::new(factor.parent.provider, factor.parent.arguments.clone()) else {
                continue;
            };
            let Some(parent) = clk::by_spec(&parent_spec) else { next.push(factor); continue; };
            let owner = FixedFactorOwner { parent, mult: u64::from(factor.mult), div: u64::from(factor.div) };
            match clk::register(spec, Arc::new(owner)) {
                Ok(_) => added += 1,
                Err(VfsError::Eexist) => {}
                Err(_) => next.push(factor),
            }
        }
        if next.len() == count { waiting = next; break; }
        waiting = next;
    }
    PENDING_FACTORS.lock().extend(waiting);
    added
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    static NEXT: AtomicU32 = AtomicU32::new(4_000);

    #[test]
    fn fixed_owners_preserve_the_hardware_values_and_refuse_a_different_rate() {
        let clock = NEXT.fetch_add(2, Ordering::Relaxed);
        let regulator = clock + 1;
        assert_eq!(register(FixedProviders {
            clocks: alloc::vec![FixedClock { phandle: clock, rate_hz: 1_000_000 }],
            factors: alloc::vec![],
            regulators: alloc::vec![FixedRegulator { phandle: regulator, voltage_uv: 900_000 }],
        }), 2);
        let spec = clk::ClockSpec::new(clock, alloc::vec![]).expect("spec");
        let owner = clk::by_spec(&spec).expect("clock");
        assert_eq!(owner.rate_hz(), Some(1_000_000));
        assert!(!owner.rate_changeable());
        assert_eq!(owner.set_rate_hz(2_000_000), Err(VfsError::Einval));
        let supply = regulator::by_phandle(regulator).expect("regulator");
        assert_eq!(supply.voltage_uv(), Some(900_000));
        assert!(supply.set_voltage(regulator::Voltage { target_uv: 850_000, min_uv: 800_000, max_uv: 900_000 }).is_ok());
    }

    #[test]
    fn a_fixed_factor_tracks_its_parent_and_waits_for_a_late_parent_owner() {
        let source = NEXT.fetch_add(2, Ordering::Relaxed);
        let factor = source + 1;
        clk::subscribe_availability(retry_factors);
        assert_eq!(register(FixedProviders {
            clocks: alloc::vec![],
            factors: alloc::vec![FixedFactorClock {
                phandle: factor, parent: ::fdt::ClockReference { provider: source, arguments: alloc::vec![] }, mult: 2, div: 3,
            }],
            regulators: alloc::vec![],
        }), 0);
        let source_spec = clk::ClockSpec::new(source, alloc::vec![]).expect("source");
        let _source = clk::register(source_spec, Arc::new(FixedClockOwner { rate_hz: 24_000_000 })).expect("source");
        let factor_spec = clk::ClockSpec::new(factor, alloc::vec![]).expect("factor");
        let derived = clk::by_spec(&factor_spec).expect("factor");
        assert_eq!(derived.rate_hz(), Some(16_000_000));
        assert!(!derived.rate_changeable());
        assert_eq!(derived.set_rate_hz(24_000_000), Err(VfsError::Einval));
    }
}
