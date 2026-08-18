//! Ordered OPP transitions over every clock a table declares.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use vfs::{KResult, VfsError};

/// Rates for every selected clock and, when the platform supplies one, a voltage range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatingPoint { pub rates_hz: Vec<u64>, pub voltage: Option<regulator::Voltage> }

impl OperatingPoint {
    fn primary_rate_hz(&self) -> Option<u64> { self.rates_hz.first().copied() }
}

/// A DT OPP table bound to its real programmable hardware owners.
pub struct Domain {
    clocks: Vec<Arc<clk::Clock>>,
    regulator: Option<Arc<regulator::Regulator>>,
    points: Vec<OperatingPoint>,
    transitioning: AtomicBool,
}

impl Domain {
    /// Bind strictly ordered operating points to their concrete rate and voltage owners.
    /// # C: O(clocks × points)
    pub fn new(clocks: Vec<Arc<clk::Clock>>, regulator: Option<Arc<regulator::Regulator>>,
               points: Vec<OperatingPoint>) -> KResult<Self>
    {
        if clocks.is_empty() || points.is_empty() { return Err(VfsError::Einval); }
        let has_voltage = points[0].voltage.is_some();
        if has_voltage != regulator.is_some() { return Err(VfsError::Enodev); }
        let mut previous = 0u64;
        for point in &points {
            let Some(primary) = point.primary_rate_hz() else { return Err(VfsError::Einval); };
            if primary <= previous || point.rates_hz.len() != clocks.len()
                || point.rates_hz.iter().any(|rate| *rate == 0)
                || point.voltage.is_some() != has_voltage { return Err(VfsError::Einval); }
            if !point.voltage.is_none_or(regulator::Voltage::valid) { return Err(VfsError::Einval); }
            previous = primary;
        }
        Ok(Self { clocks, regulator, points, transitioning: AtomicBool::new(false) })
    }

    /// Immutable operating-point table in ascending first-clock rate order. # C: O(1)
    pub fn points(&self) -> &[OperatingPoint] { &self.points }

    /// Index whose complete rate vector matches the hardware exactly. # C: O(clocks × points)
    pub fn current_index(&self) -> Option<usize> {
        let rates = self.current_rates_hz()?;
        self.points.iter().position(|point| point.rates_hz == rates)
    }

    /// Current first-clock rate, the CPU rate cpufreq exposes. # C: O(provider)
    pub fn current_rate_hz(&self) -> Option<u64> { self.clocks.first()?.rate_hz() }

    /// Transition to OPP `index`, raising voltage before clocks and lowering it after clocks.
    /// Multiple clocks follow DT declaration order while scaling up and reverse order while scaling down.
    /// # C: O(clocks)
    /// # Sleeps: y
    pub fn transition(&self, index: usize) -> KResult<()> {
        let next = self.points.get(index).ok_or(VfsError::Einval)?;
        let _guard = TransitionGuard::acquire(&self.transitioning);
        let current = self.current_index().ok_or(VfsError::Eio)?;
        if current == index { return Ok(()); }
        let previous = &self.points[current];
        let scaling_down = next.primary_rate_hz() < previous.primary_rate_hz();
        if scaling_down { self.lower(previous, next) } else { self.raise(previous, next) }
    }

    /// Establish a declared initial OPP before a policy caches its current rate.
    /// An unknown boot rate is raised to a safe declared point rather than
    /// publishing a cache that disagrees with the hardware. # C: O(clocks)
    /// # Sleeps: y
    pub fn initialise(&self, index: usize) -> KResult<()> {
        if self.current_index().is_some() { return self.transition(index); }
        let next = self.points.get(index).ok_or(VfsError::Einval)?;
        let _guard = TransitionGuard::acquire(&self.transitioning);
        if let Some(regulator) = &self.regulator { regulator.set_voltage(next.voltage.ok_or(VfsError::Einval)?)?; }
        self.program_initial(next)
    }

    fn raise(&self, previous: &OperatingPoint, next: &OperatingPoint) -> KResult<()> {
        if let Some(regulator) = &self.regulator {
            regulator.set_voltage(next.voltage.ok_or(VfsError::Einval)?)?;
            if let Err(error) = self.program(previous, next, false) {
                let _ = regulator.set_voltage(previous.voltage.ok_or(VfsError::Einval)?);
                return Err(error);
            }
            return Ok(());
        }
        self.program(previous, next, false)
    }

    fn lower(&self, previous: &OperatingPoint, next: &OperatingPoint) -> KResult<()> {
        self.program(previous, next, true)?;
        if let Some(regulator) = &self.regulator {
            if let Err(error) = regulator.set_voltage(next.voltage.ok_or(VfsError::Einval)?) {
                self.restore(previous, true);
                return Err(error);
            }
        }
        Ok(())
    }

    fn program_initial(&self, next: &OperatingPoint) -> KResult<()> {
        for (clock, rate) in self.clocks.iter().zip(&next.rates_hz) { clock.set_rate_hz(*rate)?; }
        Ok(())
    }

    fn program(&self, previous: &OperatingPoint, next: &OperatingPoint, scaling_down: bool) -> KResult<()> {
        let mut changed: Vec<usize> = Vec::with_capacity(self.clocks.len());
        for offset in 0..self.clocks.len() {
            let index = if scaling_down { self.clocks.len() - offset - 1 } else { offset };
            if let Err(error) = self.clocks[index].set_rate_hz(next.rates_hz[index]) {
                for index in changed.into_iter().rev() { let _ = self.clocks[index].set_rate_hz(previous.rates_hz[index]); }
                return Err(error);
            }
            changed.push(index);
        }
        Ok(())
    }

    fn restore(&self, previous: &OperatingPoint, scaling_down: bool) {
        for offset in 0..self.clocks.len() {
            let index = if scaling_down { offset } else { self.clocks.len() - offset - 1 };
            let _ = self.clocks[index].set_rate_hz(previous.rates_hz[index]);
        }
    }

    fn current_rates_hz(&self) -> Option<Vec<u64>> {
        self.clocks.iter().map(|clock| clock.rate_hz()).collect()
    }
}

/// Sleepable-transition serialisation without holding a spinlock over provider calls.
struct TransitionGuard<'a> { flag: &'a AtomicBool }

impl<'a> TransitionGuard<'a> {
    fn acquire(flag: &'a AtomicBool) -> Self {
        while flag.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            sync::relax();
        }
        Self { flag }
    }
}

impl Drop for TransitionGuard<'_> {
    fn drop(&mut self) { self.flag.store(false, Ordering::Release); }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
