//! Typed CPU OPP records decoded from FDT properties.

extern crate alloc;

use alloc::vec::Vec;

/// Voltage selected alongside one OPP, in microvolts.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OppVoltage { pub target_uv: u32, pub min_uv: u32, pub max_uv: u32 }

/// One enabled operating point from a table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatingPoint { pub rates_hz: Vec<u64>, pub voltage: Option<OppVoltage>, pub turbo: bool }

impl OperatingPoint {
    /// Rate of the first clock, which is the CPU frequency exposed to cpufreq. # C: O(1)
    pub fn primary_rate_hz(&self) -> Option<u64> { self.rates_hz.first().copied() }
}

/// One provider phandle plus the cells selecting a clock output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClockReference { pub provider: u32, pub arguments: Vec<u32> }

/// One CPU's usable DT OPP table and the hardware handles it references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuOppTable {
    pub cpu_mpidr: u64,
    pub table_phandle: u32,
    pub clocks: Vec<ClockReference>,
    pub regulator_phandle: Option<u32>,
    pub shared: bool,
    pub transition_latency_ns: u32,
    pub points: Vec<OperatingPoint>,
}
