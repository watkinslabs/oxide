//! Typed CPU OPP records decoded from FDT properties.

extern crate alloc;

use alloc::vec::Vec;

/// Voltage selected alongside one OPP, in microvolts.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OppVoltage { pub target_uv: u32, pub min_uv: u32, pub max_uv: u32 }

/// One dependent OPP's owning table and the performance state it requires.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequiredOpp {
    /// The dependent OPP table selected by this reference.
    pub table_phandle: u32,
    /// The dependent OPP's `opp-level` performance state.
    pub performance_state: u32,
    /// Hardware-version masks that must admit the dependent OPP, if present.
    pub supported_hw: Option<Vec<u32>>,
}

/// One enabled operating point from a table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatingPoint {
    pub rates_hz: Vec<u64>,
    pub voltage: Option<OppVoltage>,
    /// Regulator load in microamps, including zero when this OPP releases it.
    pub current_ua: Option<u32>,
    /// Platform-defined performance state for another domain to require.
    pub level: Option<u32>,
    /// A flattened matrix of hardware-version masks for this OPP.
    pub supported_hw: Option<Vec<u32>>,
    /// Dependent performance states that must be selected with this OPP.
    pub required_opps: Vec<RequiredOpp>,
    /// Whether this OPP is eligible as the device suspend operating point.
    pub suspend: bool,
    pub turbo: bool,
}

impl Default for OperatingPoint {
    fn default() -> Self {
        Self {
            rates_hz: Vec::new(), voltage: None, current_ua: None, level: None,
            supported_hw: None, required_opps: Vec::new(), suspend: false, turbo: false,
        }
    }
}

impl OperatingPoint {
    /// Rate of the first clock, which is the CPU frequency exposed to cpufreq. # C: O(1)
    pub fn primary_rate_hz(&self) -> Option<u64> { self.rates_hz.first().copied() }
}

impl CpuOppTable {
    /// The highest-frequency enabled OPP marked for system suspend. # C: O(points)
    pub fn suspend_index(&self) -> Option<usize> {
        self.points.iter().enumerate().filter(|(_, point)| point.suspend)
            .max_by_key(|(_, point)| point.primary_rate_hz()).map(|(index, _)| index)
    }
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
