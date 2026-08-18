//! Concrete CPU OPP domain assembly.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{DomainPlan, initial_index};

/// One assembled policy and the hardware owners that program it.
pub(crate) struct Domain { pub(crate) policy: Arc<cpufreq::Policy>, pub(crate) opp: Arc<opp::Domain> }

/// Bind one admitted DT domain to its registered clock and regulator owners.
/// # C: O(points)
pub(crate) fn build(plan: DomainPlan) -> Option<Domain> {
    let clocks: Vec<_> = plan.table.clocks.iter().map(|reference| {
        let spec = clk::ClockSpec::new(reference.provider, reference.arguments.clone())?;
        clk::by_spec(&spec)
    }).collect::<Option<_>>()?;
    if clocks.is_empty() || clocks.iter().enumerate().any(|(index, clock)| {
        !clock.rate_changeable() && plan.table.points.windows(2).any(|pair| {
            pair[0].rates_hz.get(index) != pair[1].rates_hz.get(index)
        })
    }) {
        return None;
    }
    let regulator = match plan.table.regulator_phandle {
        Some(phandle) => Some(regulator::by_phandle(phandle)?), None => None,
    };
    let mut points = Vec::with_capacity(plan.table.points.len());
    let mut entries = Vec::with_capacity(plan.table.points.len());
    for (index, point) in plan.table.points.iter().enumerate() {
        let rate_hz = point.primary_rate_hz()?;
        if rate_hz % cpufreq::limits::HZ_PER_KHZ != 0 { return None; }
        let khz = u32::try_from(rate_hz / cpufreq::limits::HZ_PER_KHZ).ok()?;
        let voltage = point.voltage.map(|voltage| regulator::Voltage {
            target_uv: voltage.target_uv, min_uv: voltage.min_uv, max_uv: voltage.max_uv,
        });
        points.push(opp::OperatingPoint { rates_hz: point.rates_hz.clone(), voltage });
        let flags = point.turbo.then_some(cpufreq::uapi::FLAG_BOOST).unwrap_or(0);
        entries.push(cpufreq::FreqEntry { frequency: khz, driver_data: u32::try_from(index).ok()?, flags });
    }
    let table = cpufreq::FreqTable::new(entries).ok()?;
    let initial = initial_index(&plan.table)?;
    let opp = Arc::new(opp::Domain::new(clocks, regulator, points).ok()?);
    opp.initialise(initial).ok()?;
    let current = table.entries.get(opp.current_index()?)?.frequency;
    let latency = u64::from(plan.table.transition_latency_ns).max(cpufreq::limits::DEFAULT_TRANSITION_LATENCY_NS);
    let policy = cpufreq::Policy::new(plan.cpus, table, latency, current, cpufreq::governor::default_governor().name)?;
    Some(Domain { policy, opp })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    static NEXT: AtomicU32 = AtomicU32::new(100);

    struct Clock { rate: AtomicU64 }
    impl clk::ClockOps for Clock {
        fn rate_hz(&self) -> Option<u64> { Some(self.rate.load(Ordering::Acquire)) }
        fn set_rate_hz(&self, rate_hz: u64) -> vfs::KResult<()> {
            self.rate.store(rate_hz, Ordering::Release); Ok(())
        }
    }

    struct FixedClock { rate: u64 }
    impl clk::ClockOps for FixedClock {
        fn rate_hz(&self) -> Option<u64> { Some(self.rate) }
        fn set_rate_hz(&self, rate_hz: u64) -> vfs::KResult<()> {
            (rate_hz == self.rate).then_some(()).ok_or(vfs::VfsError::Einval)
        }
        fn rate_changeable(&self) -> bool { false }
    }

    struct Regulator { voltage: AtomicU32 }
    impl regulator::RegulatorOps for Regulator {
        fn voltage_uv(&self) -> Option<u32> { Some(self.voltage.load(Ordering::Acquire)) }
        fn set_voltage(&self, voltage: regulator::Voltage) -> vfs::KResult<()> {
            self.voltage.store(voltage.target_uv, Ordering::Release); Ok(())
        }
    }

    #[test]
    fn a_dt_domain_binds_real_owners_and_starts_below_the_turbo_opp() {
        let clock_phandle = NEXT.fetch_add(2, Ordering::Relaxed);
        let regulator_phandle = clock_phandle + 1;
        let clock = Arc::new(Clock { rate: AtomicU64::new(0) });
        let regulator = Arc::new(Regulator { voltage: AtomicU32::new(0) });
        let spec = clk::ClockSpec::new(clock_phandle, alloc::vec![5]).expect("spec");
        let _clock = clk::register(spec, clock.clone()).expect("clock");
        let _regulator = regulator::register(regulator_phandle, regulator.clone()).expect("regulator");
        let table = ::fdt::CpuOppTable {
            cpu_mpidr: 0, table_phandle: NEXT.fetch_add(2, Ordering::Relaxed),
            clocks: alloc::vec![::fdt::ClockReference { provider: clock_phandle, arguments: alloc::vec![5] }],
            regulator_phandle: Some(regulator_phandle), shared: false, transition_latency_ns: 0,
            points: alloc::vec![
                ::fdt::OperatingPoint { rates_hz: alloc::vec![1_000_000], voltage: Some(::fdt::OppVoltage { target_uv: 900_000, min_uv: 900_000, max_uv: 900_000 }), turbo: false },
                ::fdt::OperatingPoint { rates_hz: alloc::vec![2_000_000], voltage: Some(::fdt::OppVoltage { target_uv: 1_000_000, min_uv: 1_000_000, max_uv: 1_000_000 }), turbo: true },
            ],
        };
        let domain = build(DomainPlan { cpus: alloc::vec![0], table }).expect("domain");
        assert_eq!(domain.policy.cur(), 1_000);
        assert_eq!(domain.opp.current_rate_hz(), Some(1_000_000));
        assert_eq!(regulator.voltage.load(Ordering::Acquire), 900_000);
        assert!(!domain.policy.boost());
        assert!(domain.policy.table.entries[1].boost());
    }

    #[test]
    fn a_dt_domain_programs_every_clock_in_a_multi_clock_opp() {
        let cpu_phandle = NEXT.fetch_add(3, Ordering::Relaxed);
        let bus_phandle = cpu_phandle + 1;
        let regulator_phandle = cpu_phandle + 2;
        let cpu_clock = Arc::new(Clock { rate: AtomicU64::new(1_000_000) });
        let bus_clock = Arc::new(Clock { rate: AtomicU64::new(400_000_000) });
        let regulator = Arc::new(Regulator { voltage: AtomicU32::new(900_000) });
        let _cpu = clk::register(clk::ClockSpec::new(cpu_phandle, alloc::vec![]).expect("cpu"), cpu_clock.clone()).expect("cpu");
        let _bus = clk::register(clk::ClockSpec::new(bus_phandle, alloc::vec![4]).expect("bus"), bus_clock.clone()).expect("bus");
        let _regulator = regulator::register(regulator_phandle, regulator).expect("regulator");
        let table = ::fdt::CpuOppTable {
            cpu_mpidr: 0, table_phandle: NEXT.fetch_add(1, Ordering::Relaxed),
            clocks: alloc::vec![
                ::fdt::ClockReference { provider: cpu_phandle, arguments: alloc::vec![] },
                ::fdt::ClockReference { provider: bus_phandle, arguments: alloc::vec![4] },
            ],
            regulator_phandle: Some(regulator_phandle), shared: false, transition_latency_ns: 0,
            points: alloc::vec![
                ::fdt::OperatingPoint { rates_hz: alloc::vec![1_000_000, 400_000_000], voltage: Some(::fdt::OppVoltage { target_uv: 900_000, min_uv: 900_000, max_uv: 900_000 }), turbo: false },
                ::fdt::OperatingPoint { rates_hz: alloc::vec![2_000_000, 600_000_000], voltage: Some(::fdt::OppVoltage { target_uv: 1_000_000, min_uv: 1_000_000, max_uv: 1_000_000 }), turbo: false },
            ],
        };
        let domain = build(DomainPlan { cpus: alloc::vec![0], table }).expect("domain");
        domain.opp.transition(1).expect("transition");
        assert_eq!(cpu_clock.rate.load(Ordering::Acquire), 2_000_000);
        assert_eq!(bus_clock.rate.load(Ordering::Acquire), 600_000_000);
    }

    #[test]
    fn an_immutable_auxiliary_clock_is_allowed_only_when_every_opp_keeps_its_rate() {
        let cpu_phandle = NEXT.fetch_add(2, Ordering::Relaxed);
        let bus_phandle = cpu_phandle + 1;
        let cpu_clock = Arc::new(Clock { rate: AtomicU64::new(1_000_000) });
        let _cpu = clk::register(clk::ClockSpec::new(cpu_phandle, alloc::vec![]).expect("cpu"), cpu_clock).expect("cpu");
        let _bus = clk::register(clk::ClockSpec::new(bus_phandle, alloc::vec![]).expect("bus"), Arc::new(FixedClock { rate: 400_000_000 })).expect("bus");
        let mut table = ::fdt::CpuOppTable {
            cpu_mpidr: 0, table_phandle: NEXT.fetch_add(1, Ordering::Relaxed),
            clocks: alloc::vec![
                ::fdt::ClockReference { provider: cpu_phandle, arguments: alloc::vec![] },
                ::fdt::ClockReference { provider: bus_phandle, arguments: alloc::vec![] },
            ],
            regulator_phandle: None, shared: false, transition_latency_ns: 0,
            points: alloc::vec![
                ::fdt::OperatingPoint { rates_hz: alloc::vec![1_000_000, 400_000_000], voltage: None, turbo: false },
                ::fdt::OperatingPoint { rates_hz: alloc::vec![2_000_000, 400_000_000], voltage: None, turbo: false },
            ],
        };
        assert!(build(DomainPlan { cpus: alloc::vec![0], table: table.clone() }).is_some());
        table.points[1].rates_hz[1] = 600_000_000;
        assert!(build(DomainPlan { cpus: alloc::vec![0], table }).is_none());
    }
}
