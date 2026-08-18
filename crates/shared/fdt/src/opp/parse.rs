//! OPP table and CPU phandle-graph decoder.

extern crate alloc;

use alloc::vec::Vec;

use crate::header::read_be_u32;
use crate::walk::{walk, Event, Flow};

use super::types::{ClockReference, CpuOppTable, OppVoltage, OperatingPoint};

struct RawCpu { mpidr: u64, enabled: bool, usable: bool, table: u32, clocks: Vec<u8>, regulator: Option<u32>, latency: u32 }
struct RawTable { phandle: u32, enabled: bool, usable: bool, shared: bool, points: Vec<OperatingPoint> }

struct Frame {
    depth: u32,
    cpus: bool,
    address_cells: u32,
    cpu_name: bool,
    cpu_type: bool,
    enabled: bool,
    phandle: Option<u32>,
    clock_cells: Option<u32>,
    reg: Option<Vec<u8>>,
    table: Option<u32>,
    clocks: Option<Vec<u8>>,
    regulator: Option<u32>,
    latency: u32,
    shared: bool,
    rates: Option<Vec<u64>>,
    voltage: Option<OppVoltage>,
    turbo: bool,
    unusable: bool,
    points: Vec<OperatingPoint>,
}

impl Frame {
    fn new(name: &[u8], depth: u32, enabled: bool) -> Self {
        Self {
            depth, cpus: depth == 1 && name == b"cpus", address_cells: 2,
            cpu_name: name == b"cpu" || name.starts_with(b"cpu@"), cpu_type: false, enabled,
            phandle: None, clock_cells: None, reg: None, table: None,
            clocks: None, regulator: None, latency: 0, shared: false, rates: None,
            voltage: None, turbo: false, unusable: false, points: Vec::new(),
        }
    }
}

/// Decode CPU nodes that name an `operating-points-v2` table. Each result has
/// complete clock specs and only enabled points, sorted by increasing first-clock rate.
/// A malformed phandle graph contributes no policy. # C: O(struct_block_size)
pub fn cpu_opp_tables(bytes: &[u8]) -> Vec<CpuOppTable> {
    let mut stack: Vec<Frame> = Vec::new();
    let mut cpus = Vec::new();
    let mut tables = Vec::new();
    let mut clocks = Vec::new();
    if walk(bytes, |event| {
        match event {
            Event::BeginNode { name, depth } => {
                let enabled = stack.last().is_none_or(|parent| parent.enabled);
                stack.push(Frame::new(name, depth, enabled));
            }
            Event::Prop { name, data, depth } => {
                let Some(frame) = stack.last_mut().filter(|frame| frame.depth == depth) else { return Flow::Stop };
                match name {
                    b"#address-cells" if frame.cpus => frame.address_cells = read_be_u32(data, 0).ok()
                        .filter(|cells| (1..=2).contains(cells)).unwrap_or(0),
                    b"#clock-cells" => frame.clock_cells = read_be_u32(data, 0).ok(),
                    b"device_type" => frame.cpu_type = string(data) == Some(b"cpu"),
                    b"status" => frame.enabled &= matches!(string(data), Some(b"ok" | b"okay")),
                    b"phandle" | b"linux,phandle" => frame.phandle = read_be_u32(data, 0).ok(),
                    b"reg" => frame.reg = Some(data.to_vec()),
                    b"operating-points-v2" => frame.table = read_be_u32(data, 0).ok(),
                    b"clocks" => frame.clocks = Some(data.to_vec()),
                    b"cpu-supply" => match read_be_u32(data, 0).ok() {
                        Some(phandle) => frame.regulator = Some(phandle), None => frame.unusable = true,
                    },
                    b"clock-latency" => match read_be_u32(data, 0).ok() {
                        Some(latency) => frame.latency = latency, None => frame.unusable = true,
                    },
                    b"opp-shared" => frame.shared = true,
                    b"opp-hz" => match rates(data) {
                        Some(rates) => frame.rates = Some(rates), None => frame.unusable = true,
                    },
                    b"opp-microvolt" => match voltage(data) {
                        Some(voltage) => frame.voltage = Some(voltage), None => frame.unusable = true,
                    },
                    b"turbo-mode" => frame.turbo = true,
                    b"opp-supported-hw" | b"required-opps" | b"opp-microamp" | b"opp-level"
                        | b"opp-suspend" => frame.unusable = true,
                    _ => {}
                }
            }
            Event::EndNode { depth } => {
                let Some(frame) = stack.pop() else { return Flow::Stop };
                if frame.depth != depth { return Flow::Stop; }
                let parent_cells = stack.last().filter(|parent| parent.cpus).map(|parent| parent.address_cells);
                if frame.unusable {
                    if let Some(parent) = stack.last_mut() { parent.unusable = true; }
                }
                if (frame.cpu_name || frame.cpu_type) && parent_cells.is_some() {
                    if let (Some(reg), Some(table), Some(clocks)) = (frame.reg.as_deref(), frame.table, frame.clocks) {
                        if let Some(mpidr) = cells(reg, parent_cells.unwrap_or(0)) {
                            cpus.push(RawCpu { mpidr, enabled: frame.enabled, table, clocks,
                                               usable: !frame.unusable, regulator: frame.regulator, latency: frame.latency });
                        }
                    }
                }
                if let Some(rates_hz) = frame.rates {
                    if frame.enabled {
                        if let Some(parent) = stack.last_mut() {
                            parent.points.push(OperatingPoint { rates_hz, voltage: frame.voltage, turbo: frame.turbo });
                        }
                    }
                }
                if let Some(phandle) = frame.phandle {
                    if let Some(cells) = frame.clock_cells { clocks.push((phandle, cells)); }
                    if !frame.points.is_empty() {
                        tables.push(RawTable { phandle, enabled: frame.enabled, usable: !frame.unusable,
                                               shared: frame.shared, points: frame.points });
                    }
                }
            }
        }
        Flow::Continue
    }).is_err() { return Vec::new(); }
    let mut out = Vec::new();
    for cpu in cpus {
        if !cpu.enabled || !cpu.usable { continue; }
        let mut matching = tables.iter().filter(|table| table.phandle == cpu.table && table.enabled && table.usable);
        let Some(table) = matching.next() else { continue; };
        if matching.next().is_some() { continue; }
        let Some(clocks) = clock_references(&cpu.clocks, &clocks) else { continue; };
        let mut points = table.points.clone();
        if points.iter().any(|point| point.rates_hz.len() != clocks.len()) { continue; }
        points.sort_unstable_by_key(|point| point.primary_rate_hz());
        if points.iter().any(|point| point.primary_rate_hz().is_none())
            || points.windows(2).any(|pair| pair[0].primary_rate_hz() == pair[1].primary_rate_hz()) { continue; }
        out.push(CpuOppTable {
            cpu_mpidr: cpu.mpidr, table_phandle: table.phandle, clocks, regulator_phandle: cpu.regulator,
            shared: table.shared, transition_latency_ns: cpu.latency, points,
        });
    }
    out
}

fn string(data: &[u8]) -> Option<&[u8]> { data.split(|byte| *byte == 0).next() }

fn rates(data: &[u8]) -> Option<Vec<u64>> {
    if data.is_empty() || data.len() % 8 != 0 { return None; }
    let mut rates = Vec::with_capacity(data.len() / 8);
    for pair in data.chunks_exact(8) {
        let rate = u64::from_be_bytes(pair.try_into().ok()?);
        if rate == 0 { return None; }
        rates.push(rate);
    }
    Some(rates)
}

fn cells(data: &[u8], count: u32) -> Option<u64> {
    if !(1..=2).contains(&count) || data.len() < count as usize * 4 { return None; }
    let mut value = 0u64;
    for index in 0..count as usize { value = (value << 32) | u64::from(read_be_u32(data, index * 4).ok()?); }
    Some(value)
}

fn voltage(data: &[u8]) -> Option<OppVoltage> {
    let cells = data.len() / 4;
    if data.len() % 4 != 0 || !matches!(cells, 1 | 3) { return None; }
    let target_uv = read_be_u32(data, 0).ok()?;
    let (min_uv, max_uv) = if cells == 1 { (target_uv, target_uv) }
        else { (read_be_u32(data, 4).ok()?, read_be_u32(data, 8).ok()?) };
    (target_uv != 0 && min_uv <= target_uv && target_uv <= max_uv)
        .then_some(OppVoltage { target_uv, min_uv, max_uv })
}

fn clock_references(data: &[u8], clocks: &[(u32, u32)]) -> Option<Vec<ClockReference>> {
    if data.is_empty() || data.len() % 4 != 0 { return None; }
    let mut offset = 0usize;
    let mut references = Vec::new();
    while offset < data.len() {
        let provider = read_be_u32(data, offset).ok()?;
        let mut candidates = clocks.iter().filter(|(clock, _)| *clock == provider).map(|(_, cells)| *cells);
        let count = usize::try_from(candidates.next()?).ok()?;
        if candidates.next().is_some() { return None; }
        let words = count.checked_add(1)?;
        let bytes = words.checked_mul(4)?;
        if data.len().checked_sub(offset)? < bytes { return None; }
        let mut arguments = Vec::with_capacity(count);
        for index in 0..count { arguments.push(read_be_u32(data, offset + (index + 1) * 4).ok()?); }
        references.push(ClockReference { provider, arguments });
        offset = offset.checked_add(bytes)?;
    }
    Some(references)
}
