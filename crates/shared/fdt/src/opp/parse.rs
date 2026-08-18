//! OPP table and CPU phandle-graph decoder.

extern crate alloc;

use alloc::vec::Vec;

use crate::header::read_be_u32;
use crate::walk::{walk, Event, Flow};

use super::types::{ClockReference, CpuOppTable, OppVoltage, OperatingPoint, RequiredOpp};

struct RawCpu { mpidr: u64, enabled: bool, usable: bool, table: u32, clocks: Vec<u8>, regulator: Option<u32>, latency: u32 }
struct RawTable { phandle: u32, enabled: bool, usable: bool, shared: bool, points: Vec<RawPoint> }

#[derive(Clone)]
struct RawPoint {
    phandle: Option<u32>,
    point: OperatingPoint,
    required_phandles: Vec<u32>,
}

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
    current_ua: Option<u32>,
    level: Option<u32>,
    supported_hw: Option<Vec<u32>>,
    required_phandles: Option<Vec<u32>>,
    suspend: bool,
    turbo: bool,
    unusable: bool,
    points: Vec<RawPoint>,
}

impl Frame {
    fn new(name: &[u8], depth: u32, enabled: bool) -> Self {
        Self {
            depth, cpus: depth == 1 && name == b"cpus", address_cells: 2,
            cpu_name: name == b"cpu" || name.starts_with(b"cpu@"), cpu_type: false, enabled,
            phandle: None, clock_cells: None, reg: None, table: None,
            clocks: None, regulator: None, latency: 0, shared: false, rates: None,
            voltage: None, current_ua: None, level: None, supported_hw: None,
            required_phandles: None, suspend: false, turbo: false, unusable: false,
            points: Vec::new(),
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
                    b"opp-microamp" => match read_be_u32(data, 0).ok().filter(|_| data.len() == 4) {
                        Some(current_ua) => frame.current_ua = Some(current_ua), None => frame.unusable = true,
                    },
                    b"opp-level" => match read_be_u32(data, 0).ok().filter(|_| data.len() == 4) {
                        Some(level) => frame.level = Some(level), None => frame.unusable = true,
                    },
                    b"opp-supported-hw" => match u32s(data) {
                        Some(masks) if !masks.is_empty() => frame.supported_hw = Some(masks),
                        _ => frame.unusable = true,
                    },
                    b"required-opps" => match u32s(data) {
                        Some(phandles) if phandles.iter().all(|phandle| *phandle != 0) => frame.required_phandles = Some(phandles),
                        _ => frame.unusable = true,
                    },
                    b"opp-suspend" => frame.suspend = true,
                    b"turbo-mode" => frame.turbo = true,
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
                if frame.rates.is_some() || frame.level.is_some() {
                    if frame.enabled {
                        if let Some(parent) = stack.last_mut() {
                            parent.points.push(RawPoint {
                                phandle: frame.phandle,
                                point: OperatingPoint {
                                    rates_hz: frame.rates.unwrap_or_default(), voltage: frame.voltage,
                                    current_ua: frame.current_ua, level: frame.level,
                                    supported_hw: frame.supported_hw, required_opps: Vec::new(),
                                    suspend: frame.suspend, turbo: frame.turbo,
                                },
                                required_phandles: frame.required_phandles.unwrap_or_default(),
                            });
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
    let Some(targets) = required_targets(&tables) else { return Vec::new(); };
    let mut out = Vec::new();
    for cpu in cpus {
        if !cpu.enabled || !cpu.usable { continue; }
        let mut matching = tables.iter().filter(|table| table.phandle == cpu.table && table.enabled && table.usable);
        let Some(table) = matching.next() else { continue; };
        if matching.next().is_some() { continue; }
        let Some(clocks) = clock_references(&cpu.clocks, &clocks) else { continue; };
        let Some(mut points) = resolve_points(table, &targets) else { continue; };
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

type RequiredTarget = (u32, u32, Option<u32>, Option<Vec<u32>>);

fn required_targets(tables: &[RawTable]) -> Option<Vec<RequiredTarget>> {
    let mut targets = Vec::new();
    for table in tables {
        if !table.enabled || !table.usable { continue; }
        for point in &table.points {
            let Some(phandle) = point.phandle else { continue; };
            if targets.iter().any(|(existing, _, _, _)| *existing == phandle) { return None; }
            targets.push((phandle, table.phandle, point.point.level, point.point.supported_hw.clone()));
        }
    }
    Some(targets)
}

fn resolve_points(table: &RawTable, targets: &[RequiredTarget]) -> Option<Vec<OperatingPoint>> {
    let mut points = Vec::with_capacity(table.points.len());
    for raw in &table.points {
        let mut point = raw.point.clone();
        for phandle in &raw.required_phandles {
            let (_, table_phandle, level, supported_hw) = targets.iter().find(|(target, _, _, _)| target == phandle)?;
            let performance_state = (*level)?;
            if *table_phandle == table.phandle || point.required_opps.iter().any(|required| required.table_phandle == *table_phandle) {
                return None;
            }
            point.required_opps.push(RequiredOpp {
                table_phandle: *table_phandle, performance_state, supported_hw: supported_hw.clone(),
            });
        }
        points.push(point);
    }
    Some(points)
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

fn u32s(data: &[u8]) -> Option<Vec<u32>> {
    if data.is_empty() || data.len() % 4 != 0 { return None; }
    let mut values = Vec::with_capacity(data.len() / 4);
    for offset in (0..data.len()).step_by(4) { values.push(read_be_u32(data, offset).ok()?); }
    Some(values)
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
