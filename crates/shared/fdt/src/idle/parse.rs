//! One-pass decoder for CPU nodes and their idle-state phandles.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::header::read_be_u32;
use crate::props::contains_string;
use crate::walk::{walk, Event, Flow};

use super::types::{CpuIdleState, CpuIdleTable};

struct RawCpu { mpidr: u64, enabled: bool, psci: bool, states: Vec<u32>, usable: bool }
struct RawState {
    phandle: u32, enabled: bool, arm_idle: bool, usable: bool, name: String, description: String,
    wakeup_latency_us: Option<u32>, entry_latency_us: Option<u32>, exit_latency_us: Option<u32>,
    target_residency_us: Option<u32>, local_timer_stop: bool, psci_suspend_param: Option<u32>,
}

struct Frame {
    depth: u32, cpus: bool, address_cells: u32, enabled: bool, usable: bool,
    cpu_name: bool, cpu_type: bool, reg: Option<Vec<u8>>, psci: bool, states: Option<Vec<u32>>,
    phandle: Option<u32>, arm_idle: bool, name: String, description: Option<String>,
    wakeup_latency_us: Option<u32>, entry_latency_us: Option<u32>, exit_latency_us: Option<u32>,
    target_residency_us: Option<u32>, local_timer_stop: bool, psci_suspend_param: Option<u32>,
}

impl Frame {
    fn new(name: &[u8], depth: u32, enabled: bool) -> Self {
        Self {
            depth, cpus: depth == 1 && name == b"cpus", address_cells: 2, enabled, usable: true,
            cpu_name: name == b"cpu" || name.starts_with(b"cpu@"), cpu_type: false, reg: None,
            psci: false, states: None, phandle: None, arm_idle: false,
            name: text(name).unwrap_or_default(), description: None, wakeup_latency_us: None,
            entry_latency_us: None, exit_latency_us: None, target_residency_us: None,
            local_timer_stop: false, psci_suspend_param: None,
        }
    }
}

/// Decode every enabled PSCI CPU that names a complete idle-state ladder.
/// Firmware with one malformed referenced state contributes no table for that
/// CPU; it never leaves a partially usable ladder behind. # C: O(struct_block_size)
pub fn cpu_idle_tables(bytes: &[u8]) -> Vec<CpuIdleTable> {
    let mut stack = Vec::new();
    let mut cpus = Vec::new();
    let mut states = Vec::new();
    if walk(bytes, |event| {
        match event {
            Event::BeginNode { name, depth } => {
                let enabled = stack.last().is_none_or(|parent: &Frame| parent.enabled);
                stack.push(Frame::new(name, depth, enabled));
            }
            Event::Prop { name, data, depth } => {
                let Some(frame) = stack.last_mut().filter(|frame| frame.depth == depth) else { return Flow::Stop };
                match name {
                    b"#address-cells" if frame.cpus => frame.address_cells = read_be_u32(data, 0).ok()
                        .filter(|cells| (1..=2).contains(cells)).unwrap_or(0),
                    b"device_type" => frame.cpu_type = string(data) == Some(b"cpu"),
                    b"status" => frame.enabled &= matches!(string(data), Some(b"ok" | b"okay")),
                    b"reg" => frame.reg = Some(data.to_vec()),
                    b"enable-method" => frame.psci = string(data) == Some(b"psci"),
                    b"cpu-idle-states" => frame.states = phandles(data).or_else(|| { frame.usable = false; None }),
                    b"phandle" | b"linux,phandle" => frame.phandle = read_be_u32(data, 0).ok(),
                    b"compatible" => frame.arm_idle = contains_string(data, b"arm,idle-state"),
                    b"idle-state-name" => frame.description = text(data).or_else(|| { frame.usable = false; None }),
                    b"wakeup-latency-us" => frame.wakeup_latency_us = number(data, &mut frame.usable),
                    b"entry-latency-us" => frame.entry_latency_us = number(data, &mut frame.usable),
                    b"exit-latency-us" => frame.exit_latency_us = number(data, &mut frame.usable),
                    b"min-residency-us" => frame.target_residency_us = number(data, &mut frame.usable),
                    b"local-timer-stop" => frame.local_timer_stop = true,
                    b"arm,psci-suspend-param" => frame.psci_suspend_param = number(data, &mut frame.usable),
                    _ => {}
                }
            }
            Event::EndNode { depth } => {
                let Some(frame) = stack.pop() else { return Flow::Stop };
                if frame.depth != depth { return Flow::Stop; }
                let parent_cells = stack.last().filter(|parent| parent.cpus).map(|parent| parent.address_cells);
                if (frame.cpu_name || frame.cpu_type) && parent_cells.is_some() {
                    if let (Some(reg), Some(states)) = (frame.reg.as_deref(), frame.states) {
                        if let Some(mpidr) = cells(reg, parent_cells.unwrap_or(0)) {
                            cpus.push(RawCpu { mpidr, enabled: frame.enabled, psci: frame.psci,
                                               states, usable: frame.usable });
                        }
                    }
                }
                if let Some(phandle) = frame.phandle {
                    states.push(RawState {
                        phandle, enabled: frame.enabled, arm_idle: frame.arm_idle, usable: frame.usable,
                        name: frame.name, description: frame.description.unwrap_or_default(),
                        wakeup_latency_us: frame.wakeup_latency_us, entry_latency_us: frame.entry_latency_us,
                        exit_latency_us: frame.exit_latency_us, target_residency_us: frame.target_residency_us,
                        local_timer_stop: frame.local_timer_stop, psci_suspend_param: frame.psci_suspend_param,
                    });
                }
            }
        }
        Flow::Continue
    }).is_err() { return Vec::new(); }
    cpus.into_iter().filter_map(|cpu| table(cpu, &states)).collect()
}

fn table(cpu: RawCpu, states: &[RawState]) -> Option<CpuIdleTable> {
    if !cpu.enabled || !cpu.usable || !cpu.psci || cpu.states.is_empty() { return None; }
    let mut table = Vec::with_capacity(cpu.states.len());
    for phandle in cpu.states {
        let mut matching = states.iter().filter(|state| state.phandle == phandle);
        let state = matching.next()?;
        if matching.next().is_some() || !state.enabled || !state.arm_idle || !state.usable { return None; }
        let wakeup_latency_us = match state.wakeup_latency_us {
            Some(latency) => latency,
            None => state.entry_latency_us?.checked_add(state.exit_latency_us?)?,
        };
        table.push(CpuIdleState {
            name: state.name.clone(), description: state.description.clone(), wakeup_latency_us,
            target_residency_us: state.target_residency_us?, local_timer_stop: state.local_timer_stop,
            psci_suspend_param: state.psci_suspend_param?,
        });
    }
    Some(CpuIdleTable { cpu_mpidr: cpu.mpidr, states: table })
}

fn string(data: &[u8]) -> Option<&[u8]> { data.split(|byte| *byte == 0).next() }
fn text(data: &[u8]) -> Option<String> {
    let bytes = string(data)?;
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(bytes).into_owned())
}
fn number(data: &[u8], usable: &mut bool) -> Option<u32> {
    let value = read_be_u32(data, 0).ok();
    if value.is_none() || data.len() != 4 { *usable = false; }
    value
}
fn phandles(data: &[u8]) -> Option<Vec<u32>> {
    if data.is_empty() || data.len() % 4 != 0 { return None; }
    data.chunks_exact(4).map(|cell| cell.try_into().ok().map(u32::from_be_bytes)).collect()
}
fn cells(data: &[u8], count: u32) -> Option<u64> {
    if !(1..=2).contains(&count) || data.len() < count as usize * 4 { return None; }
    let mut value = 0u64;
    for index in 0..count as usize { value = (value << 32) | u64::from(read_be_u32(data, index * 4).ok()?); }
    Some(value)
}
