//! One-pass SCMI FDT graph collection plus physical-resource resolution.

extern crate alloc;

use alloc::vec::Vec;

use crate::header::read_be_u32;
use crate::props::contains_string;
use crate::walk::{walk, Event, Flow};

use super::types::{ScmiCompletionIrq, ScmiCpuDomain, ScmiPerfProtocol, ScmiSharedMemory, ScmiSmcTransport};

const PERF_PROTOCOL: u32 = 0x13;

#[derive(Copy, Clone, Eq, PartialEq)]
enum Controller { None, Direct, PageAndOffset }

struct Node {
    parent: Option<usize>, depth: u32, enabled: bool, bad: bool,
    cpus: bool, cpu_name: bool, cpu_type: bool, shmem_node: bool, gic: bool, controller: Controller,
    phandle: Option<u32>, address_cells: Option<u32>, size_cells: Option<u32>, interrupt_cells: Option<u32>,
    clock_cells: Option<u32>, power_cells: Option<u32>, smc_id: Option<u32>,
    reg: Option<Vec<u8>>, ranges: Option<Vec<u8>>, shmem: Option<Vec<u8>>,
    clocks: Option<Vec<u8>>, power_domains: Option<Vec<u8>>, power_domain_names: Option<Vec<u8>>,
    interrupt_parent: Option<Vec<u8>>, interrupts: Option<Vec<u8>>, interrupts_extended: Option<Vec<u8>>, interrupt_names: Option<Vec<u8>>,
}

impl Node {
    fn new(parent: Option<usize>, depth: u32, name: &[u8], enabled: bool) -> Self {
        Self {
            parent, depth, enabled, bad: false, cpus: name == b"cpus", cpu_name: name == b"cpu" || name.starts_with(b"cpu@"),
            cpu_type: false, shmem_node: false, gic: false, controller: Controller::None, phandle: None,
            address_cells: None, size_cells: None, interrupt_cells: None, clock_cells: None, power_cells: None, smc_id: None,
            reg: None, ranges: None, shmem: None, clocks: None, power_domains: None, power_domain_names: None,
            interrupt_parent: None, interrupts: None, interrupts_extended: None, interrupt_names: None,
        }
    }

    fn assign_phandle(&mut self, value: Option<u32>) {
        let Some(value) = value.filter(|value| *value != 0) else { self.bad = true; return; };
        if self.phandle.is_some_and(|old| old != value) { self.bad = true; }
        self.phandle = Some(value);
    }
}

/// Decode enabled SMC SCMI performance protocols, their physical shared memory,
/// and every CPU's selected performance domain. Malformed graph branches are
/// omitted rather than publishing an unusable transport. # C: O(struct_block_size²)
pub fn scmi_perf_protocols(bytes: &[u8]) -> Vec<ScmiPerfProtocol> {
    let mut nodes = Vec::new();
    let mut stack = Vec::new();
    if walk(bytes, |event| {
        match event {
            Event::BeginNode { name, depth } => {
                let parent = stack.last().copied();
                let enabled = parent.and_then(|index| nodes.get(index)).map_or(true, |node: &Node| node.enabled);
                nodes.push(Node::new(parent, depth, name, enabled));
                stack.push(nodes.len() - 1);
            }
            Event::Prop { name, data, depth } => {
                let Some(node) = stack.last().and_then(|index| nodes.get_mut(*index)).filter(|node| node.depth == depth) else { return Flow::Stop };
                match name {
                    b"compatible" => {
                        node.shmem_node |= contains_string(data, b"arm,scmi-shmem");
                        node.gic |= contains_string(data, b"arm,gic-v3") || contains_string(data, b"arm,cortex-a15-gic");
                        if contains_string(data, b"arm,scmi-smc") { node.controller = Controller::Direct; }
                        if contains_string(data, b"arm,scmi-smc-param") { node.controller = Controller::PageAndOffset; }
                    }
                    b"status" => node.enabled &= matches!(string(data), Some(b"ok" | b"okay")),
                    b"device_type" => node.cpu_type = string(data) == Some(b"cpu"),
                    b"phandle" | b"linux,phandle" => node.assign_phandle(read_be_u32(data, 0).ok()),
                    b"#address-cells" => node.address_cells = read_be_u32(data, 0).ok(),
                    b"#size-cells" => node.size_cells = read_be_u32(data, 0).ok(),
                    b"#interrupt-cells" => node.interrupt_cells = read_be_u32(data, 0).ok(),
                    b"#clock-cells" => node.clock_cells = read_be_u32(data, 0).ok(),
                    b"#power-domain-cells" => node.power_cells = read_be_u32(data, 0).ok(),
                    b"arm,smc-id" => node.smc_id = read_be_u32(data, 0).ok(),
                    b"reg" => node.reg = Some(data.to_vec()),
                    b"ranges" => node.ranges = Some(data.to_vec()),
                    b"shmem" => node.shmem = Some(data.to_vec()),
                    b"clocks" => node.clocks = Some(data.to_vec()),
                    b"power-domains" => node.power_domains = Some(data.to_vec()),
                    b"power-domain-names" => node.power_domain_names = Some(data.to_vec()),
                    b"interrupt-parent" => node.interrupt_parent = Some(data.to_vec()),
                    b"interrupts" => node.interrupts = Some(data.to_vec()),
                    b"interrupts-extended" => node.interrupts_extended = Some(data.to_vec()),
                    b"interrupt-names" => node.interrupt_names = Some(data.to_vec()),
                    _ => {}
                }
            }
            Event::EndNode { depth } => {
                let Some(index) = stack.pop() else { return Flow::Stop };
                if nodes[index].depth != depth { return Flow::Stop; }
            }
        }
        Flow::Continue
    }).is_err() || !stack.is_empty() { return Vec::new(); }
    let mut out = Vec::new();
    for protocol in 0..nodes.len() {
        let Some(record) = protocol_record(&nodes, protocol) else { continue; };
        out.push(record);
    }
    out
}

fn protocol_record(nodes: &[Node], protocol: usize) -> Option<ScmiPerfProtocol> {
    let node = nodes.get(protocol)?;
    let controller = node.parent.and_then(|parent| nodes.get(parent))?;
    if !node.enabled || node.bad || !controller.enabled || controller.bad || controller.controller == Controller::None
        || protocol_id(nodes, protocol)? != PERF_PROTOCOL { return None; }
    let phandle = unique(nodes, node.phandle?)?;
    if phandle != protocol || node.clock_cells != Some(1) && node.power_cells != Some(1) { return None; }
    let shmem = shmem_reference(nodes, node, controller)?;
    let shmem_node = nodes.get(shmem)?;
    if !shmem_node.enabled || shmem_node.bad || !shmem_node.shmem_node { return None; }
    let (base_pa, size) = resource(nodes, shmem)?;
    if base_pa == 0 || size == 0 { return None; }
    if controller.controller == Controller::PageAndOffset && base_pa >= (1u64 << 44) { return None; }
    let completion_irq = completion_irq(nodes, node.parent?, controller)?;
    let mut cpu_domains = Vec::new();
    for cpu in 0..nodes.len() {
        let Some((cpu_mpidr, domain_id)) = cpu_domain(nodes, cpu, protocol) else { continue; };
        if cpu_domains.iter().any(|domain: &ScmiCpuDomain| domain.cpu_mpidr == cpu_mpidr) { return None; }
        cpu_domains.push(ScmiCpuDomain { cpu_mpidr, domain_id });
    }
    Some(ScmiPerfProtocol {
        protocol_phandle: node.phandle?, smc_id: controller.smc_id?,
        transport: match controller.controller { Controller::Direct => ScmiSmcTransport::Direct, Controller::PageAndOffset => ScmiSmcTransport::PageAndOffset, Controller::None => return None },
        completion_irq,
        shmem: ScmiSharedMemory { base_pa, size }, cpu_domains,
    })
}

fn protocol_id(nodes: &[Node], index: usize) -> Option<u32> {
    let node = nodes.get(index)?;
    let parent = node.parent?;
    if address_cells(nodes, parent)? != 1 || size_cells(nodes, parent)? != 0 { return None; }
    let reg = node.reg.as_deref()?;
    (reg.len() == 4).then(|| read_be_u32(reg, 0).ok()).flatten()
}

fn cpu_domain(nodes: &[Node], index: usize, protocol: usize) -> Option<(u64, u32)> {
    let node = nodes.get(index)?;
    let parent = node.parent?;
    if !node.enabled || node.bad || !nodes.get(parent)?.cpus || !(node.cpu_name || node.cpu_type) { return None; }
    let mpidr = cells(node.reg.as_deref()?, address_cells(nodes, parent)? )?;
    let selector = node.clocks.as_deref().and_then(|clocks| clock_ref(nodes, clocks)).or_else(|| {
        power_ref(nodes, node.power_domains.as_deref()?, node.power_domain_names.as_deref()?)
    })?;
    (selector.0 == protocol).then_some((mpidr, selector.1))
}

fn clock_ref(nodes: &[Node], data: &[u8]) -> Option<(usize, u32)> {
    let provider = unique(nodes, first_phandle(data)?)?;
    let cells = nodes.get(provider)?.clock_cells?;
    let count = usize::try_from(cells).ok()?;
    if count != 1 || data.len() < 8 { return None; }
    Some((provider, read_be_u32(data, 4).ok()?))
}

fn power_ref(nodes: &[Node], data: &[u8], names: &[u8]) -> Option<(usize, u32)> {
    let index = names.split(|byte| *byte == 0).position(|name| name == b"perf")?;
    let mut offset = 0usize;
    for current in 0..=index {
        let provider = unique(nodes, read_be_u32(data, offset).ok()?)?;
        let cells = usize::try_from(nodes.get(provider)?.power_cells?).ok()?;
        let length = cells.checked_add(1)?.checked_mul(4)?;
        if data.len().checked_sub(offset)? < length { return None; }
        if current == index {
            if cells != 1 { return None; }
            return Some((provider, read_be_u32(data, offset + 4).ok()?));
        }
        offset = offset.checked_add(length)?;
    }
    None
}

fn first_phandle(data: &[u8]) -> Option<u32> { read_be_u32(data, 0).ok().filter(|value| *value != 0) }

fn completion_irq(nodes: &[Node], controller_index: usize, controller: &Node) -> Option<Option<ScmiCompletionIrq>> {
    let Some(index) = controller.interrupt_names.as_deref().and_then(|names| names.split(|byte| *byte == 0).position(|name| name == b"a2p")) else {
        return Some(None);
    };
    if let Some(data) = controller.interrupts_extended.as_deref() {
        return extended_irq(nodes, data, index).map(Some);
    }
    let parent = interrupt_parent(nodes, controller_index)?;
    let cells = nodes.get(parent)?.interrupt_cells?;
    let cells = usize::try_from(cells).ok()?;
    let data = controller.interrupts.as_deref()?;
    let offset = index.checked_mul(cells)?.checked_mul(4)?;
    gic_irq(nodes, parent, data.get(offset..offset.checked_add(cells.checked_mul(4)?)?)?) .map(Some)
}

fn extended_irq(nodes: &[Node], data: &[u8], wanted: usize) -> Option<ScmiCompletionIrq> {
    let mut offset = 0usize;
    for index in 0..=wanted {
        let parent = unique(nodes, read_be_u32(data, offset).ok()?)?;
        offset = offset.checked_add(4)?;
        let cells = usize::try_from(nodes.get(parent)?.interrupt_cells?).ok()?;
        let bytes = cells.checked_mul(4)?;
        let spec = data.get(offset..offset.checked_add(bytes)?)?;
        if index == wanted { return gic_irq(nodes, parent, spec); }
        offset = offset.checked_add(bytes)?;
    }
    None
}

fn interrupt_parent(nodes: &[Node], mut index: usize) -> Option<usize> {
    loop {
        let node = nodes.get(index)?;
        if let Some(parent) = node.interrupt_parent.as_deref().and_then(first_phandle) { return unique(nodes, parent); }
        index = node.parent?;
    }
}

fn gic_irq(nodes: &[Node], parent: usize, spec: &[u8]) -> Option<ScmiCompletionIrq> {
    let parent = nodes.get(parent)?;
    if !parent.enabled || parent.bad || !parent.gic || parent.interrupt_cells != Some(3) || spec.len() != 12 { return None; }
    let kind = read_be_u32(spec, 0).ok()?;
    let hwirq = read_be_u32(spec, 4).ok()?;
    let flags = read_be_u32(spec, 8).ok()? & 0xf;
    let intid = match kind { 0 => 32u32.checked_add(hwirq)?, 1 => 16u32.checked_add(hwirq)?, _ => return None };
    let level = match flags { 1 | 2 => false, 4 | 8 => true, _ => return None };
    Some(ScmiCompletionIrq { intid, level })
}

fn shmem_reference(nodes: &[Node], protocol: &Node, controller: &Node) -> Option<usize> {
    if let Some(reference) = protocol.shmem.as_deref().and_then(first_phandle) {
        return unique(nodes, reference);
    }
    controller.shmem.as_deref().and_then(first_phandle).and_then(|reference| unique(nodes, reference))
}

fn unique(nodes: &[Node], phandle: u32) -> Option<usize> {
    let mut found = nodes.iter().enumerate().filter(|(_, node)| !node.bad && node.phandle == Some(phandle)).map(|(index, _)| index);
    let index = found.next()?;
    found.next().is_none().then_some(index)
}

fn resource(nodes: &[Node], index: usize) -> Option<(u64, u64)> {
    let node = nodes.get(index)?;
    let parent = node.parent?;
    let address = address_cells(nodes, parent)?;
    let size = size_cells(nodes, parent)?;
    let data = node.reg.as_deref()?;
    let address_bytes = usize::try_from(address).ok()?.checked_mul(4)?;
    let size_bytes = usize::try_from(size).ok()?.checked_mul(4)?;
    let base = cells(data, address)?;
    let length = cells(data.get(address_bytes..address_bytes.checked_add(size_bytes)?)?, size)?;
    let pa = translate(nodes, parent, base, length)?;
    Some((pa, length))
}

fn translate(nodes: &[Node], mut bus: usize, mut address: u64, size: u64) -> Option<u64> {
    loop {
        let parent = nodes.get(bus)?.parent;
        let Some(parent) = parent else { return Some(address); };
        let child_cells = address_cells(nodes, bus)?;
        let parent_cells = address_cells(nodes, parent)?;
        let size_cells = size_cells(nodes, bus)?;
        let ranges = nodes.get(bus)?.ranges.as_deref()?;
        if !ranges.is_empty() {
            let tuple = usize::try_from(child_cells.checked_add(parent_cells)?.checked_add(size_cells)?).ok()?.checked_mul(4)?;
            if tuple == 0 || ranges.len() % tuple != 0 { return None; }
            let mut found = None;
            for range in ranges.chunks_exact(tuple) {
                let child = cells(range, child_cells)?;
                let parent_address = cells(range.get(child_cells as usize * 4.. )?, parent_cells)?;
                let length_offset = usize::try_from(child_cells.checked_add(parent_cells)?).ok()?.checked_mul(4)?;
                let length = cells(range.get(length_offset.. )?, size_cells)?;
                let end = child.checked_add(length)?;
                let request_end = address.checked_add(size)?;
                if length != 0 && address >= child && request_end <= end {
                    found = parent_address.checked_add(address.checked_sub(child)?);
                    break;
                }
            }
            address = found?;
        }
        bus = parent;
    }
}

fn address_cells(nodes: &[Node], index: usize) -> Option<u32> {
    let node = nodes.get(index)?;
    node.address_cells.unwrap_or(2).try_into().ok().filter(|cells: &u32| (1..=2).contains(cells))
}

fn size_cells(nodes: &[Node], index: usize) -> Option<u32> {
    let node = nodes.get(index)?;
    node.size_cells.unwrap_or(1).try_into().ok().filter(|cells: &u32| *cells <= 2)
}

fn cells(data: &[u8], count: u32) -> Option<u64> {
    if !(1..=2).contains(&count) || data.len() < count as usize * 4 { return None; }
    let mut value = 0u64;
    for index in 0..count as usize { value = (value << 32) | u64::from(read_be_u32(data, index * 4).ok()?); }
    Some(value)
}

fn string(data: &[u8]) -> Option<&[u8]> { data.split(|byte| *byte == 0).next() }
