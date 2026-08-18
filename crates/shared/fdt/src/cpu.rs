//! CPU-node enumeration from the device tree.

use crate::header::read_be_u32;
use crate::walk::{walk, Event, Flow};

/// One CPU node's architected hardware identity and firmware availability.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CpuNode { pub mpidr: u64, pub enabled: bool }

/// Enumerate direct `/cpus` CPU children into `out`, returning the total
/// number found. A CPU node may identify itself by `device_type = "cpu"` or
/// by its conventional `cpu`/`cpu@…` node name. `reg` uses `/cpus`
/// `#address-cells`, defaulting to the FDT value of two. # C: O(struct_block_size)
pub fn cpu_nodes(bytes: &[u8], out: &mut [CpuNode]) -> usize {
    let mut cpus_depth = None;
    let mut address_cells = 2u32;
    let mut candidate_depth = None;
    let mut candidate_name = false;
    let mut candidate_type = false;
    let mut candidate_enabled = true;
    let mut candidate_mpidr = None;
    let mut count = 0usize;
    if walk(bytes, |event| {
        match event {
            Event::BeginNode { name, depth } => {
                if depth == 1 && name == b"cpus" { cpus_depth = Some(depth); }
                else if cpus_depth.is_some_and(|parent| depth == parent + 1) {
                    candidate_depth = Some(depth);
                    candidate_name = name == b"cpu" || name.starts_with(b"cpu@");
                    candidate_type = false;
                    candidate_enabled = true;
                    candidate_mpidr = None;
                }
            }
            Event::Prop { name, data, depth } => {
                if cpus_depth == Some(depth) && name == b"#address-cells" {
                    address_cells = read_be_u32(data, 0).ok().filter(|cells| (1..=2).contains(cells)).unwrap_or(0);
                }
                if candidate_depth == Some(depth) {
                    match name {
                        b"device_type" => candidate_type = data.split(|byte| *byte == 0).next() == Some(b"cpu"),
                        b"status" => candidate_enabled = matches!(data.split(|byte| *byte == 0).next(), Some(b"ok" | b"okay")),
                        b"reg" => candidate_mpidr = read_cells(data, address_cells),
                        _ => {}
                    }
                }
            }
            Event::EndNode { depth } => {
                if candidate_depth == Some(depth) {
                    if (candidate_name || candidate_type) && candidate_mpidr.is_some() {
                        if count < out.len() { out[count] = CpuNode { mpidr: candidate_mpidr.unwrap_or(0), enabled: candidate_enabled }; }
                        count += 1;
                    }
                    candidate_depth = None;
                }
                if cpus_depth == Some(depth) { cpus_depth = None; }
            }
        }
        Flow::Continue
    }).is_err() { return 0; }
    count
}

fn read_cells(data: &[u8], cells: u32) -> Option<u64> {
    if !(1..=2).contains(&cells) || data.len() < cells as usize * 4 { return None; }
    let mut value = 0u64;
    for cell in 0..cells as usize { value = (value << 32) | u64::from(read_be_u32(data, cell * 4).ok()?); }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::Fdt;

    #[test]
    fn cpu_nodes_keep_full_mpidr_and_disabled_state() {
        let mut fdt = Fdt::new();
        fdt.begin("").begin("cpus").prop_u32("#address-cells", 2).prop_u32("#size-cells", 0)
            .begin("cpu@102")
            .prop("reg", &0x0000_0001_0000_0002u64.to_be_bytes())
            .end()
            .begin("cpu@3").prop("device_type", b"cpu\0").prop("reg", &3u64.to_be_bytes()).prop_str("status", "disabled").end()
            .end().end();
        let mut nodes = [CpuNode { mpidr: 0, enabled: false }; 2];
        assert_eq!(cpu_nodes(&fdt.finish(), &mut nodes), 2);
        assert_eq!(nodes[0], CpuNode { mpidr: 0x0000_0001_0000_0002, enabled: true });
        assert_eq!(nodes[1], CpuNode { mpidr: 3, enabled: false });
    }
}
