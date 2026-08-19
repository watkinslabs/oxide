//! Device-tree CPU topology publication.

/// Publish the enabled `/cpus` nodes when ACPI did not already provide a
/// topology. The boot PE must occur in that list: accepting a tree that
/// cannot name the executing CPU would make the logical CPU zero a guess.
/// # C: O(FDT + N²)
pub fn init_cpu_topology(boot_mpidr: u64) -> bool {
    if cpu::populated() { return cpu::logical_id_for_hardware(boot_mpidr).is_some(); }
    let Some(blob) = super::blob() else { return false; };
    let mut ids = [0u64; cpu::MAX_CPUS];
    let count = ::fdt::enum_cpus(blob, &mut ids);
    if count == 0 || count > ids.len() { return false; }
    let ids = &ids[..count];
    if !valid_cpu_ids(ids, boot_mpidr) { return false; }
    for (logical, id) in ids.iter().copied().enumerate() {
        // SAFETY: the DT was retained and decoded on the single-CPU boot path;
        // `valid_cpu_ids` proved the complete bounded list is non-aliased.
        if !unsafe { cpu::add_cpu(id, cpu::FLAG_ENABLED, logical as u32) } { return false; }
    }
    true
}

fn valid_cpu_ids(ids: &[u64], boot_mpidr: u64) -> bool {
    if ids.is_empty() || ids.len() > cpu::MAX_CPUS || !ids.contains(&boot_mpidr) { return false; }
    for (index, id) in ids.iter().enumerate() {
        if *id == u64::MAX || ids[..index].contains(id) { return false; }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::valid_cpu_ids;

    #[test]
    fn requires_an_unambiguous_boot_cpu() {
        assert!(valid_cpu_ids(&[0, 0x1_0000_0002], 0x1_0000_0002));
        assert!(!valid_cpu_ids(&[0, 0], 0));
        assert!(!valid_cpu_ids(&[0, 1], 2));
    }
}
