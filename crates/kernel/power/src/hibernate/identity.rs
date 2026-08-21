//! Canonical hibernation compatibility identity.

use crypt::Sha256;

use super::format::Header;
use super::restore::Compatibility;

/// Persistent architecture selector for x86-64 images.
pub const ARCH_X86_64: u32 = 1;
/// Persistent architecture selector for AArch64 images.
pub const ARCH_AARCH64: u32 = 2;

fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update(&(bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

fn build_digest(linked_id: &[u8], sysname: &[u8], release: &[u8], version: &[u8],
                version_code: u32) -> [u8; 32] {
    let mut hash = Sha256::new();
    field(&mut hash, b"oxide-hibernate-build-v1");
    field(&mut hash, linked_id);
    field(&mut hash, sysname);
    field(&mut hash, release);
    field(&mut hash, version);
    hash.update(&version_code.to_le_bytes());
    hash.finish()
}

#[cfg(target_os = "oxide-kernel")]
fn linked_build_digest() -> [u8; 32] {
    unsafe extern "C" {
        static __build_id_start: u8;
        static __build_id_end: u8;
    }
    fn bytes(start: *const u8, end: *const u8) -> &'static [u8] {
        let len = (end as usize).saturating_sub(start as usize);
        // SAFETY: the kernel linker exports ordered bounds around its retained
        // read-only GNU build-id note, which remains mapped for the whole boot.
        unsafe { core::slice::from_raw_parts(start, len) }
    }
    build_digest(bytes(core::ptr::addr_of!(__build_id_start),
        core::ptr::addr_of!(__build_id_end)), syscall::uts::UTS_SYSNAME.as_bytes(),
        syscall::uts::UTS_RELEASE.as_bytes(), syscall::uts::UTS_VERSION.as_bytes(),
        syscall::uts::LINUX_VERSION_CODE)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn linked_build_digest() -> [u8; 32] {
    build_digest(b"hosted-build-id", syscall::uts::UTS_SYSNAME.as_bytes(),
        syscall::uts::UTS_RELEASE.as_bytes(), syscall::uts::UTS_VERSION.as_bytes(),
        syscall::uts::LINUX_VERSION_CODE)
}

fn identity_kind(kind: u8) -> u8 {
    use boot_info::BootMemKind;
    match kind {
        k if k == BootMemKind::BootloaderUsed as u8
            || k == BootMemKind::KernelImage as u8
            || k == BootMemKind::Initramfs as u8 => BootMemKind::Usable as u8,
        k => k,
    }
}

fn topology_count<I>(regions: I) -> usize
where I: IntoIterator<Item = (u64, u64, u8)>
{
    let mut count = 0usize;
    let mut previous: Option<(u64, u8)> = None;
    for (start, end, kind) in regions {
        let kind = identity_kind(kind);
        if matches!(previous, Some((previous_end, previous_kind))
            if previous_end == start && previous_kind == kind) {
            previous = Some((end, kind));
        } else {
            count += 1;
            previous = Some((end, kind));
        }
    }
    count
}

fn topology_digest<I>(regions: I) -> [u8; 32]
where I: Clone + IntoIterator<Item = (u64, u64, u8)>
{
    let mut hash = Sha256::new();
    field(&mut hash, b"oxide-hibernate-topology-v1");
    hash.update(&(topology_count(regions.clone()) as u64).to_le_bytes());
    let mut pending: Option<(u64, u64, u8)> = None;
    for (start, end, kind) in regions {
        let kind = identity_kind(kind);
        match pending {
            Some((saved_start, saved_end, saved_kind))
                if saved_end == start && saved_kind == kind =>
                pending = Some((saved_start, end, kind)),
            Some((saved_start, saved_end, saved_kind)) => {
                hash.update(&saved_start.to_le_bytes());
                hash.update(&saved_end.to_le_bytes());
                hash.update(&[saved_kind]);
                pending = Some((start, end, kind));
            }
            None => pending = Some((start, end, kind)),
        }
    }
    if let Some((start, end, kind)) = pending {
        hash.update(&start.to_le_bytes());
        hash.update(&end.to_le_bytes());
        hash.update(&[kind]);
    }
    hash.finish()
}

fn cpu_digest<I>(arch: u32, signature: &[u8], boot_id: u64, online: u32,
                 count: usize, topology: I) -> [u8; 32]
where I: IntoIterator<Item = (u64, u32)>
{
    let mut hash = Sha256::new();
    field(&mut hash, b"oxide-hibernate-cpu-v1");
    hash.update(&arch.to_le_bytes());
    field(&mut hash, signature);
    hash.update(&boot_id.to_le_bytes());
    hash.update(&online.to_le_bytes());
    hash.update(&(count as u32).to_le_bytes());
    for (hardware_id, flags) in topology {
        hash.update(&hardware_id.to_le_bytes());
        hash.update(&flags.to_le_bytes());
    }
    hash.finish()
}

fn current_arch() -> u32 {
    #[cfg(target_arch = "x86_64")]
    { ARCH_X86_64 }
    #[cfg(target_arch = "aarch64")]
    { ARCH_AARCH64 }
}

fn current_cpu_signature() -> [u8; 24] {
    let mut out = [0u8; 24];
    #[cfg(target_arch = "x86_64")]
    {
        out[..12].copy_from_slice(&hal_x86_64::cpuid_vendor());
        let (family, model, stepping) = hal_x86_64::cpuid_family_model();
        out[12..16].copy_from_slice(&family.to_le_bytes());
        out[16..20].copy_from_slice(&model.to_le_bytes());
        out[20..24].copy_from_slice(&stepping.to_le_bytes());
    }
    #[cfg(target_arch = "aarch64")]
    { out[..8].copy_from_slice(&hal_aarch64::midr_el1().to_le_bytes()); }
    out
}

/// Derive the current identity from the existing canonical subsystem owners.
/// # C: O(memory regions + CPUs)
pub fn current() -> Compatibility {
    let arch = current_arch();
    let build_id = linked_build_digest();

    let regions = pmm::setup::memory_topology();
    for (index, region) in regions.iter().enumerate() {
        super::log::topology_region(index, region.start.0, region.end.0,
            region.kind as u8);
    }
    let topology_id = topology_digest(regions.iter().map(|region|
        (region.start.0, region.end.0, region.kind as u8)));

    let count = cpu::count() as usize;
    let online = cpu::smp::online_count();
    let cpu_id = cpu_digest(arch, &current_cpu_signature(), cpu::smp::boot_cpu_id(),
        online, count, (0..count).filter_map(cpu::get));

    Compatibility {
        arch, cpu_count: online,
        hardware_sig: firmware::acpi::facs().map(|f| f.hardware_signature).unwrap_or(0),
        build_id, topology_id, cpu_id,
    }
}

/// Stamp the writer header from the same identity restore will compare.
/// # C: O(memory regions + CPUs)
pub fn stamp(header: &mut Header) -> Compatibility {
    let identity = current();
    header.arch = identity.arch;
    header.cpu_count = identity.cpu_count;
    header.hardware_sig = identity.hardware_sig;
    header.build_id = identity.build_id;
    header.topology_id = identity.topology_id;
    header.cpu_id = identity.cpu_id;
    identity
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_build_field_participates_in_the_identity() {
        let base = build_digest(b"linked-a", b"Linux", b"6.19.0-oxide", b"build-a", 1);
        assert_ne!(base, build_digest(b"linked-b", b"Linux", b"6.19.0-oxide", b"build-a", 1));
        assert_ne!(base, build_digest(b"linked-a", b"Other", b"6.19.0-oxide", b"build-a", 1));
        assert_ne!(base, build_digest(b"linked-a", b"Linux", b"6.20.0-oxide", b"build-a", 1));
        assert_ne!(base, build_digest(b"linked-a", b"Linux", b"6.19.0-oxide", b"build-b", 1));
        assert_ne!(base, build_digest(b"linked-a", b"Linux", b"6.19.0-oxide", b"build-a", 2));
    }

    #[test]
    fn topology_order_bounds_and_kind_are_admission_identity() {
        let map = [(1, 4, 0), (8, 9, 2)];
        assert_ne!(topology_digest(map), topology_digest([(1, 5, 0), (8, 9, 2)]));
        assert_ne!(topology_digest(map), topology_digest([(1, 4, 1), (8, 9, 2)]));
        assert_ne!(topology_digest(map), topology_digest([(8, 9, 2), (1, 4, 0)]));
    }

    #[test]
    fn transient_boot_owner_placement_is_not_machine_topology() {
        use boot_info::BootMemKind;
        let first = [(0x40000, 0xb67dd, BootMemKind::Usable as u8),
            (0xb67dd, 0xbc188, BootMemKind::KernelImage as u8),
            (0xbc188, 0xbe952, BootMemKind::Usable as u8)];
        let second = [(0x40000, 0xb67db, BootMemKind::Usable as u8),
            (0xb67db, 0xbc186, BootMemKind::KernelImage as u8),
            (0xbc186, 0xbe952, BootMemKind::Usable as u8)];
        assert_eq!(topology_digest(first), topology_digest(second));
    }

    #[test]
    fn cpu_signature_smp_count_boot_cpu_and_topology_all_participate() {
        let cpus = [(0x10, cpu::FLAG_ENABLED), (0x20, cpu::FLAG_ENABLED)];
        let base = cpu_digest(ARCH_X86_64, b"signature", 0x10, 2, 2, cpus);
        assert_ne!(base, cpu_digest(ARCH_AARCH64, b"signature", 0x10, 2, 2, cpus));
        assert_ne!(base, cpu_digest(ARCH_X86_64, b"other", 0x10, 2, 2, cpus));
        assert_ne!(base, cpu_digest(ARCH_X86_64, b"signature", 0x20, 2, 2, cpus));
        assert_ne!(base, cpu_digest(ARCH_X86_64, b"signature", 0x10, 1, 2, cpus));
        assert_ne!(base, cpu_digest(ARCH_X86_64, b"signature", 0x10, 2, 1, cpus[..1].iter().copied()));
    }

    #[test]
    fn writer_stamp_is_admitted_by_the_same_current_owner() {
        let mut header = Header { flags: 0, checksum: 0, first_map: 0,
            image_pages: 0, zero_pages: 0, stream_pages: 0, arch: 0,
            cpu_count: 0, hardware_sig: 0, build_id: [0; 32],
            topology_id: [0; 32], cpu_id: [0; 32], arch_data: [0; 128],
            original_sig: [0; 10] };
        let expected = stamp(&mut header);
        assert_eq!(super::super::restore::validate_compatibility(&header, &expected), Ok(()));
    }
}
