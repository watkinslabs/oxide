use elf_load::vdso::map_into;
use hal::UserVirtAddr;
use vmm::{AddressSpace, VmaBacking, VmaProt};

const X86: &[u8] = include_bytes!("../../vdso/vdso-x86_64.so");
const ARM: &[u8] = include_bytes!("../../vdso/vdso-aarch64.so");
const PAGE: usize = hal::PAGE_SIZE_BYTES as usize;

fn mapped_image_keeps_metadata(blob: &[u8], machine: u16) {
    let mm = AddressSpace::new(0).unwrap();
    let base = map_into(&mm, blob, machine, PAGE as u64).unwrap();
    let image = mm.find_vma(UserVirtAddr::new(base).unwrap()).unwrap();
    assert_eq!(image.start.as_u64(), base);
    assert_eq!(image.prot, VmaProt::READ | VmaProt::EXEC);
    let (data, offset) = match &image.backing {
        VmaBacking::KernelBytes { data, off } => (data, *off as usize),
        _ => panic!("vDSO must retain its image bytes"),
    };
    let bytes = &data[offset..];
    for name in [".text", ".dynsym", ".dynstr", ".shstrtab"] {
        let original = elf::find_section(blob, name).unwrap().unwrap();
        assert_eq!(elf::find_section(bytes, name), Ok(Some(original)),
            "mapped ELF section metadata must remain readable");
    }
    assert_eq!(bytes, blob, "complete image, including section names and headers");
    let rounded = (blob.len() + PAGE - 1) & !(PAGE - 1);
    assert_eq!(image.end.as_u64(), base + rounded as u64);
    assert_eq!(mm.vdso_range(), (base - PAGE as u64, base + rounded as u64));
    let vvar = mm.find_vma(UserVirtAddr::new(base - PAGE as u64).unwrap()).unwrap();
    assert_eq!(vvar.prot, VmaProt::READ);
    assert!(matches!(vvar.backing, VmaBacking::KernelFrame { pa } if pa == PAGE as u64));
    assert_eq!(mm.vma_count(), 2);
}

#[test]
fn x86_mapping_keeps_elf_metadata() { mapped_image_keeps_metadata(X86, elf::EM_X86_64); }

#[test]
fn arm_mapping_keeps_elf_metadata() { mapped_image_keeps_metadata(ARM, elf::EM_AARCH64); }

#[test]
fn metadata_beyond_the_load_page_is_mapped_and_reserved() {
    let mut blob = X86.to_vec();
    let old = u64::from_le_bytes(blob[40..48].try_into().unwrap()) as usize;
    let headers = blob[old..].to_vec();
    blob.resize(PAGE + headers.len(), 0);
    blob[PAGE..].copy_from_slice(&headers);
    blob[40..48].copy_from_slice(&(PAGE as u64).to_le_bytes());
    mapped_image_keeps_metadata(&blob, elf::EM_X86_64);
}

#[test]
fn unsupported_image_layout_is_refused_before_mapping() {
    let ph = u64::from_le_bytes(X86[32..40].try_into().unwrap()) as usize;
    for (offset, bytes) in [
        (ph + 16, (PAGE as u64).to_le_bytes().to_vec()),
        (ph + 40, (PAGE as u64).to_le_bytes().to_vec()),
        (ph + 4, elf::PFlags::R.bits().to_le_bytes().to_vec()),
        (16, (elf::ElfType::Exec as u16).to_le_bytes().to_vec()),
    ] {
        let mut blob = X86.to_vec();
        blob[offset..offset + bytes.len()].copy_from_slice(&bytes);
        let mm = AddressSpace::new(0).unwrap();
        assert_eq!(map_into(&mm, &blob, elf::EM_X86_64, PAGE as u64), None);
        assert_eq!(mm.vma_count(), 0);
        assert_eq!(mm.vdso_range(), (0, 0));
    }
}

#[test]
fn missing_data_page_does_not_publish_an_image() {
    let mm = AddressSpace::new(0).unwrap();
    assert_eq!(map_into(&mm, X86, elf::EM_X86_64, 0), None);
    assert_eq!(mm.vma_count(), 0);
}
