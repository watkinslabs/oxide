//! User-mode PE dependency initialization trampoline.

use alloc::vec::Vec;
use hal::UserVirtAddr;
use vmm::{AddressSpace, VmaBacking, VmaFlags, VmaProt};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PeInitTrampoline { pub base: UserVirtAddr, pub bytes: usize, pub entry: UserVirtAddr }

/// Build dependency-first TLS/DLL attach calls. TLS callbacks use the same
/// `(module_base, DLL_PROCESS_ATTACH, NULL)` ABI as a DLL entry point.
pub fn collect_initializers<'a>(loaded: &[super::pe_loader::PeLoadedModule<'a>], modules: &[pe::OwnedModule]) -> Result<Vec<super::pe_loader::PeModuleInitializer>, pe::Error> {
    let mut out = Vec::new();
    for (index, module) in loaded.iter().enumerate().skip(1).rev() {
        let callbacks = pe::parse(&modules[index].blob)?.tls_callback_rvas()?;
        for rva in callbacks { out.push(super::pe_loader::PeModuleInitializer { base: module.image.base, entry: UserVirtAddr::new(module.image.base.checked_add(rva as u64).ok_or(pe::Error::Einval)?).ok_or(pe::Error::Einval)? }); }
        if module.image.entry.as_u64() != 0 { out.push(super::pe_loader::PeModuleInitializer { base: module.image.base, entry: module.image.entry }); }
    }
    let callbacks = pe::parse(&modules[0].blob)?.tls_callback_rvas()?;
    for rva in callbacks { out.push(super::pe_loader::PeModuleInitializer { base: loaded[0].image.base, entry: UserVirtAddr::new(loaded[0].image.base.checked_add(rva as u64).ok_or(pe::Error::Einval)?).ok_or(pe::Error::Einval)? }); }
    Ok(out)
}

/// Collect TLS callbacks for a root image that has no dependency graph.
pub fn collect_root_initializers(blob: &[u8], image: &super::pe_loader::PeLoadedImage) -> Result<Vec<super::pe_loader::PeModuleInitializer>, pe::Error> {
    let mut out = Vec::new();
    for rva in pe::parse(blob)?.tls_callback_rvas()? { out.push(super::pe_loader::PeModuleInitializer { base: image.base, entry: UserVirtAddr::new(image.base.checked_add(rva as u64).ok_or(pe::Error::Einval)?).ok_or(pe::Error::Einval)? }); }
    Ok(out)
}

/// Emit a Windows x64 caller that invokes each initializer with
/// `(module_base, DLL_PROCESS_ATTACH, NULL)` and then jumps to the image.
/// # C: O(N_initializers)
pub fn map(as_: &AddressSpace, app_entry: UserVirtAddr, initializers: &[super::pe_loader::PeModuleInitializer]) -> Result<Option<PeInitTrampoline>, pe::Error> {
    if initializers.is_empty() { return Ok(None); }
    let mut code = Vec::with_capacity(initializers.len() * 30 + 12);
    for initializer in initializers {
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&initializer.base.to_le_bytes());
        code.extend_from_slice(&[0xba, 1, 0, 0, 0, 0x45, 0x31, 0xc0, 0x48, 0xb8]);
        code.extend_from_slice(&initializer.entry.as_u64().to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0]);
    }
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&app_entry.as_u64().to_le_bytes());
    code.extend_from_slice(&[0xff, 0xe0]);
    let page = hal::PAGE_SIZE_BYTES as usize;
    let bytes = (code.len() + page - 1) / page * page;
    code.resize(bytes, 0xcc);
    let data = as_.stash_bytes(code.into_boxed_slice());
    let base = as_.mmap(None, bytes, VmaProt::READ | VmaProt::EXEC, VmaFlags::PRIVATE,
        VmaBacking::KernelBytes { data, off: 0 }, false).map_err(|_| pe::Error::Einval)?;
    let entry = UserVirtAddr::new(base.as_u64()).ok_or(pe::Error::Einval)?;
    Ok(Some(PeInitTrampoline { base, bytes, entry }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_process_attach_calls_then_application_jump() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let initializers = [super::super::pe_loader::PeModuleInitializer {
            base: 0x5000_0000, entry: UserVirtAddr::new(0x5000_1010).unwrap(),
        }];
        let trampoline = map(&as_, UserVirtAddr::new(0x6000_1010).unwrap(), &initializers).unwrap().unwrap();
        let vma = as_.find_vma(trampoline.base).unwrap();
        let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("trampoline must be kernel-backed") };
        assert_eq!(&data[..2], &[0x48, 0xb9]);
        assert_eq!(&data[10..15], &[0xba, 1, 0, 0, 0]);
        assert_eq!(&data[28..30], &[0xff, 0xd0]);
        assert_eq!(&data[30..32], &[0x48, 0xb8]);
        assert_eq!(&data[40..42], &[0xff, 0xe0]);
    }
}
