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
    let exit_entry = UserVirtAddr::new(0).ok_or(pe::Error::Einval)?;
    map_with_exit(as_, app_entry, initializers, exit_entry).map(Some)
}

/// Emit the process-start continuation used by a catalog-backed PE launch.
/// The application is called using the Windows x64 ABI; if it returns, its
/// return value is passed to the native `RtlExitUserProcess` entry instead of
/// falling through into unmapped user memory.
pub fn map_with_exit(as_: &AddressSpace, app_entry: UserVirtAddr,
    initializers: &[super::pe_loader::PeModuleInitializer], exit_entry: UserVirtAddr) -> Result<PeInitTrampoline, pe::Error> {
    let mut code = Vec::with_capacity(initializers.len() * 39 + 12);
    for initializer in initializers {
        // The process entry is reached by a jump, so there is no return
        // address on the stack yet. Preserve the one nonvolatile register
        // Wine's x64 DLL-entry wrapper protects, then reserve 32 bytes of
        // home space plus the alignment slot before making the call. RBX is
        // preserved because it is nonvolatile across the Windows x64 ABI.
        code.extend_from_slice(&[0x53, 0x48, 0x83, 0xec, 0x28]);
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&initializer.base.to_le_bytes());
        code.extend_from_slice(&[0xba, 1, 0, 0, 0, 0x45, 0x31, 0xc0, 0x48, 0xb8]);
        code.extend_from_slice(&initializer.entry.as_u64().to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0]);
        code.extend_from_slice(&[0x48, 0x83, 0xc4, 0x28, 0x5b]);
    }
    if exit_entry.as_u64() == 0 {
        // Preserve the legacy initializer-only helper used by the image-only
        // loader, whose caller owns process termination.
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&app_entry.as_u64().to_le_bytes());
        code.extend_from_slice(&[0xff, 0xe0]);
    } else {
        // The initial exec frame has no caller return address. Reserve the
        // required 32-byte home space, call the application, then preserve
        // its integer return value as RtlExitUserProcess's first argument.
        code.extend_from_slice(&[0x48, 0x83, 0xec, 0x20, 0x48, 0xb8]);
        code.extend_from_slice(&app_entry.as_u64().to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0x48, 0x89, 0xc1, 0x48, 0xb8]);
        code.extend_from_slice(&exit_entry.as_u64().to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0x0f, 0x0b]);
    }
    let page = hal::PAGE_SIZE_BYTES as usize;
    let bytes = (code.len() + page - 1) / page * page;
    code.resize(bytes, 0xcc);
    let data = as_.stash_bytes(code.into_boxed_slice());
    let base = as_.mmap(None, bytes, VmaProt::READ | VmaProt::EXEC, VmaFlags::PRIVATE,
        VmaBacking::KernelBytes { data, off: 0 }, false).map_err(|_| pe::Error::Einval)?;
    let entry = UserVirtAddr::new(base.as_u64()).ok_or(pe::Error::Einval)?;
    Ok(PeInitTrampoline { base, bytes, entry })
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
        let trampoline = map_with_exit(&as_, UserVirtAddr::new(0x6000_1010).unwrap(), &initializers, UserVirtAddr::new(0x7000_1010).unwrap()).unwrap();
        let vma = as_.find_vma(trampoline.base).unwrap();
        let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("trampoline must be kernel-backed") };
        assert_eq!(&data[..5], &[0x53, 0x48, 0x83, 0xec, 0x28]);
        assert_eq!(&data[15..20], &[0xba, 1, 0, 0, 0]);
        assert_eq!(&data[33..35], &[0xff, 0xd0]);
        assert_eq!(&data[35..40], &[0x48, 0x83, 0xc4, 0x28, 0x5b]);
        assert_eq!(&data[40..44], &[0x48, 0x83, 0xec, 0x20]);
        assert_eq!(&data[44..46], &[0x48, 0xb8]);
        assert_eq!(&data[54..56], &[0xff, 0xd0]);
        assert_eq!(&data[56..59], &[0x48, 0x89, 0xc1]);
        assert_eq!(&data[69..71], &[0xff, 0xd0]);
        assert_eq!(&data[71..73], &[0x0f, 0x0b]);
    }

    #[test]
    fn map_with_exit_creates_a_continuation_without_dll_initializers() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let trampoline = map_with_exit(&as_, UserVirtAddr::new(0x6000_1010).unwrap(), &[], UserVirtAddr::new(0x7000_1010).unwrap()).unwrap();
        let vma = as_.find_vma(trampoline.base).unwrap();
        let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("trampoline must be kernel-backed") };
        assert_eq!(&data[..4], &[0x48, 0x83, 0xec, 0x20]);
        assert_eq!(&data[0..4], &[0x48, 0x83, 0xec, 0x20]);
        assert_eq!(&data[14..16], &[0xff, 0xd0]);
        assert_eq!(&data[16..19], &[0x48, 0x89, 0xc1]);
        assert_eq!(&data[29..31], &[0xff, 0xd0]);
        assert_eq!(&data[31..33], &[0x0f, 0x0b]);
    }
}
