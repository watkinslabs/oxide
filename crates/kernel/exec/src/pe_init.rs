//! User-mode PE dependency initialization trampoline.

use alloc::{vec, vec::Vec};
use hal::UserVirtAddr;
use vmm::{AddressSpace, VmaBacking, VmaFlags, VmaProt};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PeInitTrampoline { pub base: UserVirtAddr, pub bytes: usize, pub entry: UserVirtAddr }

/// Build dependency-first TLS/DLL attach calls. TLS callbacks use the same
/// `(module_base, DLL_PROCESS_ATTACH, NULL)` ABI as a DLL entry point.
pub fn collect_initializers<'a>(loaded: &[super::pe_loader::PeLoadedModule<'a>], modules: &[pe::OwnedModule]) -> Result<Vec<super::pe_loader::PeModuleInitializer>, pe::Error> {
    let mut out = Vec::new();
    if loaded.len() != modules.len() || loaded.is_empty() { return Err(pe::Error::Einval); }
    let mut state = vec![0u8; modules.len()];
    collect_module_initializers(0, loaded, modules, &mut state, &mut out)?;
    Ok(out)
}

/// Walk the owned graph in dependency-postorder, the order used by the native
/// loader's recursive process-attach path. Discovery order is not sufficient:
/// an import table may list a dependent before the DLL it also depends on.
fn collect_module_initializers<'a>(index: usize,
    loaded: &[super::pe_loader::PeLoadedModule<'a>], modules: &[pe::OwnedModule],
    state: &mut [u8], out: &mut Vec<super::pe_loader::PeModuleInitializer>) -> Result<(), pe::Error> {
    if state[index] == 2 { return Ok(()); }
    if state[index] == 1 { return Ok(()); }
    state[index] = 1;
    let dependencies = pe::parse(&modules[index].blob)?.dependencies()?;
    for dependency in dependencies {
        let resolved = pe::apiset::target(dependency).unwrap_or(dependency);
        let Some(dep_index) = modules.iter().position(|module| ascii_eq(module.name.as_slice(), resolved)) else { continue };
        if dep_index != 0 { collect_module_initializers(dep_index, loaded, modules, state, out)?; }
    }
    let callbacks = pe::parse(&modules[index].blob)?.tls_callback_rvas()?;
    if index != 0 {
        for rva in callbacks { out.push(initializer(loaded[index].image.base, rva)?); }
        // PE encodes a DLL without DllMain as AddressOfEntryPoint == 0;
        // `PeLoadedImage::entry` is base + entry RVA, so compare against the
        // module base instead of testing the already-materialized address.
        if has_dll_entry(loaded[index].image.base, loaded[index].image.entry) {
            out.push(super::pe_loader::PeModuleInitializer { base: loaded[index].image.base, entry: loaded[index].image.entry });
        }
    } else {
        for rva in callbacks { out.push(initializer(loaded[index].image.base, rva)?); }
    }
    state[index] = 2;
    Ok(())
}

fn has_dll_entry(base: u64, entry: UserVirtAddr) -> bool { entry.as_u64() != base }

fn initializer(base: u64, rva: u32) -> Result<super::pe_loader::PeModuleInitializer, pe::Error> {
    Ok(super::pe_loader::PeModuleInitializer {
        base, entry: UserVirtAddr::new(base.checked_add(rva as u64).ok_or(pe::Error::Einval)?).ok_or(pe::Error::Einval)?,
    })
}

fn ascii_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(l, r)| l.to_ascii_lowercase() == r.to_ascii_lowercase())
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
        // home space plus one alignment slot before making the call. RBX is
        // preserved because it is nonvolatile across the Windows x64 ABI.
        code.extend_from_slice(&[0x53, 0x48, 0x83, 0xec, 0x28]);
        #[cfg(feature = "debug-faultdiag")]
        {
            code.extend_from_slice(&[0x48, 0xbf]);
            code.extend_from_slice(&initializer.base.to_le_bytes());
            code.extend_from_slice(&[0x48, 0xb8]);
            code.extend_from_slice(&syscall::nt::NtService::RelayProbe.entry().to_le_bytes());
            code.extend_from_slice(&[0x0f, 0x05]);
        }
        // A conforming DLL preserves R15, so this ABI-valid marker survives
        // the attach call and identifies the initializer in a fault dump.
        code.extend_from_slice(&[0x49, 0xbf]);
        code.extend_from_slice(&initializer.base.to_le_bytes());
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
    fn zero_address_of_entry_point_is_not_a_dll_initializer() {
        let base = 0x1800_0000;
        assert!(!has_dll_entry(base, UserVirtAddr::new(base).unwrap()));
        assert!(has_dll_entry(base, UserVirtAddr::new(base + 0x1000).unwrap()));
    }

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
        assert_eq!(&data[25..30], &[0xba, 1, 0, 0, 0]);
        assert_eq!(&data[43..45], &[0xff, 0xd0]);
        assert_eq!(&data[45..50], &[0x48, 0x83, 0xc4, 0x28, 0x5b]);
        assert_eq!(&data[50..54], &[0x48, 0x83, 0xec, 0x20]);
        assert_eq!(&data[54..56], &[0x48, 0xb8]);
        assert_eq!(&data[64..66], &[0xff, 0xd0]);
        assert_eq!(&data[66..69], &[0x48, 0x89, 0xc1]);
        assert_eq!(&data[79..81], &[0xff, 0xd0]);
        assert_eq!(&data[81..83], &[0x0f, 0x0b]);
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

    #[test]
    fn dll_initializer_uses_windows_x64_call_alignment() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let initializer = [super::super::pe_loader::PeModuleInitializer { base: 0x5000_0000, entry: UserVirtAddr::new(0x5000_1010).unwrap() }];
        let trampoline = map_with_exit(&as_, UserVirtAddr::new(0x6000_1010).unwrap(), &initializer, UserVirtAddr::new(0x7000_1010).unwrap()).unwrap();
        let vma = as_.find_vma(trampoline.base).unwrap();
        let data = match vma.backing { VmaBacking::KernelBytes { data, off } => (data, off), _ => panic!("initializer trampoline must be kernel-backed") };
        let bytes = &data.0[data.1..data.1 + trampoline.bytes];
        assert!(bytes.windows(4).any(|window| window == [0x48, 0x83, 0xec, 0x20]));
        assert!(bytes.windows(5).any(|window| window == [0x48, 0x83, 0xc4, 0x20, 0x5b]));
        assert!(!bytes.windows(4).any(|window| window == [0x48, 0x83, 0xec, 0x28]));
    }
}
