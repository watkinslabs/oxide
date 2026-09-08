//! Kernel-side admission of the REAL staged Wine Unix-side catalog.
//!
//! The fixtures are the shipped `x86_64-unix` objects, so a change to the
//! loader that stops admitting them fails here instead of at a boot.

use alloc::vec::Vec;
use super::{map_shared_object_with_resolver, admit_dependency_closure};
use crate::ARCH_MACHINE;
use vmm::AddressSpace;

/// Relocation classes the kernel's own ELF mapping contract applies. Anything
/// outside this set needs a runtime owner that can execute resolver code,
/// allocate a thread-pointer block, or run initializers: the host dynamic
/// loader in the process, never the kernel.
const KERNEL_OWNED: [u32; 4] = [elf::runtime_reloc::R_X86_64_64, elf::runtime_reloc::R_X86_64_GLOB_DAT,
    elf::runtime_reloc::R_X86_64_JUMP_SLOT, elf::runtime_reloc::R_X86_64_RELATIVE];

/// Wine Unix-side objects the runtime asks the kernel to publish by name.
const STAGED: [&str; 2] = ["win32u.so", "ntdll.so"];

fn catalog_dir() -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../target/artifacts/wine/x86_64/x86_64-unix");
    assert!(dir.is_dir(), "staged Wine Unix catalog missing at {}", dir.display());
    dir
}

fn staged(name: &str) -> Vec<u8> {
    let path = catalog_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("staged {} unreadable: {error}", path.display()))
}

/// The host objects a Unix-side Wine library names in `DT_NEEDED`; the process
/// dynamic loader owns these, so they are read from the running system.
fn host_object(name: &[u8]) -> Option<Vec<u8>> {
    let text = core::str::from_utf8(name).ok()?;
    let dir = catalog_dir();
    let candidates = [dir.join(text), std::path::PathBuf::from(alloc::format!("/lib64/{text}")),
        std::path::PathBuf::from(alloc::format!("/usr/lib64/{text}")),
        std::path::PathBuf::from(alloc::format!("/usr/lib/x86_64-linux-gnu/{text}"))];
    candidates.iter().find_map(|path| std::fs::read(path).ok())
}

#[test]
fn staged_wine_unixlibs_use_only_kernel_owned_relocation_classes() {
    let mut checked = 0;
    for name in STAGED {
        let file = staged(name);
        let object = elf::parse_shared_object(&file, ARCH_MACHINE).unwrap();
        let kinds = elf::runtime_relocation_kinds(&file, &object)
            .unwrap_or_else(|error| panic!("{name} relocation classes unreadable: {error:?}"));
        assert!(!kinds.is_empty(), "{name} declares no relocations");
        for kind in &kinds {
            assert!(KERNEL_OWNED.contains(kind), "{name} needs relocation class {kind} the kernel does not own");
        }
        checked += 1;
    }
    assert_eq!(checked, STAGED.len());
}

#[test]
fn staged_wine_unixlibs_map_when_their_host_imports_resolve() {
    let mut mapped = 0;
    for (index, name) in STAGED.iter().enumerate() {
        let file = staged(name);
        let as_ = AddressSpace::new(0xa_1000 + index as u64 * 0x1000).unwrap();
        // Every undefined symbol belongs to the host libraries the process
        // loader already published; a fixed in-image address stands in here.
        let image = map_shared_object_with_resolver(&file, &as_, |_| Some(0x1000))
            .unwrap_or_else(|error| panic!("{name} refused: {error:?}"));
        assert!(image.base < image.end, "{name} mapped an empty image");
        assert!(as_.vma_count() > 0, "{name} published no VMA");
        crate::elf_modules::clear(as_.root_pa());
        mapped += 1;
    }
    assert_eq!(mapped, STAGED.len());
}

#[test]
fn the_host_closure_of_a_staged_unixlib_is_not_kernel_ownable() {
    let root = staged("win32u.so");
    let scope = admit_dependency_closure(b"win32u.so", &root, host_object)
        .expect("win32u.so dependency closure is admissible");
    let mut host = 0;
    let mut refused = 0;
    for object in &scope {
        if STAGED.iter().any(|name| name.as_bytes() == object.name.as_slice()) { continue; }
        host += 1;
        let file = host_object(&object.name).expect("closure member was opened during admission");
        let parsed = elf::parse_dependency_object(&file, ARCH_MACHINE).unwrap();
        match elf::runtime_relocation_kinds(&file, &parsed) {
            Err(_) => refused += 1,
            Ok(kinds) => if kinds.iter().any(|kind| !KERNEL_OWNED.contains(kind)) { refused += 1; },
        }
    }
    assert!(host > 0, "win32u.so named no host library");
    // Every host library in the closure carries ifunc, thread-pointer, or
    // descriptor relocations. The kernel is not their loader: the Unix side is
    // opened by the process dynamic loader, which owns exactly that work.
    assert_eq!(refused, host, "a host closure member unexpectedly needs no runtime owner");
}
