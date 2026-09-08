use super::*;
use vmm::{VmaBacking, VmaFlags, VmaProt};
use alloc::vec::Vec;

const CATALOG: &str = "target/artifacts/wine/x86_64/x86_64-windows";

fn staged(name: &str) -> Option<Vec<u8>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").join(CATALOG).join(name);
    if path.is_file() { std::fs::read(path).ok() } else { None }
}

fn input<'a>() -> process_env::EnvironmentInput<'a> {
    process_env::EnvironmentInput {
        image_base: 0, image_size: 0, image_path: "C:\\windows\\system32\\notepad.exe",
        command_line: "notepad.exe", environment: &[], process_id: 42, thread_id: 43,
    }
}

#[test]
fn the_runtime_module_publishes_the_initialization_entry_the_handover_needs() {
    let Some(blob) = staged("ntdll.dll") else { return };
    let parsed = pe::parse(&blob).expect("the staged runtime module must parse");
    let entry = runtime_init_entry(&parsed, 0x1_0000_0000).expect("the module must publish its initialization entry");
    // The entry is an address inside the mapped image, not the image base.
    assert!(entry.as_u64() > 0x1_0000_0000);
    assert!(entry.as_u64() < 0x1_0000_0000 + parsed.size_of_image as u64);
}

#[test]
fn the_handover_maps_two_images_and_enters_the_runtimes_initialization_thunk() {
    let _guard = crate::nt_ordinals::TABLE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let (Some(exe), Some(runtime_blob)) = (staged("notepad.exe"), staged("ntdll.dll")) else { return };
    let as_ = vmm::AddressSpace::new(0x100_000).expect("address space must initialize");
    let stack_bytes = 0x20_000usize;
    let stack = as_.mmap(None, stack_bytes, VmaProt::READ | VmaProt::WRITE, VmaFlags::PRIVATE,
        VmaBacking::Anonymous, false).expect("thread stack must map");
    let stack_base = stack.as_u64();
    let stack_top = stack_base + stack_bytes as u64;

    syscall::nt::ordinals::clear();
    let handover = load(&exe, &runtime_blob, &as_, &input(), stack_base, stack_top)
        .expect("the runtime handover must load");

    // Exactly two images: the executable and the runtime module. The graph the
    // executable imports is the runtime's business, not this kernel's.
    assert_ne!(handover.image.base, handover.runtime.base);
    assert_eq!(process_env::peb_image_base(&as_, &handover.environment), Some(handover.image.base));

    // The thread enters the runtime's initialization thunk, never the image
    // entry, and carries the startup context in the first argument register.
    let parsed = pe::parse(&runtime_blob).unwrap();
    let init = runtime_init_entry(&parsed, handover.runtime.base).unwrap();
    assert_eq!(handover.entry.rip, init);
    assert_ne!(handover.entry.rip, handover.image.entry);
    assert_eq!(handover.entry.rcx, handover.context.as_u64());
    assert_eq!(handover.entry.personality, ExecutionPersonality::Nt);

    // The context lives on the thread stack, in a writable mapping carrying
    // its own content, with the extent the thunk scrubs below it writable too
    // and inside the same stack. The address space being built is never the
    // active one, so the record cannot be written into it after the fact.
    let vma = as_.find_vma(handover.context).expect("the startup context must be mapped");
    assert!(vma.prot.contains(VmaProt::READ | VmaProt::WRITE));
    assert!(matches!(vma.backing, VmaBacking::KernelBytes { .. }), "the record is published with its content");
    assert!(vma.start.as_u64() >= stack_base && vma.end.as_u64() <= stack_top, "the record is on the stack");
    let placed = startup_stack::place(stack_base, stack_top).expect("the stack must carry a record");
    for probe in [placed.scrub_floor, placed.stack_pointer, placed.context] {
        let at = hal::UserVirtAddr::new(probe).expect("every probed stack address is canonical");
        let vma = as_.find_vma(at).expect("the scrubbed extent must be mapped");
        assert!(vma.prot.contains(VmaProt::READ | VmaProt::WRITE), "the runtime writes every byte of it");
    }
    assert_eq!(handover.context.as_u64(), placed.context);
    assert_eq!(handover.entry.rsp.as_u64(), placed.stack_pointer);
    assert!(placed.scrub_floor >= stack_base);
    let at64 = |field: usize| u64::from_le_bytes(handover.context_image[field..field + 8].try_into().unwrap());
    assert_eq!(at64(nt_context::CTX_RCX), handover.image.entry.as_u64());
    assert_eq!(at64(nt_context::CTX_RIP), handover.image.entry.as_u64());
    // The context resumes on the ordinary top-of-stack pointer, above the record.
    assert!(at64(nt_context::CTX_RSP) > placed.context);

    // The runtime owns the heap now: the block must not name one.
    assert_eq!(process_env::peb_process_heap(&as_, &handover.environment), Some(0));

    // And the module's numbering reached the entry table on the way through.
    assert!(syscall::nt::ordinals::installed());
    syscall::nt::ordinals::clear();
}

#[test]
fn a_catalog_without_the_runtime_module_cannot_hand_over() {
    let Some(exe) = staged("notepad.exe") else { return };
    let as_ = vmm::AddressSpace::new(0x100_000).expect("address space must initialize");
    assert!(load(&exe, b"not a PE image", &as_, &input(), 0, 0).is_err());
}


#[test]
fn the_runtime_module_exports_every_slot_the_kernel_must_fill() {
    let Some(blob) = staged("ntdll.dll") else { return };
    let parsed = pe::parse(&blob).expect("the staged runtime module must parse");
    let support = crate::pe_loader::nt_support::describe(0x7000_0000, None).unwrap();
    let slots = runtime_slots(&parsed, &support).expect("the module must export all three slots");
    assert_eq!(slots.len(), RUNTIME_SLOT_NAMES.len());
    // Distinct, non-zero RVAs inside the image; the handle slot follows the
    // Unix-call dispatcher slot, as the module declares them.
    for (rva, value) in slots {
        assert!(rva != 0 && (rva as u64) < parsed.size_of_image as u64);
        assert_ne!(value, 0);
    }
    assert_eq!(slots[0].1, support.wine_dispatcher);
    assert_eq!(slots[1].1, support.wine_unix_dispatcher);
    assert_eq!(slots[2].1, syscall::nt::WINE_UNIXLIB_HANDLE);
    assert!(slots.iter().map(|(rva, _)| *rva).collect::<alloc::collections::BTreeSet<_>>().len() == RUNTIME_SLOT_NAMES.len());
}

#[test]
fn the_handover_fills_the_runtime_modules_dispatcher_slots_in_the_mapped_image() {
    let _guard = crate::nt_ordinals::TABLE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let (Some(exe), Some(runtime_blob)) = (staged("notepad.exe"), staged("ntdll.dll")) else { return };
    let as_ = vmm::AddressSpace::new(0x100_100).expect("address space must initialize");
    let stack_bytes = 0x20_000usize;
    let stack = as_.mmap(None, stack_bytes, VmaProt::READ | VmaProt::WRITE, VmaFlags::PRIVATE,
        VmaBacking::Anonymous, false).expect("thread stack must map");
    syscall::nt::ordinals::clear();
    let handover = load(&exe, &runtime_blob, &as_, &input(), stack.as_u64(), stack.as_u64() + stack_bytes as u64)
        .expect("the runtime handover must load");
    let root = as_.root_pa();
    let support = crate::elf_modules::nt_support(root).expect("the handover must publish a support region");

    let parsed = pe::parse(&runtime_blob).unwrap();
    let read = |rva: u32| -> u64 {
        let address = hal::UserVirtAddr::new(handover.runtime.base + rva as u64).unwrap();
        let vma = as_.find_vma(address).expect("the slot must lie in a mapped image segment");
        let (data, base_off) = match vma.backing { VmaBacking::KernelBytes { data, off } => (data, off), _ => panic!("image must be kernel-backed") };
        let off = base_off as usize + (address.as_u64() - vma.start.as_u64()) as usize;
        u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
    };
    let slots = runtime_slots(&parsed, &support).unwrap();
    // The module loads each slot and calls or reads through it. Every one is
    // the address the kernel published, never the null the image ships with.
    assert_eq!(read(slots[0].0), support.wine_dispatcher);
    assert_eq!(read(slots[1].0), support.wine_unix_dispatcher);
    assert_eq!(read(slots[2].0), syscall::nt::WINE_UNIXLIB_HANDLE);

    // And the bootstrap handle names a registered table, so a call through the
    // published dispatcher is admitted rather than refused.
    let table = crate::elf_modules::unixlib_descriptor(root).expect("the Unix-call table must be registered");
    assert_eq!(table.table_address, support.table_address);
    assert!(table.entries.iter().all(|entry| *entry == support.wine_unix_dispatcher));

    // The support region is not the runtime module: nothing may resolve an
    // item by adding a block size to the module base.
    assert!(!crate::pe_loader::nt_support::is_synthetic_module(root, handover.runtime.base));
    crate::elf_modules::clear(root);
    syscall::nt::ordinals::clear();
}

#[test]
fn the_runtime_finds_its_own_module_handle_by_querying_its_text() {
    let _guard = crate::nt_ordinals::TABLE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let (Some(exe), Some(runtime_blob)) = (staged("notepad.exe"), staged("ntdll.dll")) else { return };
    let as_ = vmm::AddressSpace::new(0x100_200).expect("address space must initialize");
    let stack_bytes = 0x20_000usize;
    let stack = as_.mmap(None, stack_bytes, VmaProt::READ | VmaProt::WRITE, VmaFlags::PRIVATE,
        VmaBacking::Anonymous, false).expect("thread stack must map");
    syscall::nt::ordinals::clear();
    let handover = load(&exe, &runtime_blob, &as_, &input(), stack.as_u64(), stack.as_u64() + stack_bytes as u64)
        .expect("the runtime handover must load");

    // The module's own initialisation derives its module handle by querying
    // the address of its initialisation entry and taking the allocation base.
    // That entry is in the text section, a different fragment from the header
    // page, so a per-fragment answer hands the module an address carrying no
    // image header; it then reads a null header pointer.
    let init = handover.entry.rip;
    let init_vma = as_.find_vma(init).expect("the initialisation entry must be mapped");
    let header_vma = as_.find_vma(hal::UserVirtAddr::new(handover.runtime.base).unwrap()).unwrap();
    assert_ne!(init_vma.start, header_vma.start);
    assert!(init_vma.prot.contains(VmaProt::EXEC) && !header_vma.prot.contains(VmaProt::EXEC));

    let info = crate::nt_memory::query(&as_, init).expect("the query must find the mapped text");
    assert_eq!(info.allocation_base.as_u64(), handover.runtime.base);
    assert_ne!(info.base.as_u64(), handover.runtime.base);

    // The handle the query reports carries the image header, which is the
    // check the module performs before reading the optional header through it.
    let reported = as_.find_vma(info.allocation_base).expect("the reported handle must be mapped");
    let data = match reported.backing { VmaBacking::KernelBytes { data, off } => { assert_eq!(off, 0); data }, _ => panic!("image must be kernel-backed") };
    assert_eq!(&data[..2], b"MZ");

    // The executable answers for itself, not for the runtime.
    let exe_info = crate::nt_memory::query(&as_, handover.image.entry).unwrap();
    assert_eq!(exe_info.allocation_base.as_u64(), handover.image.base);
    assert_ne!(exe_info.allocation_base, info.allocation_base);
    crate::elf_modules::clear(as_.root_pa());
    syscall::nt::ordinals::clear();
}

/// The handover publishes both mapped images in the address space's PE
/// registry. That registry is what tells a service stub's syscall from a
/// Linux syscall issued by the native text sharing the address space, so a
/// handover that registered nothing made every caller in the process look
/// native — and, read the other way, made the personality alone decide.
#[test]
fn the_handover_publishes_both_images_in_the_pe_registry() {
    let _guard = crate::nt_ordinals::TABLE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let (Some(exe), Some(runtime_blob)) = (staged("notepad.exe"), staged("ntdll.dll")) else { return };
    let as_ = vmm::AddressSpace::new(0x100_400).expect("address space must initialize");
    let stack_bytes = 0x20_000usize;
    let stack = as_.mmap(None, stack_bytes, VmaProt::READ | VmaProt::WRITE, VmaFlags::PRIVATE,
        VmaBacking::Anonymous, false).expect("thread stack must map");
    syscall::nt::ordinals::clear();
    crate::pe_modules::clear(as_.root_pa());
    let handover = load(&exe, &runtime_blob, &as_, &input(), stack.as_u64(), stack.as_u64() + stack_bytes as u64)
        .expect("the runtime handover must load");

    let bases = crate::pe_modules::with_modules(as_.root_pa(),
        |modules| modules.iter().map(|module| module.base).collect::<Vec<_>>());
    assert_eq!(bases.len(), 2);
    assert!(bases.contains(&handover.image.base) && bases.contains(&handover.runtime.base));

    // Both entry points attribute to their own image; the thread stack, which
    // is where native code and its return addresses live, attributes to none.
    assert_eq!(crate::pe_modules::find(as_.root_pa(), handover.image.entry.as_u64()).map(|m| m.base),
        Some(handover.image.base));
    assert_eq!(crate::pe_modules::find(as_.root_pa(), handover.entry.rip.as_u64()).map(|m| m.base),
        Some(handover.runtime.base));
    assert!(crate::pe_modules::find(as_.root_pa(), stack.as_u64()).is_none());

    crate::pe_modules::clear(as_.root_pa());
    crate::elf_modules::clear(as_.root_pa());
    syscall::nt::ordinals::clear();
}
