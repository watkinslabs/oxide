use super::*;
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
    let stack_bytes = 0x10_000usize;
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

    // The context is user-writable: the thunk rewrites the entry field before
    // resuming on it.
    let vma = as_.find_vma(handover.context).expect("the startup context must be mapped");
    assert!(vma.prot.contains(VmaProt::READ | VmaProt::WRITE));
    let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("context must be kernel-backed") };
    let off = (handover.context.as_u64() - vma.start.as_u64()) as usize;
    let at64 = |field: usize| u64::from_le_bytes(data[off + field..off + field + 8].try_into().unwrap());
    assert_eq!(at64(nt_context::CTX_RCX), handover.image.entry.as_u64());
    assert_eq!(at64(nt_context::CTX_RIP), handover.image.entry.as_u64());
    assert_eq!(at64(nt_context::CTX_RSP), handover.entry.rsp.as_u64());

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

