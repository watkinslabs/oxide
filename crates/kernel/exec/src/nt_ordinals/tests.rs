use super::*;
use alloc::vec::Vec;
use alloc::string::String;
use pe::ntdll::services::DecodedService;

/// The module the image stages, which is the only numbering the guest can use.
const STAGED: &str = "target/artifacts/wine/x86_64/x86_64-windows/ntdll.dll";

fn staged() -> Option<Vec<u8>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").join(STAGED);
    if path.is_file() { std::fs::read(path).ok() } else { None }
}

#[test]
fn a_decoded_name_the_kernel_publishes_pairs_with_its_service_and_one_it_does_not_is_reported() {
    let decoded = [
        DecodedService { name: b"NtReadFile", ordinal: 6, flag_address: 0x7ffe_0308 },
        DecodedService { name: b"NtNotAServiceThisKernelPublishes", ordinal: 7, flag_address: 0x7ffe_0308 },
    ];
    let paired: Vec<_> = pairs(&decoded).collect();
    assert_eq!(paired, [(6u32, syscall::nt::NtService::ReadFile)]);
    assert_eq!(unpublished(&decoded), [b"NtNotAServiceThisKernelPublishes".as_slice()]);
    // The alternate entry point is the same service under a second name.
    assert_eq!(service_for_stub_name(b"ZwReadFile"), Some(syscall::nt::NtService::ReadFile));
    assert_eq!(service_for_stub_name(b"ZwNotAServiceEither"), None);
}

#[test]
fn the_staged_module_numbering_routes_its_own_stubs_to_the_services_the_kernel_publishes() {
    let _guard = TABLE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(blob) = staged() else { return };
    let image = pe::parse(&blob).expect("the staged runtime module must parse");
    let decoded = pe::ntdll::services::decode_all(&image).expect("its service stubs must decode");
    assert!(decoded.len() > 400, "decoded {} service stubs", decoded.len());

    // Every stub the module ships tests the same flag byte, and the kernel
    // leaves that byte zero, so every one of them takes the architectural
    // syscall leg into this kernel rather than a user-mode dispatcher.
    let flag = decoded[0].flag_address;
    assert!(decoded.iter().all(|service| service.flag_address == flag));
    assert!(pe::ntdll::stub::takes_architectural_entry(0));

    // The numbering is the module's, not this tree's: read it back rather than
    // asserting a transcribed number.
    let read_file = decoded.iter().find(|service| service.name == b"NtReadFile").expect("the module must number NtReadFile");
    let paired: Vec<_> = pairs(&decoded).collect();
    assert!(paired.contains(&(read_file.ordinal, syscall::nt::NtService::ReadFile)));

    syscall::nt::ordinals::clear();
    let numbering = install_from_image(&image).expect("the staged numbering must install");
    assert_eq!(numbering.decoded, decoded.len());
    assert_eq!(numbering.numbers, numbering.installed + numbering.unpublished);
    assert!(numbering.numbers > 250, "the module carries {} service numbers", numbering.numbers);
    // Measured against the staged 11.16 module: the kernel answers well over
    // half its numbering, and every number it does not answer is a call this
    // kernel must refuse rather than mistake for a Linux syscall.
    assert!(numbering.installed > 150, "installed {} service numbers", numbering.installed);
    assert!(numbering.unpublished > 0);

    let args = syscall::SyscallArgs { a0: 0, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 };
    let call = syscall::nt::ordinals::call_for_ordinal(read_file.ordinal, args).expect("the read ordinal must route");
    assert_eq!(call.service, syscall::nt::NtService::ReadFile);
    // The hazard this route exists to remove: the bare ordinal is also a Linux
    // syscall number, and it must not mean that Linux call.
    assert!(read_file.ordinal < 0x1000);
    syscall::nt::ordinals::clear();
}

#[test]
#[ignore]
fn report_the_staged_numbering() {
    let Some(blob) = staged() else { return };
    let image = pe::parse(&blob).unwrap();
    let decoded = pe::ntdll::services::decode_all(&image).unwrap();
    let un: Vec<_> = unpublished(&decoded).into_iter().map(|n| String::from_utf8_lossy(n).into_owned()).collect();
    std::println!("decoded={} numbers={} paired={} unpublished={}", decoded.len(), numbers(&decoded), pairs(&decoded).count(), un.len());
    std::println!("max ordinal={:?}", decoded.iter().map(|s| s.ordinal).max());
    std::println!("unpublished: {:?}", un);
}

/// The installed numbering is one global table, so every test that touches it
/// runs under this lock rather than racing a sibling's `clear`.
static TABLE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn the_process_loader_installs_the_staged_module_numbering_when_the_catalog_carries_it() {
    let _guard = TABLE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
        .join("target/artifacts/wine/x86_64/x86_64-windows");
    if !root.join("ntdll.dll").is_file() { return; }
    let ntdll = std::fs::read(root.join("ntdll.dll")).expect("the staged runtime module must be readable");
    let notepad = std::fs::read(root.join("notepad.exe")).expect("the staged root module must be readable");
    let mut catalog = pe::catalog::ModuleCatalog::new();
    catalog.add(b"ntdll.dll", &ntdll).expect("the staged runtime module must satisfy the catalog contract");

    syscall::nt::ordinals::clear();
    assert!(!syscall::nt::ordinals::installed(), "control: nothing is installed before the loader runs");

    let as_ = vmm::AddressSpace::new(0x100_000).expect("address space must initialize");
    let runtime = crate::pe_loader::map_nt_runtime(&as_).expect("the synthetic runtime page must map");
    // The graph load itself is not what this proves: the numbering is a fact
    // about the module and is installed whether or not the graph maps.
    let _ = crate::pe_loader::load_pe_process_with_catalog(&notepad, &as_, &crate::process_env::EnvironmentInput {
        image_base: 0, image_size: 0, image_path: "C:\\notepad.exe", command_line: "notepad.exe",
        environment: &[], process_id: 42, thread_id: 43,
    }, 0x7000_0000, &runtime, &catalog);

    assert!(syscall::nt::ordinals::installed(), "the loader must install the shipped numbering");
    assert!(syscall::nt::ordinals::filled() > 150, "filled {}", syscall::nt::ordinals::filled());
    syscall::nt::ordinals::clear();
}
