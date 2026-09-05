//! Hosted contracts spanning the native NT/Notepad compatibility boundary.
//!
//! These tests intentionally compose the production PE parser, NT ABI records,
//! object table, registry owner, path adapter, and user32 class registry. They
//! never invoke a kernel or depend on an installed Wine tree.

#[cfg(test)]
use elf_load::pe_loader::ImportResolver;
use pe::{parse, IMAGE_FILE_MACHINE_AMD64, IMAGE_NT_OPTIONAL_HDR64_MAGIC, SectionFlags};
use sched::nt_object::{NtObjectType, NtHandleTable};
use syscall::nt::{NtService, NtWindowMessage, NtWindowRect};
use syscall::nt_exec::{NtExecModule, NtExecRequest};
use syscall::nt_registry::{NtObjectAttributes, NtUnicodeString};
use windows_path::WindowsPath;
use windows_registry::{Registry, Root, Value, ValueType};
use windows_user32::{ClassRegistry, MenuItemInfoW, WM_CHAR, WM_KEYDOWN};

const OPT: usize = 0x98;
const SEC: usize = 0x188;

fn pe_fixture() -> Vec<u8> {
    let mut image = vec![0u8; 0x800];
    image[..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
    image[0x80..0x84].copy_from_slice(b"PE\0\0");
    image[0x84..0x86].copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
    image[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    image[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
    image[OPT..OPT + 2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR64_MAGIC.to_le_bytes());
    image[OPT + 16..OPT + 20].copy_from_slice(&0x1010u32.to_le_bytes());
    image[OPT + 24..OPT + 32].copy_from_slice(&0x1400_0000_0u64.to_le_bytes());
    image[OPT + 32..OPT + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    image[OPT + 36..OPT + 40].copy_from_slice(&0x200u32.to_le_bytes());
    image[OPT + 56..OPT + 60].copy_from_slice(&0x3000u32.to_le_bytes());
    image[OPT + 60..OPT + 64].copy_from_slice(&0x400u32.to_le_bytes());
    image[OPT + 108..OPT + 112].copy_from_slice(&16u32.to_le_bytes());
    image[SEC..SEC + 8].copy_from_slice(b".text\0\0\0");
    image[SEC + 8..SEC + 12].copy_from_slice(&0x200u32.to_le_bytes());
    image[SEC + 12..SEC + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    image[SEC + 16..SEC + 20].copy_from_slice(&0x200u32.to_le_bytes());
    image[SEC + 20..SEC + 24].copy_from_slice(&0x400u32.to_le_bytes());
    image[SEC + 36..SEC + 40].copy_from_slice(&(SectionFlags::MEM_READ | SectionFlags::MEM_EXECUTE).to_le_bytes());
    image[0x410] = 0xcc;
    image
}

fn launch_fixture() -> (std::path::PathBuf, std::path::PathBuf) {
    let base = std::env::temp_dir().join(format!("oxide-windows-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("fixture directory");
    let image = base.join("notepad.exe");
    std::fs::write(&image, pe_fixture()).expect("fixture image");
    (base, image)
}

#[cfg(test)]
struct NoImports;

#[cfg(test)]
impl ImportResolver for NoImports {
    fn resolve(&self, _dll: &[u8], _import: &pe::ImportThunk<'_>) -> Result<u64, pe::Error> { Err(pe::Error::Unsupported) }
}

/// Run the complete hosted contract suite. # C: O(1) plus fixture sizes
pub fn run() {
    let image = pe_fixture();
    let parsed = parse(&image).expect("AMD64 PE32+ fixture must be accepted");
    assert_eq!(parsed.entry_rva, 0x1010);
    assert_eq!(parsed.materialize().unwrap()[0x1010], 0xcc);
    assert_eq!(core::mem::size_of::<NtExecModule>(), 32);
    assert_eq!(core::mem::size_of::<NtExecRequest>(), 80);
    assert_eq!(core::mem::size_of::<NtObjectAttributes>(), 48);
    assert_eq!(core::mem::size_of::<NtUnicodeString>(), 16);
    assert_eq!(core::mem::size_of::<NtWindowMessage>(), 32);
    assert_eq!(core::mem::size_of::<NtWindowRect>(), 16);
    assert_eq!(core::mem::size_of::<MenuItemInfoW>(), 80);
    assert!(NtService::ExecuteWithCatalog.entry() >= syscall::nt::NT_SERVICE_NAMESPACE);
    assert!(NtService::CreateEvent.entry() > 0x100);
    assert_ne!(WM_KEYDOWN, WM_CHAR);

    let table = NtHandleTable::new();
    let event = table.insert(table.new_event(false, false), 1).unwrap();
    assert_eq!(table.get(event, 1).unwrap().kind(), NtObjectType::Event);
    let duplicate = table.duplicate(event, 1).unwrap();
    assert_eq!(table.handle_count(event), Some(2));
    assert_eq!(table.close_with_last(event), Some(false));
    assert_eq!(table.close_with_last(duplicate), Some(true));

    let path = WindowsPath::parse(r"C:\Windows\System32\notepad.exe").unwrap();
    assert_eq!(path.lookup_key(), "c:/windows/system32/notepad.exe");
    let mut registry = Registry::new();
    let key = registry.create_handle(Root::CurrentUser, r"Software\Oxide\Notepad").unwrap();
    registry.set_value_handle(key, "WindowTitle", Value { kind: ValueType::String, data: "Untitled - Notepad\0".encode_utf16().flat_map(u16::to_le_bytes).collect() }).unwrap();
    assert_eq!(registry.query_value_handle(key, "windowtitle").unwrap().kind, ValueType::String);
    assert_eq!(registry.path_for_handle(key).unwrap(), r"HKCU\Software\Oxide\Notepad");

    let mut classes = ClassRegistry::new();
    let name = "Notepad\0".encode_utf16().collect::<Vec<_>>();
    let atom = classes.register_class_ex_w(&name, 0x1400_1010).unwrap();
    assert_eq!(classes.atom(&name).unwrap(), atom);
    assert!(classes.register_class_ex_w(&name, 0x1400_2020).is_err());

    let (fixture_dir, image_path) = launch_fixture();
    let request = windows_runtime::RuntimeRequest::from_paths_with_environment(
        &image_path, b"C:\\Windows\\notepad.exe", b"notepad.exe", &fixture_dir,
        [(String::from("OXIDE_NT_PERSONALITY"), String::from("native"))],
    ).expect("owned launcher handoff");
    assert_eq!(request.module_count(), 0);
    assert_eq!(request.abi().module_count, 0);
    assert!(request.abi().image_len > 0);
    std::fs::remove_dir_all(fixture_dir).expect("fixture cleanup");
}

#[cfg(test)]
mod tests {
    use super::run;
    use super::NoImports;
    use elf_load::pe_loader::load_pe_process_with_resolver_and_modules_and_params_with_stack_bounds;
    use elf_load::process_env::EnvironmentInput;
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    use std::thread;
    use vmm::AddressSpace;
    use windows_registry::{serve_connection, Client, RegistryStore, Request, Response, Root, Value, ValueType};
    use windows_user32::{ClassError, User32};

    #[test]
    fn native_notepad_contract_is_wired_across_all_owned_boundaries() { run(); }

    #[test]
    fn registry_endpoint_preserves_the_same_key_and_value_contract_as_advapi() {
        let base = std::env::temp_dir().join(format!("oxide-windows-e2e-reg-{}", std::process::id()));
        let socket = base.with_extension("sock");
        let database = base.with_extension("db");
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_file(&database);
        let listener = UnixListener::bind(&socket).expect("registry endpoint");
        let (ready_tx, ready_rx) = mpsc::channel();
        let server_database = database.clone();
        let server = thread::spawn(move || {
            let mut store = RegistryStore::open(&server_database).expect("registry store");
            ready_tx.send(()).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            serve_connection(&mut stream, &mut store).unwrap();
        });
        ready_rx.recv().unwrap();
        let mut client = Client::connect(&socket).expect("registry client");
        let key = match client.execute(Request::Create { root: Root::CurrentUser, subkey: String::from("Software\\Oxide\\Notepad") }).unwrap() {
            Response::Handle(key) => key,
            response => panic!("unexpected registry response: {response:?}"),
        };
        assert_eq!(client.execute(Request::Set { key, name: String::from("WindowTitle"), value: Value { kind: ValueType::String, data: "Untitled - Notepad\0".encode_utf16().flat_map(u16::to_le_bytes).collect() } }).unwrap(), Response::Success);
        assert!(matches!(client.execute(Request::Query { key, name: String::from("windowtitle") }).unwrap(), Response::Value(_)));
        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(socket);
        let _ = std::fs::remove_file(database);
    }

    #[test]
    fn failed_host_window_handoff_does_not_mutate_the_class_lifecycle() {
        let mut classes = super::ClassRegistry::new();
        let name = "NotepadE2E\0".encode_utf16().collect::<Vec<_>>();
        let atom = classes.register_class_ex_w(&name, 0x1400_1010).unwrap();
        let result = classes.create_window_ex_w(&User32, &name, 0);
        assert!(matches!(result, Err(ClassError::Service(_))));
        assert_eq!(classes.atom(&name).unwrap(), atom);
        assert!(classes.unregister_class_w(&name).is_ok());
    }

    #[test]
    fn malformed_launch_rolls_back_every_vma_after_process_environment_failure() {
        let image = super::pe_fixture();
        let as_ = AddressSpace::new(0).expect("address space");
        let before = as_.vma_count();
        let input = EnvironmentInput { image_base: 0, image_size: 0, image_path: "C:\\notepad.exe", command_line: "notepad.exe", environment: &[("SystemRoot", "C:\\Windows")], process_id: 7, thread_id: 8 };
        let result = load_pe_process_with_resolver_and_modules_and_params_with_stack_bounds(&image, &as_, &input, 0, 0, &NoImports, &[], None);
        assert!(result.is_err(), "zero stack bound must fail before publication");
        assert_eq!(as_.vma_count(), before, "failed launch must remove image and environment mappings");
    }
}
