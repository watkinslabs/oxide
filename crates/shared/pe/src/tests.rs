use super::*;
use alloc::{vec, vec::Vec};

mod robustness;

const OPT: usize = 0x98;
const SEC: usize = 0x188;

pub(crate) fn image() -> Vec<u8> {
    let mut b = vec![0u8; 0x800]; b[..2].copy_from_slice(b"MZ"); b[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0"); b[0x84..0x86].copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes()); b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); b[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
    b[OPT..OPT + 2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR64_MAGIC.to_le_bytes()); b[OPT + 16..OPT + 20].copy_from_slice(&0x1010u32.to_le_bytes()); b[OPT + 24..OPT + 32].copy_from_slice(&0x1000_0000u64.to_le_bytes()); b[OPT + 32..OPT + 36].copy_from_slice(&0x1000u32.to_le_bytes()); b[OPT + 36..OPT + 40].copy_from_slice(&0x200u32.to_le_bytes()); b[OPT + 56..OPT + 60].copy_from_slice(&0x3000u32.to_le_bytes()); b[OPT + 60..OPT + 64].copy_from_slice(&0x400u32.to_le_bytes()); b[OPT + 108..OPT + 112].copy_from_slice(&16u32.to_le_bytes());
    b[SEC..SEC + 8].copy_from_slice(b".text\0\0\0"); b[SEC + 8..SEC + 12].copy_from_slice(&0x200u32.to_le_bytes()); b[SEC + 12..SEC + 16].copy_from_slice(&0x1000u32.to_le_bytes()); b[SEC + 16..SEC + 20].copy_from_slice(&0x200u32.to_le_bytes()); b[SEC + 20..SEC + 24].copy_from_slice(&0x400u32.to_le_bytes()); b[SEC + 36..SEC + 40].copy_from_slice(&(SectionFlags::MEM_READ | SectionFlags::MEM_EXECUTE).to_le_bytes()); b[0x410] = 0xcc; b
}

pub(crate) fn imports_image(dependency: &[u8]) -> Vec<u8> {
    let mut b = image();
    let dir = OPT + 112 + IMAGE_DIRECTORY_ENTRY_IMPORT * 8;
    b[dir..dir + 4].copy_from_slice(&0x1100u32.to_le_bytes()); b[dir + 4..dir + 8].copy_from_slice(&40u32.to_le_bytes());
    b[0x50c..0x510].copy_from_slice(&0x1160u32.to_le_bytes()); b[0x510..0x514].copy_from_slice(&0x1180u32.to_le_bytes());
    let end = 0x560 + dependency.len(); b[0x560..end].copy_from_slice(dependency); b[end] = 0;
    b[0x580..0x588].copy_from_slice(&0u64.to_le_bytes());
    b
}

struct OneModule<'a> { name: &'a [u8], blob: &'a [u8] }
impl<'a> ModuleSource<'a> for OneModule<'a> {
    fn load(&self, name: &[u8]) -> Option<&'a [u8]> { if name.eq_ignore_ascii_case(self.name) { Some(self.blob) } else { None } }
}

#[test] fn parses_pe32_plus_and_materializes_sections() {
    let b = image(); let p = parse(&b).unwrap(); assert_eq!(p.entry_rva, 0x1010); assert_eq!(p.sections.len(), 1); assert_eq!(p.materialize().unwrap()[0x1010], 0xcc); assert_eq!(p.rva_range(0x1010, 1).unwrap(), &[0xcc]);
}

#[test] fn rejects_pe32_and_wx_sections() {
    let mut b = image(); b[OPT..OPT + 2].copy_from_slice(&0x10bu16.to_le_bytes()); assert_eq!(parse(&b).err(), Some(Error::Enoexec));
    let mut b = image(); b[SEC + 36..SEC + 40].copy_from_slice(&(SectionFlags::MEM_READ | SectionFlags::MEM_WRITE | SectionFlags::MEM_EXECUTE).to_le_bytes()); assert_eq!(parse(&b).err(), Some(Error::Einval));
}

#[test] fn rejects_entry_in_an_unmapped_image_gap() {
    let mut b = image(); b[OPT + 16..OPT + 20].copy_from_slice(&0x2000u32.to_le_bytes()); assert_eq!(parse(&b).err(), Some(Error::Einval));
}

#[test] fn applies_dir64_relocations_and_rejects_bad_type() {
    let mut b = image(); b[OPT + 112 + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8..OPT + 116 + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8].copy_from_slice(&0x2000u32.to_le_bytes()); b[OPT + 116 + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8..OPT + 120 + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8].copy_from_slice(&12u32.to_le_bytes());
    let p = parse(&b).unwrap(); let mut flat = p.materialize().unwrap(); flat[0x1010..0x1018].copy_from_slice(&0x1000_1010u64.to_le_bytes()); flat[0x2000..0x2004].copy_from_slice(&0x1000u32.to_le_bytes()); flat[0x2004..0x2008].copy_from_slice(&12u32.to_le_bytes()); flat[0x2008..0x200a].copy_from_slice(&(10u16 << 12 | 0x10).to_le_bytes()); flat[0x200a..0x200c].copy_from_slice(&0u16.to_le_bytes()); apply_relocations(&mut flat, &p, 0x1001_0000).unwrap(); assert_eq!(u64::from_le_bytes(flat[0x1010..0x1018].try_into().unwrap()), 0x1001_1010);
}

#[test] fn discovers_import_dll_names_from_directory() {
    let mut b = image();
    let dir = OPT + 112 + IMAGE_DIRECTORY_ENTRY_IMPORT * 8;
    b[dir..dir + 4].copy_from_slice(&0x1100u32.to_le_bytes()); b[dir + 4..dir + 8].copy_from_slice(&40u32.to_le_bytes());
    b[0x500 + 12..0x500 + 16].copy_from_slice(&0x1160u32.to_le_bytes()); b[0x500 + 16..0x500 + 20].copy_from_slice(&0x1180u32.to_le_bytes());
    b[0x560..0x56b].copy_from_slice(b"USER32.dll\0");
    b[0x580..0x588].copy_from_slice(&0x1190u64.to_le_bytes());
    b[0x590..0x592].copy_from_slice(&7u16.to_le_bytes()); b[0x592..0x59a].copy_from_slice(b"Message\0");
    let p = parse(&b).unwrap(); let imports = p.imports().unwrap(); assert_eq!(imports.len(), 1); assert_eq!(imports[0].name, b"USER32.dll"); assert_eq!(imports[0].first_thunk, 0x1180);
    assert_eq!(p.dependencies().unwrap(), vec![b"USER32.dll".as_slice()]);
    assert_eq!(p.import_thunks(&imports[0]).unwrap(), vec![ImportThunk::Name { hint: 7, name: b"Message" }]);
}

#[test]
fn discovers_transitive_modules_once_and_accepts_cycles() {
    let root = imports_image(b"dep.dll");
    let dep = imports_image(b"root.exe");
    let source = OneModule { name: b"dep.dll", blob: &dep };
    let modules = discover_modules(b"root.exe", &root, &source).unwrap();
    assert_eq!(modules.len(), 2);
    assert_eq!(modules[0].name, b"root.exe");
    assert_eq!(modules[1].name, b"dep.dll");
}

#[test]
fn api_set_dependencies_are_loaded_by_their_schema_host() {
    let root = imports_image(b"api-ms-win-core-file-l1-2-0.dll");
    let host = image();
    let source = OneModule { name: b"kernelbase.dll", blob: &host };
    let modules = discover_modules(b"root.exe", &root, &source).unwrap();
    assert_eq!(modules.len(), 2);
    assert_eq!(modules[1].name, b"kernelbase.dll");
}

#[test]
fn missing_dependency_fails_before_module_mapping() {
    let root = imports_image(b"missing.dll");
    let source = OneModule { name: b"other.dll", blob: &root };
    assert!(matches!(discover_modules(b"root.exe", &root, &source), Err(Error::Unsupported)));
}

#[test]
fn owned_dependency_graph_keeps_runtime_blobs_after_source_lifetime() {
    let root = imports_image(b"dep.dll");
    let dep = image();
    let source = OneModule { name: b"dep.dll", blob: &dep };
    let modules = discover_owned_modules(b"root.exe", &root, &source).unwrap();
    assert_eq!(modules.len(), 2);
    assert_eq!(modules[0].name, b"root.exe");
    assert_eq!(modules[1].name, b"dep.dll");
    assert_eq!(modules[1].blob, dep);
}

#[test]
fn owned_dependency_graph_can_exclude_runtime_bootstrap_modules() {
    let root = imports_image(b"ntdll.dll");
    let dependency = image();
    let source = OneModule { name: b"ntdll.dll", blob: &dependency };
    let modules = discover_owned_modules_with_builtins(b"root.exe", &root, &source, |name| name.eq_ignore_ascii_case(b"ntdll.dll")).unwrap();
    assert_eq!(modules.len(), 1);
    assert_eq!(modules[0].name, b"root.exe");
}

#[test]
fn resolves_named_and_ordinal_exports_to_rvas() {
    let mut b = image();
    let dir = OPT + 112 + IMAGE_DIRECTORY_ENTRY_EXPORT * 8;
    b[dir..dir + 4].copy_from_slice(&0x1100u32.to_le_bytes()); b[dir + 4..dir + 8].copy_from_slice(&40u32.to_le_bytes());
    b[0x500 + 12..0x500 + 16].copy_from_slice(&0x1160u32.to_le_bytes());
    b[0x500 + 16..0x500 + 20].copy_from_slice(&1u32.to_le_bytes());
    b[0x500 + 20..0x500 + 24].copy_from_slice(&1u32.to_le_bytes());
    b[0x500 + 24..0x500 + 28].copy_from_slice(&1u32.to_le_bytes());
    b[0x500 + 28..0x500 + 32].copy_from_slice(&0x1130u32.to_le_bytes());
    b[0x500 + 32..0x500 + 36].copy_from_slice(&0x1134u32.to_le_bytes());
    b[0x500 + 36..0x500 + 40].copy_from_slice(&0x1138u32.to_le_bytes());
    b[0x530..0x534].copy_from_slice(&0x1010u32.to_le_bytes());
    b[0x534..0x538].copy_from_slice(&0x1170u32.to_le_bytes());
    b[0x538..0x53a].copy_from_slice(&0u16.to_le_bytes());
    b[0x560..0x56a].copy_from_slice(b"module.dll");
    b[0x570..0x577].copy_from_slice(b"Message");
    let p = parse(&b).unwrap();
    assert_eq!(p.export_rva(&ImportThunk::Name { hint: 0, name: b"Message" }).unwrap(), Some(0x1010));
    assert_eq!(p.export_rva(&ImportThunk::Ordinal(1)).unwrap(), Some(0x1010));
    assert_eq!(p.export_rva(&ImportThunk::Name { hint: 0, name: b"Missing" }).unwrap(), None);
    let mut forwarded = b;
    forwarded[0x530..0x534].copy_from_slice(&0x1110u32.to_le_bytes());
    let p = parse(&forwarded).unwrap();
    assert_eq!(p.export_rva(&ImportThunk::Ordinal(1)), Err(Error::Unsupported));
}

#[test]
fn decodes_image_relative_tls_callbacks() {
    let mut b = image();
    let dir = OPT + 112 + IMAGE_DIRECTORY_ENTRY_TLS * 8;
    b[dir..dir + 4].copy_from_slice(&0x1100u32.to_le_bytes()); b[dir + 4..dir + 8].copy_from_slice(&40u32.to_le_bytes());
    b[0x500 + 24..0x500 + 32].copy_from_slice(&(0x1000_0000u64 + 0x1150).to_le_bytes());
    b[0x550..0x558].copy_from_slice(&(0x1000_0000u64 + 0x1010).to_le_bytes());
    let p = parse(&b).unwrap();
    assert_eq!(p.tls_callback_rvas().unwrap(), vec![0x1010]);
    b[0x550..0x558].copy_from_slice(&(0x1000_0000u64 + 0x3000).to_le_bytes());
    assert_eq!(parse(&b).unwrap().tls_callback_rvas(), Err(Error::Einval));
}

#[test]
fn parses_wine_x86_64_notepad_when_installed() {
    let Ok(b) = std::fs::read("/usr/lib64/wine/x86_64-windows/notepad.exe") else { return };
    let p = parse(&b).expect("Wine's 64-bit notepad must satisfy the PE32+ contract");
    assert!(p.entry_rva != 0);
    assert!(!p.imports().unwrap().is_empty());
    let _ = p.exports().unwrap();
    let _ = p.tls().unwrap();
    let _ = p.exception_functions().unwrap();
    assert_eq!(p.dependencies().unwrap(), vec![
        b"advapi32.dll".as_slice(), b"comctl32.dll", b"comdlg32.dll",
        b"gdi32.dll", b"kernel32.dll", b"shell32.dll", b"shlwapi.dll",
        b"ucrtbase.dll", b"user32.dll",
    ]);
}

#[test]
fn locates_the_wine_x64_relay_descriptor_when_installed() {
    let Ok(b) = std::fs::read("/usr/lib64/wine/x86_64-windows/advapi32.dll") else { return };
    let parsed = parse(&b).expect("installed Wine advapi32 must parse");
    assert_eq!(parsed.relay_descriptor_rva().unwrap(), Some(0x24000));
    let import = ImportThunk::Name { hint: 0, name: b"ReadEventLogW" };
    assert_eq!(parsed.export_rva(&import).unwrap(), Some(0x19c90));
    assert_eq!(parsed.relay_export_rva(&import).unwrap(), Some(0x4c1c));
    let relays = parsed.relay_export_rvas().unwrap().unwrap();
    assert_eq!(relays[394], 0x4c1c);
    assert_eq!(relays[395], 0x4c48);
    let image = parsed.materialize().unwrap();
    assert_eq!(&image[0x24000..0x24008], &[0x02, 0x00, 0xb9, 0xde, 0, 0, 0, 0]);
}

#[test]
fn preserves_wine_ntdll_no_relay_exports_when_installed() {
    let Ok(b) = std::fs::read("/usr/lib64/wine/x86_64-windows/ntdll.dll") else { return };
    let parsed = parse(&b).expect("installed Wine ntdll must parse");
    let relays = parsed.relay_export_rvas().unwrap().unwrap();
    assert_eq!(relays[1292], 0, "_memicmp is -norelay in the installed x64 surface");
    assert_eq!(relays[1293], 0, "_setjmp is -norelay in the installed x64 surface");
    assert_eq!(relays[1294], 0, "_setjmpex is -norelay in the installed x64 surface");
    assert_eq!(parsed.export_rvas().unwrap().unwrap()[1293], 0x10bf8);
}

#[test]
fn locates_and_decodes_x64_runtime_function_unwind_info() {
    let mut b = image();
    let dir = OPT + 112 + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8;
    b[dir..dir + 4].copy_from_slice(&0x1100u32.to_le_bytes()); b[dir + 4..dir + 8].copy_from_slice(&12u32.to_le_bytes());
    b[0x500..0x504].copy_from_slice(&0x1000u32.to_le_bytes()); b[0x504..0x508].copy_from_slice(&0x1050u32.to_le_bytes()); b[0x508..0x50c].copy_from_slice(&0x11f0u32.to_le_bytes());
    b[0x5f0..0x5f4].copy_from_slice(&[1, 5, 1, 0]); b[0x5f4..0x5f6].copy_from_slice(&[4, 0]);
    let parsed = parse(&b).unwrap(); let function = parsed.exception_function_for(0x1020).unwrap().unwrap();
    assert_eq!(function, RuntimeFunction { begin_rva: 0x1000, end_rva: 0x1050, unwind_rva: 0x11f0 });
    assert_eq!(parsed.unwind_info(function).unwrap().codes, vec![UnwindCode { code_offset: 4, unwind_op: 0, op_info: 0 }]);
    assert_eq!(parsed.unwind_stack_allocation(function).unwrap(), 8);
    b[0x5f5] = 0x32;
    let parsed = parse(&b).unwrap(); let function = parsed.exception_function_for(0x1020).unwrap().unwrap();
    assert_eq!(parsed.unwind_stack_allocation(function).unwrap(), 32);
    assert_eq!(parsed.exception_function_for(0x1050).unwrap(), None);
    drop(parsed);
    b[0x5f5] = 0x37;
    assert_eq!(parse(&b).unwrap().unwind_stack_allocation(function), Err(Error::Unsupported));
    let mut malformed = b.clone(); malformed[0x500..0x504].copy_from_slice(&0x1060u32.to_le_bytes());
    assert_eq!(parse(&malformed).unwrap().exception_functions(), Err(Error::Einval));
}

#[test]
fn rejects_exception_tables_that_are_not_sorted_or_have_truncated_unwind_data() {
    let mut b = image();
    let dir = OPT + 112 + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8;
    b[dir..dir + 4].copy_from_slice(&0x1100u32.to_le_bytes()); b[dir + 4..dir + 8].copy_from_slice(&24u32.to_le_bytes());
    b[0x500..0x50c].copy_from_slice(&[0x00, 0x10, 0, 0, 0x50, 0x10, 0, 0, 0xf0, 0x11, 0, 0]);
    b[0x50c..0x518].copy_from_slice(&[0x40, 0x10, 0, 0, 0x60, 0x10, 0, 0, 0xf0, 0x11, 0, 0]);
    assert_eq!(parse(&b).unwrap().exception_functions(), Err(Error::Einval));
    let mut truncated = image();
    let dir = OPT + 112 + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8;
    truncated[dir..dir + 4].copy_from_slice(&0x1100u32.to_le_bytes()); truncated[dir + 4..dir + 8].copy_from_slice(&12u32.to_le_bytes());
    truncated[0x500..0x50c].copy_from_slice(&[0x00, 0x10, 0, 0, 0x50, 0x10, 0, 0, 0xff, 0x2f, 0, 0]);
    assert_eq!(parse(&truncated).unwrap().exception_functions(), Err(Error::Einval));
}

#[test]
fn unwinds_x64_saved_register_and_return_address_through_reader() {
    let mut b = image();
    let dir = OPT + 112 + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8;
    b[dir..dir + 4].copy_from_slice(&0x1100u32.to_le_bytes()); b[dir + 4..dir + 8].copy_from_slice(&12u32.to_le_bytes());
    b[0x500..0x504].copy_from_slice(&0x1000u32.to_le_bytes()); b[0x504..0x508].copy_from_slice(&0x1060u32.to_le_bytes()); b[0x508..0x50c].copy_from_slice(&0x11f0u32.to_le_bytes());
    // The unwind stream reverses: allocate 32 bytes, then pop the saved RBP.
    b[0x5f0..0x5f4].copy_from_slice(&[1, 2, 2, 0]); b[0x5f4..0x5f8].copy_from_slice(&[1, 0x32, 2, 0x50]);
    let parsed = parse(&b).unwrap(); let function = parsed.exception_function_for(0x1040).unwrap();
    let context = UnwindContext { regs: [0; 16], rip: 0x1040, rsp: 0x8000 };
    let result = parsed.unwind_x64(function, 0x1040, context, |address| match address {
        0x8020 => Ok(0x1111), 0x8028 => Ok(0x2222), _ => Err(Error::Einval),
    }).unwrap();
    assert_eq!(result.regs[5], 0x1111);
    assert_eq!(result.rip, 0x2222); assert_eq!(result.rsp, 0x8030);
}

#[test]
fn leaf_unwind_reads_return_address_and_rejects_xmm_restore_until_context_exists() {
    let blob = image(); let parsed = parse(&blob).unwrap();
    let context = UnwindContext { regs: [0; 16], rip: 7, rsp: 0x9000 };
    let result = parsed.unwind_x64(None, 0, context, |address| if address == 0x9000 { Ok(0x1234) } else { Err(Error::Einval) }).unwrap();
    assert_eq!(result.rip, 0x1234); assert_eq!(result.rsp, 0x9008);
    let mut b = image(); let dir = OPT + 112 + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8;
    b[dir..dir + 4].copy_from_slice(&0x1100u32.to_le_bytes()); b[dir + 4..dir + 8].copy_from_slice(&12u32.to_le_bytes());
    b[0x500..0x504].copy_from_slice(&0x1000u32.to_le_bytes()); b[0x504..0x508].copy_from_slice(&0x1060u32.to_le_bytes()); b[0x508..0x50c].copy_from_slice(&0x11f0u32.to_le_bytes());
    b[0x5f0..0x5f4].copy_from_slice(&[1, 1, 1, 0]); b[0x5f4..0x5f6].copy_from_slice(&[1, 8]);
    let parsed = parse(&b).unwrap(); let function = parsed.exception_function_for(0x1040).unwrap();
    assert_eq!(parsed.unwind_x64(function, 0x1040, context, |_| Ok(0)), Err(Error::Unsupported));
}

#[test]
fn audits_wine_notepad_dependency_contract_when_installed() {
    let Some(root) = ["/usr/lib64/wine/x86_64-windows", "/usr/lib/wine/x86_64-windows"]
        .iter().find(|root| std::path::Path::new(root).join("notepad.exe").is_file()) else { return };
    let notepad = std::fs::read(std::path::Path::new(root).join("notepad.exe")).unwrap();
    let image = parse(&notepad).expect("installed Wine Notepad must parse");
    let dependencies = image.dependencies().unwrap();
    assert!(dependencies.len() >= 5);
    for dependency in dependencies {
        let path = std::path::Path::new(root).join(std::str::from_utf8(dependency).unwrap());
        let blob = std::fs::read(&path).unwrap_or_else(|_| panic!("missing Notepad dependency {}", path.display()));
        let module = parse(&blob).unwrap_or_else(|_| panic!("invalid PE dependency {}", path.display()));
        assert!(module.exports().unwrap().is_some(), "dependency has no export directory");
        assert!(!module.dependencies().unwrap().iter().any(|name| name.is_empty()));
    }
}

#[test]
fn installed_wine_notepad_graph_is_closed_and_case_unique() {
    let Some(root) = ["/usr/lib64/wine/x86_64-windows", "/usr/lib/wine/x86_64-windows"]
        .iter().find(|root| std::path::Path::new(root).join("notepad.exe").is_file()) else { return };
    let notepad = std::fs::read(std::path::Path::new(root).join("notepad.exe")).unwrap();
    let mut catalog = crate::catalog::ModuleCatalog::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|value| value.to_str()) != Some("dll") { continue; }
        let name = path.file_name().unwrap().to_str().unwrap().as_bytes().to_vec();
        catalog.add(&name, &std::fs::read(path).unwrap()).unwrap();
    }
    let source = &catalog;
    let modules = discover_modules(b"notepad.exe", &notepad, &source).unwrap();
    for (index, module) in modules.iter().enumerate() {
        assert!(!modules[..index].iter().any(|previous| previous.name.eq_ignore_ascii_case(module.name)), "duplicate graph node");
        for dependency in module.image.dependencies().unwrap() {
            let name = crate::apiset::target(dependency).unwrap_or(dependency);
            assert!(modules.iter().any(|candidate| candidate.name.eq_ignore_ascii_case(name)), "unclosed dependency graph");
        }
    }
}

#[test]
fn resolves_wine_ntdll_export_when_installed() {
    let Ok(b) = std::fs::read("/usr/lib/wine/x86_64-windows/ntdll.dll") else { return };
    let p = parse(&b).expect("Wine's ntdll must satisfy the PE32+ contract");
    assert!(p.export_rva(&ImportThunk::Name { hint: 0, name: b"NtClose" }).unwrap().is_some());
}
