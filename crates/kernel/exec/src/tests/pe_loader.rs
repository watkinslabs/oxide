
    use super::*;
    use alloc::{vec, vec::Vec};
    use core::cell::RefCell;

    struct TracingNtRuntime<'a> { runtime: &'a NtRuntime, missing: RefCell<Option<(Vec<u8>, Vec<u8>)>> }
    impl ImportResolver for TracingNtRuntime<'_> {
        fn resolve(&self, dll: &[u8], import: &pe::ImportThunk<'_>) -> Result<u64, pe::Error> {
            let result = self.runtime.resolve(dll, import);
            if result.is_err() && self.missing.borrow().is_none() {
                let name = match import { pe::ImportThunk::Name { name, .. } => name.to_vec(), pe::ImportThunk::Ordinal(value) => value.to_le_bytes().to_vec() };
                *self.missing.borrow_mut() = Some((dll.to_vec(), name));
            }
            result
        }
    }

    fn tiny_pe() -> alloc::vec::Vec<u8> {
        let mut b = vec![0u8; 0x600]; b[..2].copy_from_slice(b"MZ"); b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes()); b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); b[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        let o = 0x98; b[o..o + 2].copy_from_slice(&0x20bu16.to_le_bytes()); b[o + 16..o + 20].copy_from_slice(&0x1010u32.to_le_bytes()); b[o + 24..o + 32].copy_from_slice(&0x1000_0000u64.to_le_bytes()); b[o + 32..o + 36].copy_from_slice(&0x1000u32.to_le_bytes()); b[o + 36..o + 40].copy_from_slice(&0x200u32.to_le_bytes()); b[o + 56..o + 60].copy_from_slice(&0x3000u32.to_le_bytes()); b[o + 60..o + 64].copy_from_slice(&0x400u32.to_le_bytes());
        let s = 0x188; b[s..s + 8].copy_from_slice(b".text\0\0\0"); b[s + 8..s + 12].copy_from_slice(&0x200u32.to_le_bytes()); b[s + 12..s + 16].copy_from_slice(&0x1000u32.to_le_bytes()); b[s + 16..s + 20].copy_from_slice(&0x200u32.to_le_bytes()); b[s + 20..s + 24].copy_from_slice(&0x400u32.to_le_bytes()); b[s + 36..s + 40].copy_from_slice(&(0x6000_0020u32).to_le_bytes()); b[0x410] = 0xcc; b
    }

    #[test]
    fn installed_wine_notepad_graph_reports_missing_native_ntdll_surface() {
        let roots = [
            "/usr/lib64/wine/x86_64-windows",
            "/usr/lib/wine/x86_64-windows",
        ];
        let Some(root) = roots.iter().find(|root| std::path::Path::new(root).join("notepad.exe").is_file()) else { return };
        let notepad_path = std::path::Path::new(root).join("notepad.exe");
        let notepad = std::fs::read(&notepad_path).expect("installed Wine Notepad must be readable");
        let mut catalog = pe::catalog::ModuleCatalog::new();
        for entry in std::fs::read_dir(root).expect("Wine DLL directory must be readable") {
            let path = entry.expect("Wine DLL directory entry must be readable").path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("dll") { continue; }
            let name = path.file_name().and_then(|name| name.to_str()).expect("Wine DLL name must be UTF-8");
            if name.eq_ignore_ascii_case("ntdll.dll") { continue; }
            let blob = std::fs::read(&path).expect("Wine DLL must be readable");
            catalog.add(name.as_bytes(), &blob).expect("Wine DLL must satisfy the PE catalog contract");
        }
        let as_ = AddressSpace::new(0x100_000).expect("Notepad integration address space must initialize");
        let runtime = map_nt_runtime(&as_).expect("native NTDLL runtime must map");
        let tracing_runtime = TracingNtRuntime { runtime: &runtime, missing: RefCell::new(None) };
        let result = load_pe_process_with_catalog_with_fallback(&notepad, &as_, &process_env::EnvironmentInput {
            image_base: 0, image_size: 0, image_path: "C:\\notepad.exe", command_line: "notepad.exe",
            environment: &[], process_id: 42, thread_id: 43,
        }, 0x7000_0000, &runtime, &tracing_runtime, &catalog);
        // The production launcher excludes Wine ntdll.dll. This fixture must
        // stay honest until each NTDLL import used by the graph has a native
        // implementation; a mapped Wine copy must not mask that gap.
        assert!(matches!(result, Err(pe::Error::Unsupported)));
        let missing = tracing_runtime.missing.into_inner().expect("the negative-control graph must identify its first unresolved import");
        std::eprintln!("Notepad graph first unresolved import: {}!{}", std::string::String::from_utf8_lossy(&missing.0), std::string::String::from_utf8_lossy(&missing.1));
        assert_eq!(as_.vma_count(), 1, "only the native NTDLL page survives rollback");
    }

    fn imported_pe() -> alloc::vec::Vec<u8> {
        let mut b = tiny_pe();
        b.resize(0x800, 0);
        b[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        b[0x98 + 56..0x98 + 60].copy_from_slice(&0x4000u32.to_le_bytes());
        b[0x98 + 108..0x98 + 112].copy_from_slice(&16u32.to_le_bytes());
        let dir = 0x98 + 112 + pe::IMAGE_DIRECTORY_ENTRY_IMPORT * 8;
        b[dir..dir + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        b[dir + 4..dir + 8].copy_from_slice(&40u32.to_le_bytes());
        let s = 0x188 + 40;
        b[s..s + 8].copy_from_slice(b".idata\0\0");
        b[s + 8..s + 12].copy_from_slice(&0x200u32.to_le_bytes());
        b[s + 12..s + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        b[s + 16..s + 20].copy_from_slice(&0x200u32.to_le_bytes());
        b[s + 20..s + 24].copy_from_slice(&0x500u32.to_le_bytes());
        b[s + 36..s + 40].copy_from_slice(&0xc000_0040u32.to_le_bytes());
        let d = 0x500;
        b[d..d + 4].copy_from_slice(&0x2080u32.to_le_bytes());
        b[d + 12..d + 16].copy_from_slice(&0x2060u32.to_le_bytes());
        b[d + 16..d + 20].copy_from_slice(&0x2090u32.to_le_bytes());
        b[0x560..0x569].copy_from_slice(b"ntdll.dll");
        b[0x580..0x588].copy_from_slice(&0x20a0u64.to_le_bytes());
        b[0x590..0x598].copy_from_slice(&0u64.to_le_bytes());
        b[0x5a0..0x5a2].copy_from_slice(&7u16.to_le_bytes());
        b[0x5a2..0x5a9].copy_from_slice(b"NtClose");
        b
    }

    fn exported_pe() -> alloc::vec::Vec<u8> {
        let mut b = tiny_pe();
        b[0x98 + 108..0x98 + 112].copy_from_slice(&16u32.to_le_bytes());
        let dir = 0x98 + 112 + pe::IMAGE_DIRECTORY_ENTRY_EXPORT * 8;
        b[dir..dir + 4].copy_from_slice(&0x1100u32.to_le_bytes());
        b[dir + 4..dir + 8].copy_from_slice(&40u32.to_le_bytes());
        b[0x50c..0x510].copy_from_slice(&0x1160u32.to_le_bytes());
        b[0x510..0x514].copy_from_slice(&1u32.to_le_bytes());
        b[0x514..0x518].copy_from_slice(&1u32.to_le_bytes());
        b[0x518..0x51c].copy_from_slice(&1u32.to_le_bytes());
        b[0x51c..0x520].copy_from_slice(&0x1130u32.to_le_bytes());
        b[0x520..0x524].copy_from_slice(&0x1134u32.to_le_bytes());
        b[0x524..0x528].copy_from_slice(&0x1138u32.to_le_bytes());
        b[0x530..0x534].copy_from_slice(&0x1010u32.to_le_bytes());
        b[0x534..0x538].copy_from_slice(&0x1170u32.to_le_bytes());
        b[0x538..0x53a].copy_from_slice(&0u16.to_le_bytes());
        b[0x560..0x56a].copy_from_slice(b"module.dll");
        b[0x570..0x577].copy_from_slice(b"NtClose");
        b
    }

    struct FixedResolver;
    impl ImportResolver for FixedResolver {
        fn resolve(&self, dll: &[u8], import: &pe::ImportThunk<'_>) -> Result<u64, pe::Error> {
            assert_eq!(dll, b"ntdll.dll");
            assert_eq!(import, &pe::ImportThunk::Name { hint: 7, name: b"NtClose" });
            Ok(0x1234_5678_9abc_def0)
        }
    }

    #[test]
    fn binds_imports_before_mapping_and_requires_writable_iat() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let blob = imported_pe();
        let parsed = pe::parse(&blob).unwrap();
        assert_eq!(parsed.imports().unwrap().len(), 1);
        let image = load_pe_image_with_resolver(&blob, &as_, &FixedResolver).unwrap();
        assert_eq!(image.size, 0x4000);
        let vma = as_.find_vma(UserVirtAddr::new(image.base + 0x2090).unwrap()).unwrap();
        let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("PE image must be kernel-backed") };
        let offset = 0x2090usize;
        assert_eq!(u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()), 0x1234_5678_9abc_def0);
    }

    #[test]
    fn default_loader_rejects_imports_without_an_nt_runtime() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        assert_eq!(load_pe_image(&imported_pe(), &as_), Err(pe::Error::Unsupported));
        assert_eq!(as_.vma_count(), 0);
    }

    #[test]
    fn malformed_tls_callbacks_are_rejected_before_mapping() {
        let mut blob = tiny_pe();
        let directory = 0x98 + 112 + pe::IMAGE_DIRECTORY_ENTRY_TLS * 8;
        blob[directory..directory + 4].copy_from_slice(&0x1100u32.to_le_bytes());
        blob[directory + 4..directory + 8].copy_from_slice(&40u32.to_le_bytes());
        blob[0x98 + 108..0x98 + 112].copy_from_slice(&16u32.to_le_bytes());
        blob[0x500 + 24..0x500 + 32].copy_from_slice(&(0x1000_0000u64 + 0x1010).to_le_bytes());
        let as_ = AddressSpace::new(0x20_000).unwrap();
        assert_eq!(load_pe_image(&blob, &as_), Err(pe::Error::Einval));
        assert_eq!(as_.vma_count(), 0);
    }

    #[test]
    fn export_resolver_matches_module_names_without_case_sensitivity() {
        let blob = exported_pe();
        let parsed = pe::parse(&blob).unwrap();
        let exports = parsed.exports().unwrap().unwrap();
        assert_eq!((exports.name, exports.ordinal_base, exports.function_count, exports.name_count, exports.functions_rva, exports.names_rva, exports.ordinals_rva), (b"module.dll".as_slice(), 1, 1, 1, 0x1130, 0x1134, 0x1138));
        let modules = [PeExportModule { name: b"NTDLL.DLL", image: parsed, base: 0x5000_0000 }];
        let resolver = PeExportResolver { modules: &modules };
        let address = resolver.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"NtClose" }).unwrap();
        assert_eq!(address, 0x5000_1010);
    }

    #[test]
    fn graph_resolver_follows_bounded_named_forwarders() {
        let mut forwarded = exported_pe();
        let directory = 0x98 + 112 + pe::IMAGE_DIRECTORY_ENTRY_EXPORT * 8;
        forwarded[directory + 4..directory + 8].copy_from_slice(&0x100u32.to_le_bytes());
        forwarded[0x530..0x534].copy_from_slice(&0x1150u32.to_le_bytes());
        forwarded[0x550..0x550 + b"module.NtClose\0".len()].copy_from_slice(b"module.NtClose\0");
        let target = exported_pe();
        let forwarded_image = pe::parse(&forwarded).unwrap();
        let target_image = pe::parse(&target).unwrap();
        let modules = [
            PeExportRef { name: b"forward.dll", image: &forwarded_image, base: 0x6000_0000 },
            PeExportRef { name: b"module.dll", image: &target_image, base: 0x7000_0000 },
        ];
        let resolver = PeGraphResolver { modules: &modules, fallback: &RejectImports };
        assert_eq!(resolver.resolve(b"forward.dll", &pe::ImportThunk::Name { hint: 0, name: b"NtClose" }).unwrap(), 0x7000_1010);
    }

    #[test]
    fn maps_executable_ntdll_stub_page_and_resolves_implemented_services() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let runtime = map_nt_runtime(&as_).unwrap();
        let vma = as_.find_vma(runtime.base).unwrap();
        assert!(vma.prot.contains(VmaProt::READ) && vma.prot.contains(VmaProt::EXEC));
        let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("NTDLL stubs must be kernel-backed") };
        assert_eq!(&data[..4], &[0x57, 0x56, 0x48, 0x89]);
        let address = runtime.resolve(b"NtDlL.DlL", &pe::ImportThunk::Name { hint: 0, name: b"NtClose" }).unwrap();
        assert!(address >= runtime.base.as_u64() && address < runtime.base.as_u64() + runtime.bytes as u64);
        let multiple = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"NtWaitForMultipleObjects" }).unwrap();
        assert!(multiple >= runtime.base.as_u64() && multiple < runtime.base.as_u64() + runtime.bytes as u64);
        let process_query = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"NtQueryInformationProcess" }).unwrap();
        assert!(process_query >= runtime.base.as_u64() && process_query < runtime.base.as_u64() + runtime.bytes as u64);
        let create_thread = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"NtCreateThreadEx" }).unwrap();
        assert!(create_thread >= runtime.base.as_u64() && create_thread < runtime.base.as_u64() + runtime.bytes as u64);
        for name in [b"NtTerminateThread".as_slice(), b"NtQueryInformationThread".as_slice()] {
            let address = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name }).unwrap();
            assert!(address >= runtime.base.as_u64() && address < runtime.base.as_u64() + runtime.bytes as u64);
        }
        for name in [b"RtlAllocateHeap".as_slice(), b"RtlFreeHeap".as_slice()] {
            let address = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name }).unwrap();
            assert!(address >= runtime.base.as_u64() && address < runtime.base.as_u64() + runtime.bytes as u64);
        }
        for name in [b"NtdllDefWindowProc_A".as_slice(), b"NtdllDefWindowProc_W".as_slice(), b"RtlUnwind".as_slice(), b"NtCreateSemaphore".as_slice(), b"NtReleaseSemaphore".as_slice(), b"NtCreateMutant".as_slice(), b"NtReleaseMutant".as_slice(), b"NtQueryMutant".as_slice(), b"NtLockFile".as_slice(), b"NtUnlockFile".as_slice(), b"NtDuplicateObject".as_slice(), b"NtCreateTimer".as_slice(), b"NtSetTimer".as_slice(), b"NtCancelTimer".as_slice(), b"NtCreateIoCompletion".as_slice(), b"NtSetIoCompletion".as_slice(), b"NtRemoveIoCompletion".as_slice(), b"NtSignalAndWaitForSingleObject".as_slice(), b"NtOpenProcessToken".as_slice(), b"NtOpenThreadToken".as_slice(), b"NtQueryInformationToken".as_slice(), b"RtlInitUnicodeString".as_slice(), b"RtlInitUnicodeStringEx".as_slice(), b"NtQueryObject".as_slice(), b"RtlInitAnsiString".as_slice(), b"RtlInitAnsiStringEx".as_slice(), b"NtQuerySecurityObject".as_slice(), b"RtlQueryPerformanceCounter".as_slice(), b"RtlQueryPerformanceFrequency".as_slice(), b"NtRenameKey".as_slice(), b"NtSetSecurityObject".as_slice(), b"RtlAddAccessAllowedAce".as_slice(), b"RtlAddAccessAllowedAceEx".as_slice(), b"RtlAddAccessDeniedAce".as_slice(), b"RtlAddAccessDeniedAceEx".as_slice(), b"RtlAddAce".as_slice(), b"RtlAddAuditAccessAce".as_slice(), b"RtlAddAuditAccessAceEx".as_slice(), b"RtlCreateAcl".as_slice(), b"RtlCreateSecurityDescriptor".as_slice(), b"RtlCreateUnicodeStringFromAsciiz".as_slice(), b"RtlDosPathNameToNtPathName_U".as_slice()] {
            let address = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name }).unwrap();
            assert!(address >= runtime.base.as_u64() && address < runtime.base.as_u64() + runtime.bytes as u64);
        }
        assert_eq!(runtime.resolve(b"kernel32.dll", &pe::ImportThunk::Name { hint: 0, name: b"ExitProcess" }), Err(pe::Error::Unsupported));
        let capture = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlCaptureContext" }).unwrap();
        assert!(capture >= runtime.base.as_u64() && capture < runtime.base.as_u64() + runtime.bytes as u64);
        let create_atoms = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlCreateAtomTable" }).unwrap();
        assert!(create_atoms >= runtime.base.as_u64() && create_atoms < runtime.base.as_u64() + runtime.bytes as u64);
        let create_heap = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlCreateHeap" }).unwrap();
        assert!(create_heap >= runtime.base.as_u64() && create_heap < runtime.base.as_u64() + runtime.bytes as u64);
        let create_unicode = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlCreateUnicodeString" }).unwrap();
        assert!(create_unicode >= runtime.base.as_u64() && create_unicode < runtime.base.as_u64() + runtime.bytes as u64);
        let delete_atom = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlDeleteAtomFromAtomTable" }).unwrap();
        assert!(delete_atom >= runtime.base.as_u64() && delete_atom < runtime.base.as_u64() + runtime.bytes as u64);
        let deregister_wait = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlDeregisterWait" }).unwrap();
        assert!(deregister_wait >= runtime.base.as_u64() && deregister_wait < runtime.base.as_u64() + runtime.bytes as u64);
        for name in [b"RtlDestroyAtomTable" as &[u8], b"RtlDestroyHeap", b"RtlDetermineDosPathNameType_U", b"RtlDosPathNameToNtPathName_U_WithStatus", b"RtlExitUserProcess", b"RtlGetProcessHeaps", b"RtlGetUserInfoHeap", b"RtlImageNtHeader", b"RtlIsNameLegalDOS8Dot3", b"RtlLockHeap", b"RtlUnlockHeap", b"RtlLookupAtomInAtomTable", b"RtlOemStringToUnicodeString", b"RtlQueryAtomInAtomTable", b"RtlRegisterWait", b"RtlRestoreContext", b"RtlSetIoCompletionCallback", b"RtlGetLastWin32Error", b"RtlRestoreLastWin32Error", b"RtlSetLastWin32Error", b"RtlSetSearchPathMode", b"RtlSetUnhandledExceptionFilter", b"RtlSetUserValueHeap", b"RtlTimeFieldsToTime", b"RtlTimeToTimeFields", b"RtlUnicodeStringToAnsiSize", b"RtlUnicodeStringToAnsiString", b"RtlUnicodeStringToInteger", b"RtlUnicodeStringToOemSize", b"RtlUnicodeStringToOemString", b"RtlUnicodeToMultiByteN"] {
            let address = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name }).unwrap();
            assert!(address >= runtime.base.as_u64() && address < runtime.base.as_u64() + runtime.bytes as u64);
        }
        let multibyte_size = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlUnicodeToMultiByteSize" }).unwrap();
        assert!(multibyte_size >= runtime.base.as_u64() && multibyte_size < runtime.base.as_u64() + runtime.bytes as u64);
        let oem = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlUnicodeToOemN" }).unwrap();
        assert!(oem >= runtime.base.as_u64() && oem < runtime.base.as_u64() + runtime.bytes as u64);
        let upcase = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlUpcaseUnicodeString" }).unwrap();
        assert!(upcase >= runtime.base.as_u64() && upcase < runtime.base.as_u64() + runtime.bytes as u64);
        let upper_char = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlUpperChar" }).unwrap();
        assert!(upper_char >= runtime.base.as_u64() && upper_char < runtime.base.as_u64() + runtime.bytes as u64);
        let wcsicmp = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"_wcsicmp" }).unwrap();
        assert!(wcsicmp >= runtime.base.as_u64() && wcsicmp < runtime.base.as_u64() + runtime.bytes as u64);
        let wcsnicmp = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"_wcsnicmp" }).unwrap();
        assert!(wcsnicmp >= runtime.base.as_u64() && wcsnicmp < runtime.base.as_u64() + runtime.bytes as u64);
        let isalpha = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"isalpha" }).unwrap();
        assert!(isalpha >= runtime.base.as_u64() && isalpha < runtime.base.as_u64() + runtime.bytes as u64);
        let islower = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"islower" }).unwrap();
        assert!(islower >= runtime.base.as_u64() && islower < runtime.base.as_u64() + runtime.bytes as u64);
        let memcpy = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"memcpy" }).unwrap();
        assert!(memcpy >= runtime.base.as_u64() && memcpy < runtime.base.as_u64() + runtime.bytes as u64);
        let memmove = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"memmove" }).unwrap();
        assert!(memmove >= runtime.base.as_u64() && memmove < runtime.base.as_u64() + runtime.bytes as u64);
        let memset = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"memset" }).unwrap();
        assert!(memset >= runtime.base.as_u64() && memset < runtime.base.as_u64() + runtime.bytes as u64);
        let strcat = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"strcat" }).unwrap();
        assert!(strcat >= runtime.base.as_u64() && strcat < runtime.base.as_u64() + runtime.bytes as u64);
        let strchr = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"strchr" }).unwrap();
        assert!(strchr >= runtime.base.as_u64() && strchr < runtime.base.as_u64() + runtime.bytes as u64);
        let strcpy = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"strcpy" }).unwrap();
        assert!(strcpy >= runtime.base.as_u64() && strcpy < runtime.base.as_u64() + runtime.bytes as u64);
        let strlen = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"strlen" }).unwrap();
        assert!(strlen >= runtime.base.as_u64() && strlen < runtime.base.as_u64() + runtime.bytes as u64);
        let strpbrk = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"strpbrk" }).unwrap();
        assert!(strpbrk >= runtime.base.as_u64() && strpbrk < runtime.base.as_u64() + runtime.bytes as u64);
        let strrchr = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"strrchr" }).unwrap();
        assert!(strrchr >= runtime.base.as_u64() && strrchr < runtime.base.as_u64() + runtime.bytes as u64);
        let tolower = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"tolower" }).unwrap();
        assert!(tolower >= runtime.base.as_u64() && tolower < runtime.base.as_u64() + runtime.bytes as u64);
        let wcscat = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"wcscat" }).unwrap();
        assert!(wcscat >= runtime.base.as_u64() && wcscat < runtime.base.as_u64() + runtime.bytes as u64);
        let wcschr = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"wcschr" }).unwrap();
        assert!(wcschr >= runtime.base.as_u64() && wcschr < runtime.base.as_u64() + runtime.bytes as u64);
        let wcscmp = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"wcscmp" }).unwrap();
        assert!(wcscmp >= runtime.base.as_u64() && wcscmp < runtime.base.as_u64() + runtime.bytes as u64);
        let wcscpy = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"wcscpy" }).unwrap();
        assert!(wcscpy >= runtime.base.as_u64() && wcscpy < runtime.base.as_u64() + runtime.bytes as u64);
        let wcslen = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"wcslen" }).unwrap();
        assert!(wcslen >= runtime.base.as_u64() && wcslen < runtime.base.as_u64() + runtime.bytes as u64);
        let wcsncmp = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"wcsncmp" }).unwrap();
        assert!(wcsncmp >= runtime.base.as_u64() && wcsncmp < runtime.base.as_u64() + runtime.bytes as u64);
        let wcsrchr = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"wcsrchr" }).unwrap();
        assert!(wcsrchr >= runtime.base.as_u64() && wcsrchr < runtime.base.as_u64() + runtime.bytes as u64);
        let wcstoul = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"wcstoul" }).unwrap();
        assert!(wcstoul >= runtime.base.as_u64() && wcstoul < runtime.base.as_u64() + runtime.bytes as u64);
        let dbg_header = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"__wine_dbg_header" }).unwrap();
        assert!(dbg_header >= runtime.base.as_u64() && dbg_header < runtime.base.as_u64() + runtime.bytes as u64);
        let dbg_output = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"__wine_dbg_output" }).unwrap();
        assert!(dbg_output >= runtime.base.as_u64() && dbg_output < runtime.base.as_u64() + runtime.bytes as u64);
        let dbg_strdup = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"__wine_dbg_strdup" }).unwrap();
        assert!(dbg_strdup >= runtime.base.as_u64() && dbg_strdup < runtime.base.as_u64() + runtime.bytes as u64);
        let guid_from_string = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlGUIDFromString" }).unwrap();
        let random = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlRandom" }).unwrap();
        assert!(random >= runtime.base.as_u64() && random < runtime.base.as_u64() + runtime.bytes as u64);
        let host_version = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"wine_get_host_version" }).unwrap();
        assert!(host_version >= runtime.base.as_u64() && host_version < runtime.base.as_u64() + runtime.bytes as u64);
        let flush_slist = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlInterlockedFlushSList" }).unwrap();
        assert!(flush_slist >= runtime.base.as_u64() && flush_slist < runtime.base.as_u64() + runtime.bytes as u64);
        let push_slist = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlInterlockedPushEntrySList" }).unwrap();
        assert!(push_slist >= runtime.base.as_u64() && push_slist < runtime.base.as_u64() + runtime.bytes as u64);
        let try_enter = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlTryEnterCriticalSection" }).unwrap();
        assert!(try_enter >= runtime.base.as_u64() && try_enter < runtime.base.as_u64() + runtime.bytes as u64);
        let are_bits_clear = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlAreBitsClear" }).unwrap();
        assert!(are_bits_clear >= runtime.base.as_u64() && are_bits_clear < runtime.base.as_u64() + runtime.bytes as u64);
        let are_bits_set = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlAreBitsSet" }).unwrap();
        assert!(are_bits_set >= runtime.base.as_u64() && are_bits_set < runtime.base.as_u64() + runtime.bytes as u64);
        let initialize_bitmap = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlInitializeBitMap" }).unwrap();
        assert!(initialize_bitmap >= runtime.base.as_u64() && initialize_bitmap < runtime.base.as_u64() + runtime.bytes as u64);
        let lookup_function_entry = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlLookupFunctionEntry" }).unwrap();
        assert!(lookup_function_entry >= runtime.base.as_u64() && lookup_function_entry < runtime.base.as_u64() + runtime.bytes as u64);
        let pc_to_file_header = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlPcToFileHeader" }).unwrap();
        assert!(pc_to_file_header >= runtime.base.as_u64() && pc_to_file_header < runtime.base.as_u64() + runtime.bytes as u64);
        let set_bits = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlSetBits" }).unwrap();
        assert!(set_bits >= runtime.base.as_u64() && set_bits < runtime.base.as_u64() + runtime.bytes as u64);
        let time_to_seconds = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 0, name: b"RtlTimeToSecondsSince1970" }).unwrap();
        assert!(time_to_seconds >= runtime.base.as_u64() && time_to_seconds < runtime.base.as_u64() + runtime.bytes as u64);
        assert!(guid_from_string >= runtime.base.as_u64() && guid_from_string < runtime.base.as_u64() + runtime.bytes as u64);
    }

    #[test]
    fn module_set_maps_all_images_and_rolls_back_on_a_late_import_failure() {
        let first = tiny_pe();
        let second = tiny_pe();
        let modules = [
            pe::Module { name: b"first.exe", image: pe::parse(&first).unwrap() },
            pe::Module { name: b"second.dll", image: pe::parse(&second).unwrap() },
        ];
        let as_ = AddressSpace::new(0x40_000).unwrap();
        let loaded = load_pe_module_set_with_resolver(&modules, &as_, &RejectImports).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, b"first.exe");
        assert_ne!(loaded[0].image.base, loaded[1].image.base);
        assert!(as_.vma_count() >= 4);

        let as_ = AddressSpace::new(0x40_000).unwrap();
        let planned = load_pe_module_graph(&modules, &as_, &RejectImports).unwrap();
        assert_eq!(planned.len(), 2);
        assert_eq!(planned[0].image.base, loaded[0].image.base);
        assert_ne!(planned[0].image.base, planned[1].image.base);

        let owned = [
            pe::OwnedModule { name: b"first.exe".to_vec(), blob: first.clone() },
            pe::OwnedModule { name: b"second.dll".to_vec(), blob: second.clone() },
        ];
        let as_ = AddressSpace::new(0x40_000).unwrap();
        let owned_loaded = load_owned_pe_module_graph(&owned, &as_, &RejectImports).unwrap();
        assert_eq!(owned_loaded.len(), 2);
        assert_eq!(owned_loaded[1].name, b"second.dll");

        let imported = imported_pe();
        let modules = [
            pe::Module { name: b"first.exe", image: pe::parse(&first).unwrap() },
            pe::Module { name: b"bad.dll", image: pe::parse(&imported).unwrap() },
        ];
        let as_ = AddressSpace::new(0x40_000).unwrap();
        assert!(matches!(load_pe_module_set_with_resolver(&modules, &as_, &RejectImports), Err(pe::Error::Unsupported)));
        assert_eq!(as_.vma_count(), 0);
    }

    #[test]
    fn graph_resolver_binds_an_import_to_the_assigned_dll_base() {
        let mut root = imported_pe();
        root[0x560..0x56a].copy_from_slice(b"module.dll");
        let dependency = exported_pe();
        let modules = [
            pe::Module { name: b"root.exe", image: pe::parse(&root).unwrap() },
            pe::Module { name: b"module.dll", image: pe::parse(&dependency).unwrap() },
        ];
        let as_ = AddressSpace::new(0x40_000).unwrap();
        let loaded = load_pe_module_graph(&modules, &as_, &RejectImports).unwrap();
        let root_vma = as_.find_vma(UserVirtAddr::new(loaded[0].image.base + 0x2090).unwrap()).unwrap();
        let data = match root_vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("PE image must be kernel-backed") };
        let iat = 0x2090usize;
        assert_eq!(u64::from_le_bytes(data[iat..iat + 8].try_into().unwrap()), loaded[1].image.base + 0x1010);
    }

    #[test]
    fn maps_headers_and_code_without_touching_linux_state() {
        let as_ = AddressSpace::new(0x1_0000).unwrap(); as_.set_mmap_layout(0x7000_0000, true);
        let image = load_pe_image(&tiny_pe(), &as_).unwrap(); assert_eq!(image.size, 0x3000); assert_eq!(image.preferred_base, 0x1000_0000); assert_eq!(image.base, image.preferred_base); assert!(image.entry.as_u64() >= image.base); assert!(as_.vma_count() >= 2);
        assert_eq!(image.tls_directory, (0, 0));
        let entry = initial_entry_state(&image, 0x6000_0001).unwrap(); assert_eq!(entry.rip, image.entry); assert_eq!(entry.rsp.as_u64(), 0x5fff_ffe0);
    }

    #[test]
    fn hello_pe_contains_a_real_native_terminate_entry_contract() {
        let mut blob = tiny_pe();
        let selector = (syscall::nt::NT_SERVICE_NAMESPACE | syscall::nt::NtService::TerminateProcess as u64).to_le_bytes();
        blob[0x410..0x412].copy_from_slice(&[0x48, 0xb8]);
        blob[0x412..0x41a].copy_from_slice(&selector);
        blob[0x41a..0x421].copy_from_slice(&[0x48, 0xc7, 0xc1, 0xff, 0xff, 0xff, 0xff]);
        blob[0x421..0x423].copy_from_slice(&[0x31, 0xd2]);
        blob[0x423..0x425].copy_from_slice(&[0x0f, 0x05]);
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let process = load_pe_process(&blob, &as_, &process_env::EnvironmentInput {
            image_base: 0, image_size: 0, image_path: "C:\\hello.exe", command_line: "hello.exe",
            environment: &[], process_id: 1, thread_id: 2,
        }, 0x6000_0000).unwrap();
        let vma = as_.find_vma(process.image.entry).unwrap();
        let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("Hello PE text must be kernel-backed") };
        assert_eq!(&data[0x1010..0x1025], &blob[0x410..0x425]);
        assert_eq!(process.entry.rip, process.image.entry);
        assert_eq!(process.entry.personality, ExecutionPersonality::Nt);
        assert_eq!(process.entry.rsp.as_u64() % 16, 0);
    }

    #[test]
    fn relocates_when_preferred_base_is_occupied() {
        let as_ = AddressSpace::new(0x1_0000).unwrap(); as_.set_mmap_layout(0x7000_0000, true);
        let occupied = UserVirtAddr::new(0x1000_0000).unwrap();
        as_.mmap(Some(occupied), 0x3000, VmaProt::READ, VmaFlags::PRIVATE, VmaBacking::Anonymous, true).unwrap();
        let image = load_pe_image(&tiny_pe(), &as_).unwrap(); assert_ne!(image.base, image.preferred_base); assert_eq!(image.base % 0x1000, 0); assert!(image.entry.as_u64() < image.base + image.size as u64);
    }

    #[test]
    fn entry_state_uses_the_nt_teb_as_gs_base() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let image = load_pe_image(&tiny_pe(), &as_).unwrap();
        let env = process_env::build(&process_env::EnvironmentInput {
            image_base: image.base, image_size: image.size, image_path: "C:\\notepad.exe",
            command_line: "notepad.exe", environment: &[], process_id: 1, thread_id: 1,
        }, &as_).unwrap();
        let state = initial_entry_state_with_environment(&image, 0x6000_0000, &env).unwrap();
        assert_eq!(state.personality, ExecutionPersonality::Nt);
        assert_eq!(state.gs_base, env.teb);
        assert_eq!(state.rsp.as_u64() % 16, 0);
    }

    #[test]
    fn failed_environment_setup_rolls_back_the_pe_mapping() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let result = load_pe_process(&tiny_pe(), &as_, &process_env::EnvironmentInput {
            image_base: 0x1000_0000, image_size: 0x3000, image_path: "bad\0path",
            command_line: "notepad.exe", environment: &[], process_id: 1, thread_id: 1,
        }, 0x6000_0000);
        assert!(matches!(result, Err(pe::Error::Einval)));
        assert_eq!(as_.vma_count(), 0);
    }

    #[test]
    fn process_environment_derives_image_metadata_from_the_mapped_pe() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let process = load_pe_process(&tiny_pe(), &as_, &process_env::EnvironmentInput {
            image_base: 0, image_size: 0, image_path: "C:\\notepad.exe",
            command_line: "notepad.exe", environment: &[], process_id: 1, thread_id: 1,
        }, 0x6000_0000).unwrap();
        let vma = as_.find_vma(process.environment.base).unwrap();
        let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("environment must be kernel-backed") };
        assert_eq!(u64::from_le_bytes(data[0x10..0x18].try_into().unwrap()), process.image.base);
        assert_eq!(u32::from_le_bytes(data[0x540..0x544].try_into().unwrap()), process.image.size);
    }

    #[test]
    fn catalog_loader_maps_root_and_native_ntdll_fallback_as_one_process() {
        let as_ = AddressSpace::new(0x40_000).unwrap();
        let runtime = map_nt_runtime(&as_).unwrap();
        let catalog = pe::catalog::ModuleCatalog::new();
        let process = load_pe_process_with_catalog(&imported_pe(), &as_, &process_env::EnvironmentInput {
            image_base: 0, image_size: 0, image_path: "C:\\notepad.exe",
            command_line: "notepad.exe", environment: &[], process_id: 7, thread_id: 8,
        }, 0x6000_0000, &runtime, &catalog).unwrap();
        assert_eq!(process.image.size, 0x4000);
        assert!(process.environment.bytes >= 0x4000);
        assert_eq!(process.entry.gs_base, process.environment.teb);
    }

    #[test]
    fn catalog_loader_prefers_native_ntdll_for_implemented_exports() {
        let as_ = AddressSpace::new(0x40_000).unwrap();
        let runtime = map_nt_runtime(&as_).unwrap();
        let mut catalog = pe::catalog::ModuleCatalog::new();
        let mut wine_ntdll = exported_pe();
        wine_ntdll[0x560..0x569].copy_from_slice(b"ntdll.dll");
        catalog.add(b"ntdll.dll", &wine_ntdll).unwrap();
        let process = load_pe_process_with_catalog(&imported_pe(), &as_, &process_env::EnvironmentInput {
            image_base: 0, image_size: 0, image_path: "C:\\root.exe",
            command_line: "root.exe", environment: &[], process_id: 7, thread_id: 8,
        }, 0x6000_0000, &runtime, &catalog).unwrap();
        let vma = as_.find_vma(UserVirtAddr::new(process.image.base + 0x2090).unwrap()).unwrap();
        let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("PE image must be kernel-backed") };
        let bound = u64::from_le_bytes(data[0x2090..0x2098].try_into().unwrap());
        let native = runtime.resolve(b"ntdll.dll", &pe::ImportThunk::Name { hint: 7, name: b"NtClose" }).unwrap();
        assert_eq!(bound, native);
        assert_ne!(bound, process.initializers[0].base + 0x1010);
    }

    #[test]
    fn catalog_loader_emits_dependency_first_initializers() {
        let as_ = AddressSpace::new(0x40_000).unwrap();
        let runtime = map_nt_runtime(&as_).unwrap();
        let mut root = imported_pe();
        root[0x560..0x569].fill(0);
        root[0x560..0x567].copy_from_slice(b"dep.dll");
        let mut catalog = pe::catalog::ModuleCatalog::new();
        catalog.add(b"dep.dll", &exported_pe()).unwrap();
        let process = load_pe_process_with_catalog(&root, &as_, &process_env::EnvironmentInput {
            image_base: 0, image_size: 0, image_path: "C:\\root.exe",
            command_line: "root.exe", environment: &[], process_id: 7, thread_id: 8,
        }, 0x6000_0000, &runtime, &catalog).unwrap();
        assert_eq!(process.initializers.len(), 1);
        assert_eq!(process.initializers[0].entry.as_u64(), process.initializers[0].base + 0x1010);
        assert_eq!(process.initializer_trampoline.unwrap().entry, process.entry.rip);
        assert_ne!(process.entry.rip, process.image.entry);
    }

    #[test]
    fn catalog_loader_places_dependency_tls_callbacks_before_dll_attach() {
        let as_ = AddressSpace::new(0x40_000).unwrap();
        let runtime = map_nt_runtime(&as_).unwrap();
        let mut root = imported_pe(); root[0x560..0x569].fill(0); root[0x560..0x567].copy_from_slice(b"dep.dll");
        let mut dep = exported_pe();
        let tls = 0x98 + 112 + pe::IMAGE_DIRECTORY_ENTRY_TLS * 8;
        dep[tls..tls + 4].copy_from_slice(&0x1180u32.to_le_bytes()); dep[tls + 4..tls + 8].copy_from_slice(&40u32.to_le_bytes());
        dep[0x580 + 24..0x580 + 32].copy_from_slice(&(0x1000_0000u64 + 0x11d0).to_le_bytes());
        dep[0x5d0..0x5d8].copy_from_slice(&(0x1000_0000u64 + 0x1015).to_le_bytes()); dep[0x5d8..0x5e0].fill(0);
        assert_eq!(pe::parse(&dep).unwrap().tls_callback_rvas().unwrap(), vec![0x1015]);
        let mut catalog = pe::catalog::ModuleCatalog::new(); catalog.add(b"dep.dll", &dep).unwrap();
        let process = load_pe_process_with_catalog(&root, &as_, &process_env::EnvironmentInput {
            image_base: 0, image_size: 0, image_path: "C:\\root.exe", command_line: "root.exe", environment: &[], process_id: 7, thread_id: 8,
        }, 0x6000_0000, &runtime, &catalog).unwrap();
        assert_eq!(process.initializers.len(), 2);
        assert_eq!(process.initializers[0].entry.as_u64(), process.initializers[0].base + 0x1015);
        assert_eq!(process.initializers[1].entry.as_u64(), process.initializers[1].base + 0x1010);
    }

    #[test]
    fn direct_loader_runs_root_tls_callback_before_application_entry() {
        let as_ = AddressSpace::new(0x40_000).unwrap();
        let mut root = exported_pe();
        let tls = 0x98 + 112 + pe::IMAGE_DIRECTORY_ENTRY_TLS * 8;
        root[tls..tls + 4].copy_from_slice(&0x1180u32.to_le_bytes()); root[tls + 4..tls + 8].copy_from_slice(&40u32.to_le_bytes());
        root[0x580 + 24..0x580 + 32].copy_from_slice(&(0x1000_0000u64 + 0x11d0).to_le_bytes());
        root[0x5d0..0x5d8].copy_from_slice(&(0x1000_0000u64 + 0x1015).to_le_bytes()); root[0x5d8..0x5e0].fill(0);
        let process = load_pe_process_with_resolver(&root, &as_, &process_env::EnvironmentInput {
            image_base: 0, image_size: 0, image_path: "C:\\root.exe", command_line: "root.exe", environment: &[], process_id: 7, thread_id: 8,
        }, 0x6000_0000, &RejectImports).unwrap();
        assert_eq!(process.initializers.len(), 1);
        assert_eq!(process.initializers[0].entry.as_u64(), process.image.base + 0x1015);
        assert_eq!(process.entry.rip, process.initializer_trampoline.unwrap().entry);
    }

    #[test]
    fn catalog_loader_rolls_back_mapped_images_on_invalid_module_name() {
        let as_ = AddressSpace::new(0x40_000).unwrap();
        let runtime = map_nt_runtime(&as_).unwrap();
        let mut root = imported_pe();
        root[0x560] = 0xff; root[0x561] = 0;
        let dependency = exported_pe();
        let mut catalog = pe::catalog::ModuleCatalog::new();
        catalog.add(&[0xff], &dependency).unwrap();
        let result = load_pe_process_with_catalog(&root, &as_, &process_env::EnvironmentInput {
            image_base: 0, image_size: 0, image_path: "C:\\notepad.exe",
            command_line: "notepad.exe", environment: &[], process_id: 7, thread_id: 8,
        }, 0x6000_0000, &runtime, &catalog);
        assert!(matches!(result, Err(pe::Error::Einval)));
        assert_eq!(as_.vma_count(), 1);
    }

    #[test]
    fn installed_wine_notepad_catalog_covers_its_transitive_runtime_graph() {
        let roots = [
            "/usr/lib64/wine/x86_64-windows",
            "/usr/lib/wine/x86_64-windows",
        ];
        let Some(root) = roots.iter().find(|root| {
            std::path::Path::new(root).join("notepad.exe").is_file()
        }) else { return };
        let notepad = std::fs::read(std::path::Path::new(root).join("notepad.exe"))
            .expect("installed Wine Notepad must be readable");
        let mut catalog = pe::catalog::ModuleCatalog::new();
        for entry in std::fs::read_dir(root).expect("Wine DLL directory must be readable") {
            let entry = entry.expect("Wine DLL directory entry must be readable");
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("dll") { continue; }
            let name = path.file_name().and_then(|name| name.to_str()).expect("Wine DLL name must be UTF-8");
            if name.eq_ignore_ascii_case("ntdll.dll") { continue; }
            let blob = std::fs::read(&path).expect("Wine DLL must be readable");
            catalog.add(name.as_bytes(), &blob).expect("Wine DLL must satisfy the PE catalog contract");
        }
        let source = &catalog;
        let modules = pe::discover_owned_modules_with_builtins(
            b"notepad.exe", &notepad, &source, |name| name.eq_ignore_ascii_case(b"ntdll.dll"),
        ).expect("installed Wine Notepad dependency graph must discover");
        assert!(modules.len() > 10, "Notepad coverage must include a real DLL graph");
        assert!(modules.iter().any(|module| module.name.eq_ignore_ascii_case(b"kernel32.dll")));
        assert!(modules.iter().any(|module| module.name.eq_ignore_ascii_case(b"user32.dll")));
    }
