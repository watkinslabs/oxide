use super::*;
use proptest::prelude::*;

#[test]
fn x64_process_parameter_string_has_native_byte_counts_and_terminator() {
    let (desc, encoded) = encode_x64_process_parameter_string("notepad.exe", 0x4000, 24).unwrap();
    assert_eq!(desc, X64ProcessParameterString { length: 22, maximum_length: 24, buffer: 0x4000 });
    assert_eq!(encoded, "notepad.exe\0".encode_utf16().collect::<Vec<_>>());
}

#[test]
fn x64_process_parameter_string_rejects_invalid_capacity_pointer_and_text() {
    for (value, buffer, capacity) in [("", 0x4001, 2), ("", 0x4000, 3), ("abc", 0x4000, 6),
        ("a\0b", 0x4000, 8), ("x", 0x4000, (u16::MAX as usize) + 2)] {
        assert_eq!(encode_x64_process_parameter_string(value, buffer, capacity), Err(Error::Einval));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_ascii_process_strings_map_or_reject_without_partial_state(
        path in "[A-Za-z0-9_./\\\\]{0,128}", command in "[A-Za-z0-9 _.-]{0,128}") {
        let as_ = AddressSpace::new(0x40_000).unwrap();
        let result = build(&EnvironmentInput { image_base: 0x1400_0000, image_size: 0x5000,
            image_path: &path, command_line: &command, environment: &[("TEMP", "C:\\Temp")],
            process_id: 1, thread_id: 1 }, &as_);
        if let Ok(env) = result {
            prop_assert!(env.base.as_u64() % PAGE as u64 == 0);
            prop_assert!(env.peb.as_u64() >= env.base.as_u64());
            prop_assert!(env.tls.as_u64() < env.base.as_u64() + env.bytes as u64);
        } else {
            prop_assert_eq!(as_.vma_count(), 0);
        }
    }
}
#[test]
fn maps_self_consistent_nt_environment() {
    let as_ = AddressSpace::new(0x10_000).unwrap();
    let e = build(&EnvironmentInput { image_base: 0x1400_0000, image_size: 0x5000, image_path: "C:\\notepad.exe", command_line: "notepad.exe file.txt", environment: &[("TEMP", "C:\\Temp"), ("PATH", "C:\\Windows")], process_id: 7, thread_id: 8 }, &as_).unwrap();
    assert!(e.peb.as_u64() >= e.base.as_u64() && e.teb.as_u64() < e.base.as_u64() + e.bytes as u64);
    assert_eq!(e.base.as_u64() % PAGE as u64, 0);
}

#[test]
fn supplied_windows_process_parameters_are_encoded() {
    let as_ = AddressSpace::new(0x20_000).unwrap();
    let e = build_with_modules_and_params(&EnvironmentInput {
        image_base: 0x1400_0000, image_size: 0x5000, image_path: "C:\\notepad.exe",
        command_line: "notepad.exe document.txt", environment: &[], process_id: 1, thread_id: 1,
    }, &[NtModuleInput { base: 0x1400_0000, entry: 0x1400_1000, size: 0x5000,
        full_name: "C:\\notepad.exe", base_name: "notepad.exe" }], &NtProcessParameters {
        current_directory: "C:\\Users\\oxide", current_directory_handle: 0x21, console_handle: 0x31,
        standard_handles: [0x41, 0x42, 0x43],
    }, &as_).unwrap();
    let vma = as_.find_vma(e.base).unwrap();
    let (bytes, off) = match vma.backing { VmaBacking::KernelBytes { data, off } => (data, off), _ => panic!("environment must be kernel bytes") };
    let at = |offset: usize| { let start = off + e.process_parameters.as_u64() as usize - e.base.as_u64() as usize + offset; u64::from_ne_bytes(bytes[start..start + 8].try_into().unwrap()) };
    assert_eq!(at(0x10), 0x31);
    assert_eq!(at(PARAM_CURRENT_DIRECTORY_HANDLE_OFF), 0x21);
    assert_eq!([at(0x20), at(0x28), at(0x30)], [0x41, 0x42, 0x43]);
}

#[test]
fn partial_standard_handle_triplet_is_rejected_before_mapping() {
    let as_ = AddressSpace::new(0x20_000).unwrap();
    let result = build_with_modules_and_params(&EnvironmentInput {
        image_base: 0x1400_0000, image_size: 0x5000, image_path: "C:\\hello.exe",
        command_line: "hello.exe", environment: &[], process_id: 1, thread_id: 1,
    }, &[NtModuleInput { base: 0x1400_0000, entry: 0x1400_1000, size: 0x5000,
        full_name: "C:\\hello.exe", base_name: "hello.exe" }], &NtProcessParameters {
        current_directory: "C:\\", current_directory_handle: 0, console_handle: 0,
        standard_handles: [0x41, 0, 0x43],
    }, &as_);
    assert_eq!(result, Err(Error::Einval));
    assert_eq!(as_.vma_count(), 0);
}

#[test]
fn encoded_x64_fields_and_utf16_buffers_match_the_published_pointers() {
    let as_ = AddressSpace::new(0x20_000).unwrap();
    let e = build(&EnvironmentInput { image_base: 0x1400_0000, image_size: 0x5000,
        image_path: "C:\\Windows\\notepad.exe", command_line: "notepad.exe a.txt",
        environment: &[("TEMP", "C:\\Temp")], process_id: 11, thread_id: 12 }, &as_).unwrap();
    let vma = as_.find_vma(e.base).unwrap();
    let (bytes, off) = match vma.backing { VmaBacking::KernelBytes { data, off } => (data, off), _ => panic!("environment must be immutable kernel bytes") };
    let read64 = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
    let read16 = |o: usize| u16::from_le_bytes(bytes[o..o + 2].try_into().unwrap());
    let base = e.base.as_u64() as usize;
    assert_eq!(read64(0x10), 0x1400_0000);
    assert_eq!(read64(0x18), base as u64 + LDR_OFF as u64);
    assert_eq!(read64(0x20), base as u64 + PARAM_OFF as u64);
    assert_eq!(read64(TEB_OFF + 0x30), base as u64 + TEB_OFF as u64);
    assert_eq!(read64(TEB_OFF + 0x60), base as u64);
    assert_eq!(read64(TEB_OFF + 0x58), base as u64 + TLS_OFF as u64);
    assert_eq!(read64(TEB_OFF + TEB_ACTIVATION_CONTEXT_STACK_OFFSET),
        base as u64 + TEB_OFF as u64 + TEB_ACTIVATION_CONTEXT_STACK_INLINE as u64);
    assert_eq!(read64(TEB_OFF + TEB_SYSCALL_FRAME_OFFSET), base as u64 + PROCESS_SYSCALL_FRAME_OFF as u64);
    assert_eq!(read16(PARAM_OFF + 0x60), ("C:\\Windows\\notepad.exe".encode_utf16().count() * 2) as u16);
    assert_eq!(read16(PARAM_OFF + 0x70), ("notepad.exe a.txt".encode_utf16().count() * 2) as u16);
    assert_eq!(read16(PARAM_OFF + PARAM_COMMAND_LINE_OFF + 2), (("notepad.exe a.txt".encode_utf16().count() + 1) * 2) as u16);
    assert_eq!(read16(PARAM_OFF + PARAM_CURRENT_DIRECTORY_OFF), ("C:\\Windows".encode_utf16().count() * 2) as u16);
    assert_eq!(read16(PARAM_OFF + PARAM_CURRENT_DIRECTORY_OFF + 2), CURRENT_DIR_STORAGE as u16);
    assert_eq!(read64(PARAM_OFF + 0x80), base as u64 + ENV_OFF as u64);
    assert_eq!(u32::from_le_bytes(bytes[PARAM_OFF + PARAM_SHOW_WINDOW_OFF..PARAM_OFF + PARAM_SHOW_WINDOW_OFF + 4].try_into().unwrap()), SHOW_WINDOW_NORMAL);
    assert_eq!(u32::from_le_bytes(bytes[PARAM_OFF + PARAM_PROCESS_GROUP_ID_OFF..PARAM_OFF + PARAM_PROCESS_GROUP_ID_OFF + 4].try_into().unwrap()), 11);
    assert_eq!(read16(PARAM_OFF + PARAM_WINDOW_TITLE_OFF), ("C:\\Windows\\notepad.exe".encode_utf16().count() * 2) as u16);
    assert_eq!(read16(PARAM_OFF + PARAM_WINDOW_TITLE_OFF + 2), ("C:\\Windows\\notepad.exe".encode_utf16().count() * 2 + 2) as u16);
    assert_eq!(read64(PARAM_OFF + PARAM_WINDOW_TITLE_OFF + 8), base as u64 + PROCESS_STR_OFF as u64);
    assert_eq!(read64(PEB_OFF + 0x68), base as u64 + API_SET_OFF as u64);
    assert_eq!(read64(PEB_OFF + PEB_PROCESS_HEAP_OFF), PROCESS_HEAP_HANDLE);
    assert_eq!(u32::from_le_bytes(bytes[PEB_OFF + PEB_NUMBER_OF_PROCESSORS_OFF..PEB_OFF + PEB_NUMBER_OF_PROCESSORS_OFF + 4].try_into().unwrap()), INITIAL_PROCESSOR_COUNT);
    assert_eq!(u32::from_le_bytes(bytes[API_SET_OFF..API_SET_OFF + 4].try_into().unwrap()), 6);
    assert_eq!(u32::from_le_bytes(bytes[API_SET_OFF + 12..API_SET_OFF + 16].try_into().unwrap()), pe::apiset::entries().len() as u32);
    assert_eq!(off, 0);
}

#[test]
fn initial_process_parameters_publish_wine_startup_identity() {
    let as_ = AddressSpace::new(0x20_000).unwrap();
    let e = build(&EnvironmentInput {
        image_base: 0x1400_0000, image_size: 0x5000, image_path: "C:\\Windows\\notepad.exe",
        command_line: "notepad.exe", environment: &[], process_id: 73, thread_id: 74,
    }, &as_).unwrap();
    let vma = as_.find_vma(e.base).unwrap();
    let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("environment must be kernel-backed") };
    let read32 = |offset: usize| u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
    let read16 = |offset: usize| u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap());
    let read64 = |offset: usize| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
    assert_eq!(read32(PARAM_OFF + PARAM_SHOW_WINDOW_OFF), SHOW_WINDOW_NORMAL);
    assert_eq!(read32(PARAM_OFF + PARAM_PROCESS_GROUP_ID_OFF), 73);
    assert_eq!(read16(PARAM_OFF + PARAM_WINDOW_TITLE_OFF), 44);
    assert_eq!(read16(PARAM_OFF + PARAM_WINDOW_TITLE_OFF + 2), 46);
    assert_eq!(read64(PARAM_OFF + PARAM_WINDOW_TITLE_OFF + 8), e.base.as_u64() + PROCESS_STR_OFF as u64);
}

#[test]
fn normalized_process_parameters_publish_sizes_consumed_by_environment_apis() {
    let as_ = AddressSpace::new(0x20_000).unwrap();
    let e = build(&EnvironmentInput {
        image_base: 0x1400_0000, image_size: 0x5000,
        image_path: "C:\\Windows\\notepad.exe", command_line: "notepad.exe",
        environment: &[("TEMP", "C:\\Temp"), ("PATH", "C:\\Windows")],
        process_id: 1, thread_id: 2,
    }, &as_).unwrap();
    let vma = as_.find_vma(e.base).unwrap();
    let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("environment must be kernel-backed") };
    let read32 = |offset: usize| u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
    let read64 = |offset: usize| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
    assert_eq!(read32(PARAM_OFF), PARAM_SIZE);
    assert_eq!(read32(PARAM_OFF + 4), PARAM_SIZE);
    assert_eq!(read32(PARAM_OFF + 8), PARAM_FLAGS_NORMALIZED);
    assert_eq!(read64(PARAM_OFF + PARAM_ENVIRONMENT_SIZE_OFF), "TEMP=C:\\Temp\0PATH=C:\\Windows\0\0".encode_utf16().count() as u64 * 2);
    assert_eq!(read64(PARAM_OFF + 0x80), e.base.as_u64() + ENV_OFF as u64);
    assert_eq!(read64(PARAM_OFF + 0x80), e.environment.as_u64());
    assert_eq!(PARAM_SIZE as usize, PROCESS_STR_OFF - PARAM_OFF);
}

#[test]
fn loader_lists_publish_the_executable_and_ntdll_as_circular_entries() {
    let as_ = AddressSpace::new(0x20_000).unwrap();
    let e = build_with_modules(&EnvironmentInput { image_base: 0x1400_0000, image_size: 0x5000,
        image_path: "C:\\Windows\\notepad.exe", command_line: "notepad.exe", environment: &[], process_id: 1, thread_id: 1 }, &[
        NtModuleInput { base: 0x1400_0000, entry: 0x1400_1010, size: 0x5000, full_name: "C:\\Windows\\notepad.exe", base_name: "notepad.exe" },
        NtModuleInput { base: 0x7000_0000, entry: 0, size: 0x9000, full_name: "C:\\Windows\\System32\\ntdll.dll", base_name: "ntdll.dll" },
    ], &as_).unwrap();
    let vma = as_.find_vma(e.base).unwrap();
    let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("environment must be kernel-backed") };
    let read64 = |offset: usize| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
    let first = e.base.as_u64() + MOD_OFF as u64;
    let second = first + MOD_STRIDE as u64;
    assert_eq!(read64(LDR_OFF + 0x10), first);
    assert_eq!(read64(LDR_OFF + 0x18), second);
    assert_eq!(read64(MOD_OFF + 0x30), 0x1400_0000);
    assert_eq!(read64(MOD_OFF + 0x38), 0x1400_1010);
    assert_eq!(read64(MOD_OFF + MOD_STRIDE + 0x30), 0x7000_0000);
    assert_eq!(read64(MOD_OFF + MOD_STRIDE + 0x38), 0);
    assert_eq!(read64(MOD_OFF), second);
    assert_eq!(read64(MOD_OFF + 8), e.base.as_u64() + LDR_OFF as u64 + 0x18);
    assert_eq!(read64(MOD_OFF + MOD_STRIDE), e.base.as_u64() + LDR_OFF as u64 + 0x10);
    assert_eq!(read64(MOD_OFF + MOD_STRIDE + 8), first);
}

#[test]
fn loader_records_remain_intact_when_the_module_list_reaches_the_string_arena() {
    let as_ = AddressSpace::new(0x40_000).unwrap();
    let mut modules = Vec::new();
    for index in 0..16 {
        modules.push(NtModuleInput { base: 0x7000_0000 + index * 0x10_000, entry: 0, size: 0x9000,
            full_name: "C:\\Windows\\System32\\module.dll", base_name: "module.dll" });
    }
    let e = build_with_modules(&EnvironmentInput { image_base: 0x1400_0000, image_size: 0x5000,
        image_path: "C:\\Windows\\notepad.exe", command_line: "notepad.exe", environment: &[], process_id: 1, thread_id: 1 }, &modules, &as_).unwrap();
    let vma = as_.find_vma(e.base).unwrap();
    let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("environment must be kernel-backed") };
    for (index, module) in modules.iter().enumerate() {
        let offset = MOD_OFF + index * MOD_STRIDE + 0x30;
        assert_eq!(u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()), module.base);
    }
}
#[test]
fn rejects_embedded_nul_without_mapping() {
    let as_ = AddressSpace::new(0x10_000).unwrap();
    assert_eq!(build(&EnvironmentInput { image_base: 1, image_size: 1, image_path: "bad\0path", command_line: "", environment: &[], process_id: 1, thread_id: 1 }, &as_), Err(Error::Einval));
    assert_eq!(as_.vma_count(), 0);
}

#[test]
fn rejects_oversized_strings_before_mapping_any_bytes() {
    let as_ = AddressSpace::new(0x20_000).unwrap();
    let path = "x".repeat(BLOCK_BYTES);
    let result = build(&EnvironmentInput { image_base: 1, image_size: 1,
        image_path: &path, command_line: "", environment: &[], process_id: 1, thread_id: 1 }, &as_);
    assert_eq!(result, Err(Error::Einval));
    assert_eq!(as_.vma_count(), 0);
}

#[test]
fn rejects_oversized_current_directory_before_mapping_any_bytes() {
    let as_ = AddressSpace::new(0x20_000).unwrap();
    let current_directory = "x".repeat(CURRENT_DIR_STORAGE / 2);
    let result = build_with_modules_and_params(&EnvironmentInput {
        image_base: 0x1400_0000, image_size: 0x5000, image_path: "C:\\notepad.exe",
        command_line: "notepad.exe", environment: &[], process_id: 1, thread_id: 1,
    }, &[NtModuleInput { base: 0x1400_0000, entry: 0x1400_1000, size: 0x5000,
        full_name: "C:\\notepad.exe", base_name: "notepad.exe" }], &NtProcessParameters {
        current_directory: &current_directory, current_directory_handle: 0,
        console_handle: 0, standard_handles: [0; 3],
    }, &as_);
    assert_eq!(result, Err(Error::Einval));
    assert_eq!(as_.vma_count(), 0);
}

#[test]
fn thread_teb_is_distinct_and_publishes_thread_identity() {
    let as_ = AddressSpace::new(0x40_000).unwrap();
    let first = build_thread_teb(7, 8, 0x12_000, &as_).unwrap();
    let second = build_thread_teb(7, 9, 0x12_000, &as_).unwrap();
    assert_ne!(first, second);
    let vma = as_.find_vma(first).unwrap();
    let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("TEB must be kernel-backed") };
    assert_eq!(u64::from_le_bytes(data[0x30..0x38].try_into().unwrap()), first.as_u64());
    assert_eq!(u64::from_le_bytes(data[0x60..0x68].try_into().unwrap()), 0x12_000);
    assert_eq!(u32::from_le_bytes(data[0x40..0x44].try_into().unwrap()), 7);
    assert_eq!(u32::from_le_bytes(data[0x48..0x4c].try_into().unwrap()), 8);
    assert_eq!(u64::from_le_bytes(data[0x58..0x60].try_into().unwrap()), first.as_u64() + THREAD_TLS_OFF as u64);
    assert_eq!(u64::from_le_bytes(data[TEB_ACTIVATION_CONTEXT_STACK_OFFSET..TEB_ACTIVATION_CONTEXT_STACK_OFFSET + 8].try_into().unwrap()),
        first.as_u64() + TEB_ACTIVATION_CONTEXT_STACK_INLINE as u64);
    assert_eq!(u32::from_le_bytes(data[TEB_CURRENT_LOCALE_OFF..TEB_CURRENT_LOCALE_OFF + 4].try_into().unwrap()), 0x409);
    assert!(data[TEB_TLS_SLOTS_OFF..TEB_TLS_SLOTS_OFF + TEB_TLS_SLOTS * 8].iter().all(|byte| *byte == 0));
    assert_eq!(u64::from_le_bytes(data[TEB_TLS_EXPANSION_SLOTS_OFF..TEB_TLS_EXPANSION_SLOTS_OFF + 8].try_into().unwrap()), 0);
    assert_eq!(u64::from_le_bytes(data[TEB_SYSCALL_FRAME_OFFSET..TEB_SYSCALL_FRAME_OFFSET + 8].try_into().unwrap()), first.as_u64() + THREAD_SYSCALL_FRAME_OFF as u64);
}

#[test]
fn thread_teb_publishes_stack_bounds_and_exact_cleanup() {
    let as_ = AddressSpace::new(0x80_000).unwrap();
    let stack = as_.mmap(None, 0x8000, VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE, VmaBacking::Anonymous, false).unwrap();
    let low = stack.as_u64();
    let high = low + 0x8000;
    let teb = build_thread_teb_with_stack(7, 8, 0x12_000, low, high, &as_).unwrap();
    let vma = as_.find_vma(teb).unwrap();
    let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("TEB must be kernel-backed") };
    let read64 = |offset: usize| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
    assert_eq!(read64(TEB_STACK_BASE_OFF), high);
    assert_eq!(read64(TEB_STACK_LIMIT_OFF), low);
    assert_eq!(read64(TEB_DEALLOCATION_STACK_OFF), low);
    assert!(!unmap_thread_teb(stack, &as_));
    assert!(as_.find_vma(teb).is_some());
    assert!(unmap_thread_teb(teb, &as_));
    assert!(as_.find_vma(teb).is_none());
    assert!(as_.munmap(stack, 0x8000).is_ok());
}

#[test]
fn thread_teb_rejects_one_sided_or_reversed_stack_bounds() {
    let as_ = AddressSpace::new(0x40_000).unwrap();
    assert_eq!(build_thread_teb_with_stack(1, 2, 3, 0x1000, 0, &as_), Err(Error::Einval));
    assert_eq!(build_thread_teb_with_stack(1, 2, 3, 0x2000, 0x1000, &as_), Err(Error::Einval));
    assert_eq!(as_.vma_count(), 0);
}

#[test]
fn process_teb_publishes_native_tls_layout_and_reserved_bitmap_bits() {
    let as_ = AddressSpace::new(0x20_000).unwrap();
    let e = build(&EnvironmentInput { image_base: 0x1400_0000, image_size: 0x5000,
        image_path: "C:\\Windows\\notepad.exe", command_line: "notepad.exe", environment: &[], process_id: 1, thread_id: 2 }, &as_).unwrap();
    let vma = as_.find_vma(e.base).unwrap();
    let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("environment must be kernel-backed") };
    let read32 = |offset: usize| u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
    let read64 = |offset: usize| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
    assert_eq!(read32(PEB_OFF + 0x80), 0x0001_0001);
    assert_eq!(read32(PEB_OFF + 0x84), 0);
    assert_eq!(read64(PEB_OFF + 0x78), e.base.as_u64() + TLS_BITMAP_DESC_OFF as u64);
    assert!(data[PEB_OFF + 0x240..PEB_OFF + 0x2c0].iter().all(|byte| *byte == 0));
    assert_eq!(read64(PEB_OFF + 0x238), e.base.as_u64() + TLS_EXP_BITMAP_DESC_OFF as u64);
    assert_eq!(read32(TLS_BITMAP_DESC_OFF), 64);
    assert_eq!(read32(TLS_EXP_BITMAP_DESC_OFF), 1024);
    assert_eq!(read64(TLS_BITMAP_DESC_OFF + 8), e.base.as_u64() + PEB_OFF as u64 + 0x80);
    assert_eq!(read64(TLS_EXP_BITMAP_DESC_OFF + 8), e.base.as_u64() + PEB_OFF as u64 + 0x240);
    assert_eq!(read32(TEB_OFF + TEB_CURRENT_LOCALE_OFF), 0x409);
    assert_eq!(read64(TEB_OFF + TEB_TLS_EXPANSION_SLOTS_OFF), 0);
}

#[test]
fn process_teb_publishes_the_actual_exec_stack_nt_tib_bounds() {
    let as_ = AddressSpace::new(0x40_000).unwrap();
    let stack = as_.mmap(None, 0x8000, VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE, VmaBacking::Anonymous, false).unwrap();
    let stack_top = stack.as_u64() + 0x8000;
    let e = build_with_modules_and_stack(&EnvironmentInput {
        image_base: 0x1400_0000, image_size: 0x5000, image_path: "C:\\Windows\\notepad.exe",
        command_line: "notepad.exe", environment: &[], process_id: 1, thread_id: 2,
    }, &[NtModuleInput { base: 0x1400_0000, entry: 0x1400_1000, size: 0x5000,
        full_name: "C:\\Windows\\notepad.exe", base_name: "notepad.exe" }], 0, stack_top, &as_).unwrap();
    let vma = as_.find_vma(e.base).unwrap();
    let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("environment must be kernel-backed") };
    let read64 = |offset: usize| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
    assert_eq!(read64(TEB_OFF + TEB_STACK_BASE_OFF), stack_top);
    assert_eq!(read64(TEB_OFF + TEB_STACK_LIMIT_OFF), stack.as_u64());
    assert_eq!(read64(TEB_OFF + TEB_DEALLOCATION_STACK_OFF), stack.as_u64());
}
