use super::*;
use super::super::{publish, runtime};
use core::cell::RefCell;

// Fedora Wine10.20-3.fc42 prepared winternl.h / unix_private.h, independently
// measured with x86 GCC15.2.1-7 and ARM GCC15.2.1-1: sizeof(PEB)=7c8,
// sizeof(TEB)=1838, sizeof(parameters)=410, native overlay=2f0..3d8.
const PEB_BYTES: usize = 0x7c8;
const TEB_BYTES: usize = 0x1838;
const PARAM_BYTES: usize = 0x410;
const WOW_OFFSET: usize = 0x180c;
const NATIVE_OFFSET: usize = 0x2f0;
const NATIVE_BYTES: usize = 0xe8;
const DEBUG_BUFFER_OFFSET: usize = 8;
const DEBUG_BUFFER_BYTES: usize = 1020;
const ARM_FRAME_BYTES: usize = 0x330;

fn get64(bytes: &[u8], offset: usize) -> u64 { u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) }
fn data(as_: &AddressSpace, address: UserVirtAddr) -> Vec<u8> {
    match as_.find_vma(address).unwrap().backing { VmaBacking::KernelBytes { data, .. } => data.to_vec(), _ => panic!("builder backing") }
}
fn module(index: usize) -> NtModuleInput<'static> {
    NtModuleInput { base: 0x180000000 + index as u64 * 0x10000, entry: 0, size: 0x1000, full_name: "C:\\Windows\\a.dll", base_name: "a.dll" }
}
fn fixture(count: usize, environment: &[(&str, &str)]) -> (alloc::sync::Arc<AddressSpace>, NtProcessEnvironment, Vec<u8>) {
    let as_ = AddressSpace::new(0x80000).unwrap();
    let modules: Vec<_> = (0..count).map(module).collect();
    let env = build_with_modules(&EnvironmentInput { image_base: 0x140000000, image_size: 0x1000,
        image_path: "a.exe", command_line: "a.exe", environment, process_id: 7, thread_id: 8 }, &modules, &as_).unwrap();
    let bytes = data(&as_, env.base);
    (as_, env, bytes)
}
fn assert_thread(bytes: &[u8], offset: usize, address: u64, peb: u64) {
    assert_eq!(get64(bytes, offset + 0x30), address);
    assert_eq!(get64(bytes, offset + 0x60), peb);
    assert_eq!(get64(bytes, offset + 0x58), address + THREAD_TLS_OFF as u64);
    assert_eq!(get64(bytes, offset + TEB_SYSCALL_FRAME_OFFSET), address + THREAD_SYSCALL_FRAME_OFF as u64);
    assert_eq!(&bytes[offset + WOW_OFFSET..offset + WOW_OFFSET + 4], &[0; 4]);
    let list = TEB_ACTIVATION_CONTEXT_STACK_INLINE + ACTIVATION_LIST_OFF;
    assert_eq!(get64(bytes, offset + list), address + list as u64);
    assert_eq!(get64(bytes, offset + list + POINTER_BYTES), address + list as u64);
    assert!(bytes[offset + 0x2a8..offset + 0x2b4].iter().all(|b| *b == 0));
    assert!(bytes[offset + TEB_TLS_SLOTS_OFF..offset + TEB_TLS_SLOTS_OFF + TEB_TLS_SLOTS * 8].iter().all(|b| *b == 0));
}

#[test]
fn empty_environment_declared_extent_is_accepted_by_runtime() {
    let (_, _, bytes) = fixture(1, &[]);
    let length = get64(&bytes, PARAM_OFF + PARAM_ENVIRONMENT_SIZE_OFF) as usize;
    let words: Vec<u16> = bytes[ENV_OFF..ENV_OFF + length].chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
    assert_eq!(runtime::environment_block_length(&words), Some(words.len()));
    assert_eq!(words, [0, 0]);
}

#[test]
fn full_catalog_and_max_environment_leave_complete_objects_disjoint() {
    let value = "x".repeat(ENV_BYTES / 2 - 4);
    let (as_, env, bytes) = fixture(MAX_MODULES, &[("K", &value)]);
    assert_eq!(as_.vma_count(), 1);
    assert_eq!(get64(&bytes, PARAM_OFF + PARAM_ENVIRONMENT_SIZE_OFF) as usize, ENV_BYTES);
    assert_thread(&bytes, TEB_OFF, env.teb.as_u64(), env.peb.as_u64());
    assert!(PEB_OFF + PEB_BYTES <= TEB_OFF);
    assert!(TEB_OFF + THREAD_TEB_BYTES <= PARAM_OFF);
    assert!(PARAM_OFF + PARAM_BYTES <= PROCESS_STR_OFF);
    assert_eq!(get64(&bytes, PARAM_OFF + PARAM_SHOW_WINDOW_OFF) as u32, SHOW_WINDOW_NORMAL);
    for i in 0..MAX_MODULES { assert_eq!(get64(&bytes, MOD_OFF + i * MOD_STRIDE + 0x30), module(i).base); }
    assert_eq!(&bytes[ENV_OFF + ENV_BYTES - 4..ENV_OFF + ENV_BYTES], &[0; 4]);
}

#[test]
fn environment_one_word_past_capacity_rolls_back() {
    let as_ = AddressSpace::new(0x80000).unwrap();
    let value = "x".repeat(ENV_BYTES / 2 - 3);
    assert!(build(&EnvironmentInput { image_base: 1, image_size: 4096, image_path: "a", command_line: "a",
        environment: &[("K", &value)], process_id: 1, thread_id: 1 }, &as_).is_err());
    assert_eq!(as_.vma_count(), 0);
}

fn write_scratch(bytes: &mut [u8], offset: usize, address: u64) {
    let before = bytes[offset..offset + TEB_BYTES].to_vec();
    let frame = (get64(bytes, offset + TEB_SYSCALL_FRAME_OFFSET) - address) as usize + offset;
    bytes[frame..frame + ARM_FRAME_BYTES].fill(0xa5);
    let tls = (get64(bytes, offset + 0x58) - address) as usize + offset;
    for slot in 0..THREAD_TLS_BYTES / POINTER_BYTES { put_u64(bytes, tls + slot * POINTER_BYTES, slot as u64 + 1); }
    let debug = offset + NT_DEBUG_INFO_OFFSET as usize;
    bytes[debug + DEBUG_BUFFER_OFFSET..debug + DEBUG_BUFFER_OFFSET + DEBUG_BUFFER_BYTES].fill(b'x');
    bytes[debug + DEBUG_BUFFER_OFFSET + DEBUG_BUFFER_BYTES - 1] = 0;
    assert!(bytes[frame..frame + ARM_FRAME_BYTES].iter().all(|b| *b == 0xa5));
    assert_eq!(&bytes[offset..offset + TEB_BYTES], &before);
}

#[test]
fn main_scratch_writes_preserve_teb_parameters_environment_and_catalog() {
    let (_, env, mut bytes) = fixture(MAX_MODULES, &[("K", "V")]);
    let before = bytes.clone();
    write_scratch(&mut bytes, TEB_OFF, env.teb.as_u64());
    bytes[TEB_OFF + NATIVE_OFFSET..TEB_OFF + NATIVE_OFFSET + NATIVE_BYTES].fill(0x5a);
    assert_eq!(&bytes[..PEB_BYTES], &before[..PEB_BYTES]);
    assert_eq!(&bytes[PARAM_OFF..], &before[PARAM_OFF..]);
}

#[test]
fn two_child_four_page_arenas_preserve_identity_and_scratch() {
    let (as_, env, _) = fixture(1, &[]);
    let first = build_thread_teb(7, 9, env.peb.as_u64(), &as_).unwrap();
    let second = build_thread_teb(7, 10, env.peb.as_u64(), &as_).unwrap();
    assert_ne!(first, second);
    for teb in [first, second] {
        let mut bytes = data(&as_, teb);
        assert_eq!(bytes.len(), 0x4000);
        assert_thread(&bytes, 0, teb.as_u64(), env.peb.as_u64());
        write_scratch(&mut bytes, 0, teb.as_u64());
        assert!(unmap_thread_teb(teb, &as_));
    }
    assert_eq!(as_.vma_count(), 1);
}

#[test]
fn catalog_commit_preserves_concurrent_non_catalog_mutations() {
    let (_, env, bytes) = fixture(1, &[]);
    let live = RefCell::new(bytes);
    let markers = [TEB_OFF + TEB_TLS_SLOTS_OFF, PARAM_OFF + PARAM_SHOW_WINDOW_OFF, PROCESS_STR_OFF, ENV_OFF, TLS_BITMAP_DESC_OFF];
    publish::publish_using(env.peb.as_u64(), &[module(1)], |address, target| {
        let offset = (address - env.base.as_u64()) as usize;
        assert_eq!((offset, target.len()), (LDR_OFF, ENV_OFF - LDR_OFF));
        target.copy_from_slice(&live.borrow()[offset..offset + target.len()]);
        for marker in markers { live.borrow_mut()[marker] = 0xa5; }
        Ok(())
    }, |address, source| {
        let offset = (address - env.base.as_u64()) as usize;
        assert_eq!((offset, source.len()), (LDR_OFF, ENV_OFF - LDR_OFF));
        live.borrow_mut()[offset..offset + source.len()].copy_from_slice(source);
        Ok(())
    }).unwrap();
    for marker in markers { assert_eq!(live.borrow()[marker], 0xa5); }
    assert_eq!(get64(&live.borrow(), MOD_OFF + MOD_STRIDE + 0x30), module(1).base);
}

fn descriptor(bytes: &[u8], base: u64, offset: usize) -> (usize, Vec<u16>) {
    let capacity = u16::from_le_bytes(bytes[offset + 2..offset + 4].try_into().unwrap()) as usize;
    let start = (get64(bytes, offset + 8) - base) as usize;
    let words = bytes[start..start + capacity].chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
    (start, words)
}

#[test]
fn appended_unicode_names_have_byte_disjoint_buffers_and_terminators() {
    let (_, env, mut bytes) = fixture(1, &[]);
    let module = NtModuleInput { full_name: "C:\\長い\\😀.dll", base_name: "😀.dll", ..module(1) };
    publish::plan(&mut bytes, env.base.as_u64(), &module).unwrap();
    let slot = MOD_OFF + MOD_STRIDE;
    let (full_at, full) = descriptor(&bytes, env.base.as_u64(), slot + 0x48);
    let (base_at, name) = descriptor(&bytes, env.base.as_u64(), slot + 0x58);
    assert_eq!(full, module.full_name.encode_utf16().chain(core::iter::once(0)).collect::<Vec<_>>());
    assert_eq!(name, module.base_name.encode_utf16().chain(core::iter::once(0)).collect::<Vec<_>>());
    assert_eq!(base_at, full_at + full.len() * WCHAR_BYTES);
}

#[test]
fn catalog_string_capacity_counts_bytes_before_any_mutation() {
    for free in [8, 6] {
        let (_, env, mut bytes) = fixture(1, &[]);
        for off in [0x48, 0x58] {
            put_u64(&mut bytes, MOD_OFF + off + 8, env.base.as_u64() + (ENV_OFF - free - 4) as u64);
            put_u16(&mut bytes, MOD_OFF + off + 2, 4);
        }
        let before = bytes.clone();
        let result = publish::plan(&mut bytes, env.base.as_u64(), &NtModuleInput { full_name: "x", base_name: "y", ..module(1) });
        if free == 8 { assert!(result.is_ok()); assert_eq!(&bytes[ENV_OFF - 8..ENV_OFF], &[b'x', 0, 0, 0, b'y', 0, 0, 0]); }
        else { assert_eq!(result, Err(Error::Einval)); assert_eq!(bytes, before); }
    }
}

#[test]
fn full_catalog_or_invalid_batch_never_calls_commit() {
    let (_, env, bytes) = fixture(MAX_MODULES, &[]);
    assert_eq!(publish::publish_using(env.base.as_u64(), &[module(99)], |address, target| {
        let offset = (address - env.base.as_u64()) as usize;
        target.copy_from_slice(&bytes[offset..offset + target.len()]); Ok(())
    }, |_, _| panic!("failed batch must not commit")), Err(Error::Einval));
}
