//! Native RTL string operations used by the Windows personality.
#![cfg(target_os = "oxide-kernel")]
#[path = "nt_rtl/wndproc_payload.rs"]
mod wndproc_payload;
pub(crate) use wndproc_payload::begin as begin_wndproc_payload_callback;
use syscall::{nt::{NtCall, NtService}, SyscallArgs}; use alloc::{string::String, vec, vec::Vec}; use sync::{Modules as ModulesLockClass, Spinlock};
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d; const STATUS_BUFFER_OVERFLOW: u64 = 0x8000_0005; const STATUS_INVALID_PARAMETER_2: u64 = 0xc000_00f0; const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
const STATUS_PENDING: u64 = 0x0000_0103; const STATUS_UNSUCCESSFUL: u64 = 0xc000_0001;
const STATUS_NO_CALLBACK_ACTIVE: u64 = 0xc000_0258;
const STATUS_NAME_TOO_LONG: u64 = 0xc000_0106; const UNICODE_STRING_BYTES: usize = 16; const CURDIR_BYTES: usize = UNICODE_STRING_BYTES + 8; const UNICODE_STRING_MAX: u32 = 0xfffc; const ANSI_STRING_MAX: u32 = 0xfffe;
const STATUS_INVALID_SID: u64 = 0xc000_0078; const STATUS_INVALID_ACL: u64 = 0xc000_0077; const STATUS_REVISION_MISMATCH: u64 = 0xc000_0059; const STATUS_ALLOTTED_SPACE_EXCEEDED: u64 = 0xc000_0099;
const ACL_HEADER_BYTES: usize = 8; const ACE_HEADER_BYTES: usize = 4; const SID_HEADER_BYTES: usize = 8; const MAX_SUBAUTHORITIES: usize = 15; const SECURITY_DESCRIPTOR_BYTES: usize = 20; const STATUS_UNKNOWN_REVISION: u64 = 0xc000_0058;
const TEXT_UNICODE_STATISTICS: u32 = 0x0002;
const TEXT_UNICODE_CONTROLS: u32 = 0x0004;
const TEXT_UNICODE_SIGNATURE: u32 = 0x0008;
const TEXT_UNICODE_REVERSE_MASK: u32 = 0x00f0;
const TEXT_UNICODE_NOT_UNICODE_MASK: u32 = 0x0f00;
const TEXT_UNICODE_NULL_BYTES: u32 = 0x1000;
const TEXT_UNICODE_NOT_ASCII_MASK: u32 = 0xf000;
const TEXT_UNICODE_ODD_LENGTH: u32 = 0x0200;
const STATUS_SUCCESS: u64 = 0;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const PRODUCT_UNDEFINED: u32 = 0;
const PRODUCT_ULTIMATE_N: u32 = 0x1c;
const MUI_LANGUAGE_ID: u32 = 0x04;
const MUI_LANGUAGE_NAME: u32 = 0x08;
const MUI_MACHINE_LANGUAGE_SETTINGS: u32 = 0x400;
const UI_LANGUAGE_NAME_U16: [u16; 7] = [b'e' as u16, b'n' as u16, b'-' as u16, b'U' as u16, b'S' as u16, 0, 0];
const UI_LANGUAGE_ID_U16: [u16; 6] = [b'0' as u16, b'4' as u16, b'0' as u16, b'9' as u16, 0, 0];
const WINDOWS_VERSION_INFO_BYTES: usize = 284;
const WINDOWS_VERSION_SIZE: u32 = WINDOWS_VERSION_INFO_BYTES as u32;
const WINDOWS_VERSION_MAJOR: u32 = 10;
const WINDOWS_VERSION_MINOR: u32 = 0;
const WINDOWS_VERSION_BUILD: u32 = 19045;
const WINDOWS_PLATFORM_NT: u32 = 2;
const WINDOWS_SUITE_SINGLE_USER_TS: u16 = 0x0100;
const WINDOWS_PRODUCT_WORKSTATION: u8 = 1;
const GUID_STRING_BYTES: usize = 76;
const TEB_PEB_OFFSET: u64 = 0x60;
const PEB_PROCESS_PARAMETERS_OFFSET: u64 = 0x20;
const PARAM_CURRENT_DIRECTORY_OFFSET: u64 = 0x38;
const PARAM_CURRENT_DIRECTORY_HANDLE_OFFSET: u64 = 0x48;
const PARAM_IMAGE_PATH_OFFSET: u64 = 0x60;
const PARAM_ENVIRONMENT_OFFSET: u64 = 0x80;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const STATUS_NOT_SUPPORTED: u64 = 0xc000_00bb;
const STATUS_OBJECT_NAME_INVALID: u64 = 0xc000_0033;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
const STATUS_OBJECT_PATH_NOT_FOUND: u64 = 0xc000_003a;
const STATUS_NOT_A_DIRECTORY: u64 = 0xc000_0103;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const CONTEXT_AMD64: u32 = 0x0010_0000;
const CONTEXT_AMD64_ALL: u32 = 0x0010_001f;
const CONTEXT_XSTATE: u32 = 0x0040;
const CONTEXT_ALLOWED: u32 = 0xd800_0000 | CONTEXT_AMD64_ALL | CONTEXT_XSTATE;
const AMD64_CONTEXT_BYTES: u64 = 0x4d0;
const CONTEXT_EX_BYTES: u64 = 0x20;
#[cfg(target_arch = "x86_64")]
const XSTATE_LEGACY_BYTES: u64 = 512;
#[cfg(target_arch = "x86_64")]
const XSTATE_HEADER_BYTES: u64 = 64;
use crate::nt_wine_window::pfn::{self, CLIENT_PROCS_BYTES as NTUSER_CLIENT_PROCS_BYTES, WORKERS_BYTES as NTUSER_WORKERS_BYTES};

pub(crate) fn validate_nt_user_pfn_table(base: u64, bytes: u64) -> bool {
    pfn::validate_table(base, bytes, |address| uaccess::get_user_u64(address).is_ok())
}

pub(crate) fn validate_nt_user_pfn_tables(a: u64, w: u64, workers: u64) -> bool {
    validate_nt_user_pfn_table(a, NTUSER_CLIENT_PROCS_BYTES)
        && validate_nt_user_pfn_table(w, NTUSER_CLIENT_PROCS_BYTES)
        && validate_nt_user_pfn_table(workers, NTUSER_WORKERS_BYTES)
}

/// Convert the fixed Windows GUID spelling into its 16-byte little-endian ABI.
/// # C: O(1) plus bounded usercopy
fn guid_from_string(descriptor: u64, target: u64) -> u64 {
    if descriptor == 0 || target == 0 { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut header, descriptor).is_err() { return STATUS_INVALID_PARAMETER; }
    let length = u16::from_le_bytes([header[0], header[1]]) as usize;
    let buffer = u64::from_le_bytes(header[8..16].try_into().unwrap());
    if length < GUID_STRING_BYTES || buffer == 0 { return STATUS_INVALID_PARAMETER; }
    let mut text = [0u8; GUID_STRING_BYTES];
    if uaccess::copy_from_user(&mut text, buffer).is_err() { return STATUS_INVALID_PARAMETER; }
    let at = |index: usize| -> Option<u8> {
        let value = u16::from_le_bytes([text[index * 2], text[index * 2 + 1]]);
        (value <= 0x7f).then_some(value as u8)
    };
    if at(0) != Some(b'{') || at(9) != Some(b'-') || at(14) != Some(b'-') || at(19) != Some(b'-') || at(24) != Some(b'-') || at(37) != Some(b'}') {
        return STATUS_INVALID_PARAMETER;
    }
    let hex = |index: usize| -> Option<u8> {
        match at(index)? {
            b'0'..=b'9' => Some(at(index)? - b'0'), b'a'..=b'f' => Some(at(index)? - b'a' + 10),
            b'A'..=b'F' => Some(at(index)? - b'A' + 10), _ => None,
        }
    };
    let pair = |index: usize| -> Option<u8> { Some((hex(index)? << 4) | hex(index + 1)?) };
    let positions = [1usize, 3, 5, 7, 10, 12, 15, 17, 20, 22, 25, 27, 29, 31, 33, 35];
    let mut parsed = [0u8; 16];
    for (slot, position) in positions.iter().enumerate() {
        let Some(value) = pair(*position) else { return STATUS_INVALID_PARAMETER; };
        parsed[slot] = value;
    }
    let mut guid = [0u8; 16];
    guid[0] = parsed[3]; guid[1] = parsed[2]; guid[2] = parsed[1]; guid[3] = parsed[0];
    guid[4] = parsed[5]; guid[5] = parsed[4]; guid[6] = parsed[7]; guid[7] = parsed[6];
    guid[8..].copy_from_slice(&parsed[8..]);
    if uaccess::copy_to_user(target, &guid).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
}
/// Initialize a Windows `UNICODE_STRING` descriptor without copying its source.
/// # C: O(min(source length, 32766)) plus usercopy
pub fn dispatch(call: NtCall) -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    if let Some(result) = crate::nt_rtl_xstate::dispatch(call) { return Some(result); }
    if call.service == NtService::RtlGetExePath { return Some(get_exe_path(call.args.a0, call.args.a1)); }
    if call.service == NtService::RtlInitializeNtUserPfn {
        let Some([a0, a1, a2, a3, a4, a5]) = pfn::initialize_args([
            call.args.a0, call.args.a1, call.args.a2, call.args.a3, call.args.a4, call.args.a5,
        ]) else { return Some(STATUS_INVALID_PARAMETER); };
        let call = NtCall { service: call.service, args: SyscallArgs { a0, a1, a2, a3, a4, a5 } };
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        klog::write_raw(b"[WINDOWS-USER32-INIT] rtl-pfn a=");
        klog::write_hex_u64(call.args.a1);
        klog::write_raw(b" w=");
        klog::write_hex_u64(call.args.a3);
        klog::write_raw(b" workers=");
        klog::write_hex_u64(call.args.a5);
        klog::write_raw(b" ptrs=");
        klog::write_hex_u64(call.args.a0);
        klog::write_raw(b",");
        klog::write_hex_u64(call.args.a2);
        klog::write_raw(b",");
        klog::write_hex_u64(call.args.a4);
        klog::write_raw(b"\n");
        if !cur.is_nt_personality() {
            return Some(STATUS_INVALID_PARAMETER);
        }
        if (call.args.a1 != 0 && call.args.a0 == 0) || (call.args.a3 != 0 && call.args.a2 == 0)
            || (call.args.a5 != 0 && call.args.a4 == 0)
            || !validate_nt_user_pfn_table(call.args.a0, call.args.a1)
            || !validate_nt_user_pfn_table(call.args.a2, call.args.a3)
            || !validate_nt_user_pfn_table(call.args.a4, call.args.a5) {
            return Some(STATUS_INVALID_PARAMETER);
        }
        let mut state = cur.thread_group.nt_user_pfn.lock();
        if state.is_some() { return Some(STATUS_INVALID_PARAMETER); }
        *state = Some([call.args.a0, call.args.a1, call.args.a2, call.args.a3, call.args.a4, call.args.a5]);
        klog::write_raw(b"[WINDOWS-USER32-INIT] rtl-pfn-published\n");
        return Some(STATUS_SUCCESS);
    }
    if call.service == NtService::RtlRetrieveNtUserPfn {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 || call.args.a1 == 0 || call.args.a2 == 0 {
            return Some(STATUS_INVALID_PARAMETER);
        }
        let Some(state) = *cur.thread_group.nt_user_pfn.lock() else { return Some(STATUS_INVALID_PARAMETER); };
        klog::write_raw(b"[WINDOWS-USER32-INIT] retrieve out=");
        klog::write_hex_u64(call.args.a0);
        klog::write_raw(b",");
        klog::write_hex_u64(call.args.a1);
        klog::write_raw(b",");
        klog::write_hex_u64(call.args.a2);
        klog::write_raw(b" state=");
        klog::write_hex_u64(state[0]);
        klog::write_raw(b",");
        klog::write_hex_u64(state[2]);
        klog::write_raw(b",");
        klog::write_hex_u64(state[4]);
        klog::write_raw(b"\n");
        if uaccess::put_user_u64(call.args.a0, state[0]).is_err()
            || uaccess::put_user_u64(call.args.a1, state[2]).is_err()
            || uaccess::put_user_u64(call.args.a2, state[4]).is_err() {
            return Some(STATUS_INVALID_PARAMETER);
        }
        return Some(STATUS_SUCCESS);
    }
    if call.service == NtService::RtlResetNtUserPfn {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
        let mut state = cur.thread_group.nt_user_pfn.lock();
        if state.take().is_none() { return Some(STATUS_INVALID_PARAMETER); }
        return Some(STATUS_SUCCESS);
    }
    if call.service == NtService::RtlWow64EnableFsRedirection { return Some(STATUS_SUCCESS); }
    if call.service == NtService::RtlWow64EnableFsRedirectionEx {
        if call.args.a1 != 0 && uaccess::put_user_u32(call.args.a1, 0).is_err() { return Some(STATUS_ACCESS_VIOLATION); }
        return Some(STATUS_SUCCESS);
    }
    if call.service == NtService::RtlWow64GetProcessMachines {
        if call.args.a1 != 0 && uaccess::copy_to_user(call.args.a1, &0u16.to_le_bytes()).is_err() { return Some(STATUS_ACCESS_VIOLATION); }
        if call.args.a2 != 0 && uaccess::copy_to_user(call.args.a2, &IMAGE_FILE_MACHINE_AMD64.to_le_bytes()).is_err() { return Some(STATUS_ACCESS_VIOLATION); }
        return Some(STATUS_SUCCESS);
    }
    if call.service == NtService::RtlWow64GetThreadContext { return Some(STATUS_INVALID_PARAMETER); }
    if call.service == NtService::RtlWow64SetThreadContext { return Some(STATUS_INVALID_PARAMETER); }
    if call.service == NtService::RtlZombifyActivationContext { return Some(STATUS_NOT_IMPLEMENTED); }
    if call.service == NtService::RtlGetExtendedContextLength2 { return Some(get_extended_context_length(call.args.a0 as u32, call.args.a1, call.args.a2)); }
    if call.service == NtService::RtlInitializeExtendedContext2 { return Some(initialize_extended_context(call.args.a0, call.args.a1 as u32, call.args.a2, call.args.a3)); }
    if call.service == NtService::RtlGetExtendedFeaturesMask { return Some(get_extended_features_mask(call.args.a0)); }
    if call.service == NtService::RtlSetExtendedFeaturesMask { return Some(set_extended_features_mask(call.args.a0, call.args.a1)); }
    if call.service == NtService::RtlGetFullPathNameU { return Some(get_full_path(call.args.a0, call.args.a1, call.args.a2, call.args.a3)); }
    if call.service == NtService::RtlGetProductInfo { return Some(get_product_info(call)); }
    if call.service == NtService::RtlGetProcessPreferredUILanguages { return Some(get_process_preferred_ui_languages(call)); }
    if call.service == NtService::RtlSetProcessPreferredUILanguages { return Some(set_process_preferred_ui_languages(call)); }
    if call.service == NtService::RtlGetSearchPath { return Some(get_search_path(call.args.a0)); }
    if call.service == NtService::RtlReleasePath { return Some(release_path(call.args.a0)); }
    if call.service == NtService::RtlRunOnceBeginInitialize { return Some(run_once_begin_initialize(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::RtlRunOnceComplete { return Some(run_once_complete(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::RtlRunOnceExecuteOnce {
        #[cfg(target_arch = "x86_64")]
        { return Some(run_once_execute_once_x86(call.args.a0, call.args.a1, call.args.a2, call.args.a3)); }
        #[cfg(target_arch = "aarch64")]
        { return Some(STATUS_NOT_SUPPORTED); }
    }
    if call.service == NtService::RtlGetSystemPreferredUILanguages { return Some(get_system_preferred_ui_languages(call)); }
    if call.service == NtService::RtlSetThreadErrorMode { return Some(set_thread_error_mode(call.args.a0 as u32, call.args.a1)); }
    if call.service == NtService::RtlSetThreadPreferredUILanguages { return Some(set_thread_preferred_ui_languages(call)); }
    if call.service == NtService::RtlGetThreadErrorMode { return Some(get_thread_error_mode()); }
    if call.service == NtService::RtlGetThreadPreferredUILanguages { return Some(get_thread_preferred_ui_languages(call)); }
    if call.service == NtService::RtlGetUserPreferredUILanguages { return Some(get_user_preferred_ui_languages(call)); }
    if call.service == NtService::RtlGetVersion { return Some(get_version(call.args.a0)); }
    if call.service == NtService::RtlImpersonateSelf { return Some(impersonate_self(call.args.a0 as u32)); }
    if call.service == NtService::RtlIsProcessorFeaturePresent { return Some(is_processor_feature_present(call.args.a0 as u32)); }
    if call.service == NtService::RtlGetEnabledExtendedFeatures {
        const LEGACY_XSTATE: u64 = 0x3;
        #[cfg(target_arch = "x86_64")]
        let enabled = LEGACY_XSTATE | hal_x86_64::xsave_xcr0();
        #[cfg(not(target_arch = "x86_64"))]
        let enabled = LEGACY_XSTATE;
        return Some(enabled & call.args.a0);
    }
    if call.service == NtService::RtlGetCurrentPeb {
        let Some(task) = sched::live::current() else { return Some(0); };
        if !task.is_nt_personality() { return Some(0); }
        let Some(address) = task.nt_teb().checked_add(TEB_PEB_OFFSET) else { return Some(0); };
        return Some(uaccess::get_user_u64(address).ok().unwrap_or(0));
    }
    if call.service == NtService::RtlGetCurrentDirectoryU {
        return Some(get_current_directory(call.args.a0, call.args.a1));
    }
    if call.service == NtService::RtlSetCurrentDirectoryU {
        return Some(set_current_directory(call.args.a0));
    }
    if call.service == NtService::RtlDeleteBarrier { return Some(0); }
    if call.service == NtService::RtlInitBarrier { return Some(init_barrier(call.args.a0, call.args.a1 as u32, call.args.a2 as u32)); }
    if let Some(result) = crate::nt_rtl_integer::dispatch(call) { return Some(result); }
    if let Some(result) = crate::nt_rtl_ansi::dispatch(call) { return Some(result); }
    if let Some(result) = crate::nt_debug::dispatch(call) { return Some(result); }
    if call.service == NtService::RtlGUIDFromString { return Some(guid_from_string(call.args.a0, call.args.a1)); }
    if let Some(result) = crate::nt_critical::dispatch(call) { return Some(result); }
    if call.service == NtService::RtlAreBitsClear { return Some(are_bits_clear(call.args.a0, call.args.a1 as u32, call.args.a2 as u32)); }
    if call.service == NtService::RtlAreBitsSet { return Some(are_bits_set(call.args.a0, call.args.a1 as u32, call.args.a2 as u32)); }
    if call.service == NtService::RtlSetBits { return Some(set_bits(call.args.a0, call.args.a1 as u32, call.args.a2 as u32)); }
    if call.service == NtService::RtlInitializeBitMap { return Some(initialize_bitmap(call.args.a0, call.args.a1, call.args.a2 as u32)); }
    if call.service == NtService::RtlSetLastWin32Error || call.service == NtService::RtlRestoreLastWin32Error { return Some(set_last_win32_error(call.args.a0)); }
    if call.service == NtService::RtlGetLastWin32Error { return Some(get_last_win32_error()); }
    if call.service == NtService::RtlDosPathNameToNtPathNameU { return Some(dos_path_to_nt(call.args.a0, call.args.a1, call.args.a2, call.args.a3)); }
    if call.service == NtService::RtlDosPathNameToNtPathNameUWithStatus { return Some(if dos_path_to_nt(call.args.a0, call.args.a1, call.args.a2, call.args.a3) == 1 { 0 } else { STATUS_INVALID_PARAMETER }); }
    if call.service == NtService::RtlCreateUnicodeStringFromAsciiz { return Some(create_unicode_string_from_ascii(call.args.a0, call.args.a1)); }
    if call.service == NtService::RtlCreateUnicodeString { return Some(create_unicode_string(call.args.a0, call.args.a1)); }
    if call.service == NtService::RtlAnsiStringToUnicodeString { return Some(ansi_to_unicode_string(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::RtlUnicodeStringToAnsiSize { return Some(unicode_string_to_ansi_size(call.args.a0)); }
    if call.service == NtService::RtlCharToInteger { return Some(char_to_integer(call.args.a0, call.args.a1 as u32, call.args.a2)); }
    if call.service == NtService::RtlFreeUnicodeString { return Some(free_unicode_string(call.args.a0)); }
    if call.service == NtService::RtlFreeAnsiString { return Some(free_ansi_string(call.args.a0)); }
    if call.service == NtService::RtlGetAce { return Some(get_ace(call.args.a0, call.args.a1 as u32, call.args.a2)); }
    if call.service == NtService::RtlGetControlSecurityDescriptor { return Some(get_security_control(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::RtlIsTextUnicode { return Some(is_text_unicode(call.args.a0, call.args.a1 as i64, call.args.a2)); }
    if call.service == NtService::RtlLengthSecurityDescriptor { return Some(length_security_descriptor(call.args.a0)); }
    if call.service == NtService::RtlMakeSelfRelativeSD { return Some(make_self_relative_sd(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::RtlNtStatusToDosError { return Some(nt_status_to_dos_error(call.args.a0 as u32) as u64); }
    if call.service == NtService::RtlQueryInformationAcl { return Some(query_acl(call.args.a0, call.args.a1, call.args.a2 as u32, call.args.a3 as u32)); }
    if call.service == NtService::RtlUniform { return Some(uniform(call.args.a0)); }
    if call.service == NtService::RtlRandom { return Some(random(call.args.a0)); }
    if call.service == NtService::WineGetHostVersion { return Some(host_version(call.args.a0, call.args.a1)); }
    if call.service == NtService::RtlInterlockedFlushSList { return Some(flush_slist(call.args.a0)); }
    if call.service == NtService::RtlInterlockedPushEntrySList { return Some(push_slist(call.args.a0, call.args.a1)); }
    if call.service == NtService::RtlCreateSecurityDescriptor { return Some(create_security_descriptor(call.args.a0, call.args.a1 as u32)); }
    if call.service == NtService::RtlCreateAcl { return Some(create_acl(call.args.a0, call.args.a1 as u32, call.args.a2 as u32)); }
    if call.service == NtService::RtlAreAllAccessesGranted { return Some(((call.args.a0 as u32 & call.args.a1 as u32) == call.args.a1 as u32) as u64); }
    if call.service == NtService::RtlAreAnyAccessesGranted { return Some(((call.args.a0 as u32 & call.args.a1 as u32) != 0) as u64); }
    if call.service == NtService::RtlAddAce { return Some(add_aces(call.args.a0, call.args.a1 as u32, call.args.a3, call.args.a4 as u32)); }
    if matches!(call.service, NtService::RtlAddAccessAllowedAce | NtService::RtlAddAccessAllowedAceEx | NtService::RtlAddAccessDeniedAce | NtService::RtlAddAccessDeniedAceEx) {
        let (acl, revision, flags, mask, sid) = if matches!(call.service, NtService::RtlAddAccessAllowedAce | NtService::RtlAddAccessDeniedAce) {
            (call.args.a0, call.args.a1 as u32, 0, call.args.a2 as u32, call.args.a3)
        } else { (call.args.a0, call.args.a1 as u32, call.args.a2 as u32, call.args.a3 as u32, call.args.a4) };
        let ace_type = if matches!(call.service, NtService::RtlAddAccessAllowedAce | NtService::RtlAddAccessAllowedAceEx) { 0 } else { 1 };
        return Some(add_access_ace(acl, revision, flags, mask, sid, ace_type));
    }
    let ansi = matches!(call.service, NtService::RtlInitAnsiString | NtService::RtlInitAnsiStringEx);
    let strict = match call.service {
        NtService::RtlInitUnicodeString | NtService::RtlInitAnsiString => false,
        NtService::RtlInitUnicodeStringEx | NtService::RtlInitAnsiStringEx => true,
        _ => return None,
    };
    let target = call.args.a0;
    if target == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let source = call.args.a1;
    let (length, maximum) = if source == 0 { (0u32, 0u32) } else {
        let max = if ansi { ANSI_STRING_MAX } else { UNICODE_STRING_MAX };
        let width: u64 = if ansi { 1 } else { 2 };
        let last = if ansi { 0xffff } else { 0x7fff };
        let mut length = max;
        for index in 0..=last {
            let Some(address) = source.checked_add(index * width) else { return Some(STATUS_INVALID_PARAMETER); };
            let mut word = [0u8; 2];
            if uaccess::copy_from_user(&mut word[..width as usize], address).is_err() { return Some(STATUS_INVALID_PARAMETER); }
            if (ansi && word[0] == 0) || (!ansi && word == [0, 0]) {
                let candidate = (index as u32) * width as u32;
                if strict && candidate > max { return Some(STATUS_NAME_TOO_LONG); }
                length = candidate;
                break;
            }
            if strict && index == last { return Some(STATUS_NAME_TOO_LONG); }
        }
        (length, length.saturating_add(if ansi { 1 } else { 2 }))
    };
    let mut descriptor = [0u8; UNICODE_STRING_BYTES];
    descriptor[0..2].copy_from_slice(&(length as u16).to_le_bytes());
    descriptor[2..4].copy_from_slice(&(maximum as u16).to_le_bytes());
    descriptor[8..16].copy_from_slice(&source.to_le_bytes());
    if uaccess::copy_to_user(target, &descriptor).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    Some(0)
}

/// Return the Windows processor-feature bit for the x86_64 execution target.
/// The feature numbers are stable Windows ABI values; the xsave mask is read
/// from the same native CPU state used by the kernel's signal implementation.
fn is_processor_feature_present(feature: u32) -> u64 {
    match feature {
        2 | 3 | 8 | 9 | 10 | 12 | 13 => 1,
        17 => {
            #[cfg(target_arch = "x86_64")]
            { u64::from(hal_x86_64::xsave_xcr0() != 0) }
            #[cfg(not(target_arch = "x86_64"))]
            { 0 }
        }
        18 => {
            #[cfg(target_arch = "x86_64")]
            { u64::from(hal_x86_64::xsave_xcr0() & 0x6 == 0x6) }
            #[cfg(not(target_arch = "x86_64"))]
            { 0 }
        }
        _ => 0,
    }
}

fn get_full_path(name: u64, size: u64, buffer: u64, file_part: u64) -> u64 {
    if name == 0 { return 0; }
    let Some(input) = read_wide_z(name) else { return 0; };
    if input.is_empty() || input.iter().all(|&value| value == b' ' as u16) { return 0; }
    let Some(task) = sched::live::current() else { return 0; };
    if !task.is_nt_personality() { return 0; }
    let teb = task.nt_teb();
    let Some(peb_address) = teb.checked_add(TEB_PEB_OFFSET) else { return 0; };
    let peb = uaccess::get_user_u64(peb_address).ok().unwrap_or(0);
    let Some(params_address) = peb.checked_add(PEB_PROCESS_PARAMETERS_OFFSET) else { return 0; };
    let params = uaccess::get_user_u64(params_address).ok().unwrap_or(0);
    let Some(current_address) = params.checked_add(PARAM_CURRENT_DIRECTORY_OFFSET) else { return 0; };
    let Some(current) = read_nt_unicode(current_address) else { return 0; };
    let mut path = absolute_path(&input, &current);
    collapse_path(&mut path);
    let required = match path.len().checked_add(1).and_then(|len| len.checked_mul(2)) { Some(value) => value, None => return 0 };
    if required > size as usize { return required as u64; }
    let Some(terminator) = buffer.checked_add((path.len() * 2) as u64) else { return 0; };
    if buffer == 0 || uaccess::copy_to_user(buffer, &wide_bytes(&path)).is_err() || uaccess::copy_to_user(terminator, &[0, 0]).is_err() { return 0; }
    if file_part != 0 {
        let mut start = 0usize; for (index, &value) in path.iter().enumerate() { if value == b'\\' as u16 { start = index + 1; } }
        let Some(file_address) = buffer.checked_add((start * 2) as u64) else { return 0; };
        if uaccess::copy_to_user(file_part, &file_address.to_le_bytes()).is_err() { return 0; }
    }
    (path.len() * 2) as u64
}
fn absolute_path(input: &[u16], current: &[u16]) -> alloc::vec::Vec<u16> {
    let slash = |value: u16| value == b'\\' as u16 || value == b'/' as u16;
    let mut path = alloc::vec::Vec::new();
    if input.len() >= 2 && slash(input[0]) && slash(input[1]) { path.extend_from_slice(input); }
    else if input.len() >= 3 && input[1] == b':' as u16 && slash(input[2]) { path.extend_from_slice(input); }
    else if input.first().is_some_and(|&value| slash(value)) { path.extend_from_slice(&current[..core::cmp::min(2, current.len())]); path.extend_from_slice(input); }
    else if input.len() >= 2 && input[1] == b':' as u16 {
        if current.len() >= 2 && ascii_lower(current[0]) == ascii_lower(input[0]) { path.extend_from_slice(current); if path.last().is_some_and(|&value| !slash(value)) { path.push(b'\\' as u16); } path.extend_from_slice(&input[2..]); }
        else { path.extend_from_slice(&input[..2]); path.push(b'\\' as u16); path.extend_from_slice(&input[2..]); }
    } else { path.extend_from_slice(current); if path.last().is_some_and(|&value| !slash(value)) { path.push(b'\\' as u16); } path.extend_from_slice(input); }
    path
}
fn ascii_lower(value: u16) -> u16 { if (b'A' as u16..=b'Z' as u16).contains(&value) { value + (b'a' - b'A') as u16 } else { value } }
fn collapse_path(path: &mut alloc::vec::Vec<u16>) {
    for value in path.iter_mut() { if *value == b'/' as u16 { *value = b'\\' as u16; } }
    let root = if path.len() >= 2 && path[1] == b':' as u16 { 3 } else if path.len() >= 2 && path[0] == b'\\' as u16 && path[1] == b'\\' as u16 { 2 } else { 0 };
    let mut output = alloc::vec::Vec::new(); let mut index = 0usize;
    while index < path.len() {
        while index < path.len() && path[index] == b'\\' as u16 { if output.last() != Some(&(b'\\' as u16)) { output.push(path[index]); } index += 1; }
        let start = index; while index < path.len() && path[index] != b'\\' as u16 { index += 1; }
        let component = &path[start..index];
        if component == [b'.' as u16] { continue; }
        if component == [b'.' as u16, b'.' as u16] && output.len() > root { while output.len() > root && output.pop() != Some(b'\\' as u16) {} continue; }
        if !component.is_empty() { if !output.is_empty() && output.last() != Some(&(b'\\' as u16)) { output.push(b'\\' as u16); } output.extend_from_slice(component); }
    }
    *path = output;
}
fn wide_bytes(value: &[u16]) -> alloc::vec::Vec<u8> { let mut output = alloc::vec![0u8; value.len() * 2]; for (index, unit) in value.iter().enumerate() { output[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes()); } output }

fn get_extended_features_mask(context_ex: u64) -> u64 {
    if context_ex == 0 { return 0; }
    let mut chunk = [0u8; 4];
    if uaccess::copy_from_user(&mut chunk, context_ex.saturating_add(16)).is_err() { return 0; }
    let offset = i32::from_le_bytes(chunk) as i64;
    if offset < 0 { return 0; }
    let Some(xstate) = context_ex.checked_add(offset as u64) else { return 0; };
    let mut mask = [0u8; 8];
    if uaccess::copy_from_user(&mut mask, xstate).is_err() { return 0; }
    u64::from_le_bytes(mask) & !3
}

fn set_extended_features_mask(context_ex: u64, feature_mask: u64) -> u64 {
    if context_ex == 0 { return STATUS_INVALID_PARAMETER; }
    let mut descriptor = [0u8; 4];
    if uaccess::copy_from_user(&mut descriptor, context_ex.saturating_add(16)).is_err() { return STATUS_INVALID_PARAMETER; }
    let offset = i32::from_le_bytes(descriptor) as i64;
    if offset < 0 { return STATUS_INVALID_PARAMETER; }
    let Some(xstate) = context_ex.checked_add(offset as u64) else { return STATUS_INVALID_PARAMETER; };
    #[cfg(target_arch = "x86_64")]
    let enabled = hal_x86_64::xsave_xcr0();
    #[cfg(not(target_arch = "x86_64"))]
    let enabled = 0;
    if uaccess::put_user_u64(xstate, enabled & feature_mask & !3).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn get_extended_context_length(flags: u32, length: u64, compaction_mask: u64) -> u64 {
    if length == 0 || flags & CONTEXT_AMD64 == 0 || flags & !CONTEXT_ALLOWED != 0 { return STATUS_INVALID_PARAMETER; }
    if flags & CONTEXT_XSTATE == 0 { return if uaccess::put_user_u32(length, (AMD64_CONTEXT_BYTES + CONTEXT_EX_BYTES + 7) as u32).is_ok() { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER }; }
    #[cfg(not(target_arch = "x86_64"))]
    { let _ = compaction_mask; return STATUS_NOT_SUPPORTED; }
    #[cfg(target_arch = "x86_64")]
    {
        let supported = hal_x86_64::xsave_xcr0();
        if !hal_x86_64::xsave_active() || supported == 0 { return STATUS_NOT_SUPPORTED; }
        let requested = compaction_mask & supported & !3;
        let xsave = hal_x86_64::xsave_area_bytes() as u64;
        let tail = if requested == 0 { XSTATE_HEADER_BYTES } else { xsave.saturating_sub(XSTATE_LEGACY_BYTES).max(XSTATE_HEADER_BYTES) };
        let total = AMD64_CONTEXT_BYTES + CONTEXT_EX_BYTES + 63 + tail;
        if total > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
        if uaccess::put_user_u32(length, total as u32).is_ok() { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER }
    }
}

fn initialize_extended_context(context: u64, flags: u32, context_ex: u64, compaction_mask: u64) -> u64 {
    if context == 0 || context_ex == 0 || flags & CONTEXT_AMD64 == 0 || flags & !CONTEXT_ALLOWED != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if flags & CONTEXT_XSTATE != 0 {
        let _ = compaction_mask;
        return STATUS_NOT_SUPPORTED;
    }
    let aligned = match context.checked_add(15) { Some(value) => value & !15, None => return STATUS_INVALID_PARAMETER };
    let extended = match aligned.checked_add(AMD64_CONTEXT_BYTES) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    if uaccess::put_user_u32(aligned + 0x30, flags).is_err() || uaccess::put_user_u64(context_ex, extended).is_err() {
        return STATUS_INVALID_PARAMETER;
    }
    let mut descriptor = [0u8; CONTEXT_EX_BYTES as usize];
    descriptor[0..4].copy_from_slice(&(-(AMD64_CONTEXT_BYTES as i32)).to_le_bytes());
    descriptor[4..8].copy_from_slice(&(AMD64_CONTEXT_BYTES as u32).to_le_bytes());
    descriptor[8..12].copy_from_slice(&(-(AMD64_CONTEXT_BYTES as i32)).to_le_bytes());
    descriptor[12..16].copy_from_slice(&(AMD64_CONTEXT_BYTES + 24).to_le_bytes());
    descriptor[16..20].copy_from_slice(&25u32.to_le_bytes());
    if uaccess::copy_to_user(extended, &descriptor).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn get_exe_path(name: u64, result: u64) -> u64 {
    if name == 0 || result == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(task) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !task.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let teb = task.nt_teb();
    let Some(peb_address) = teb.checked_add(TEB_PEB_OFFSET) else { return STATUS_INVALID_PARAMETER; };
    let peb = uaccess::get_user_u64(peb_address).ok().unwrap_or(0);
    let Some(params_address) = peb.checked_add(PEB_PROCESS_PARAMETERS_OFFSET) else { return STATUS_INVALID_PARAMETER; };
    let params = uaccess::get_user_u64(params_address).ok().unwrap_or(0);
    if params == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(image_address) = params.checked_add(PARAM_IMAGE_PATH_OFFSET) else { return STATUS_INVALID_PARAMETER; };
    let image = read_nt_unicode(image_address);
    let Some(image) = image else { return STATUS_INVALID_PARAMETER; };
    let name = read_wide_z(name);
    let Some(name) = name else { return STATUS_INVALID_PARAMETER; };
    let Some(environment_address) = params.checked_add(PARAM_ENVIRONMENT_OFFSET) else { return STATUS_INVALID_PARAMETER; };
    let no_default = env_has_name(environment_address, b"NoDefaultCurrentDirectoryInExePath");
    let mut path = alloc::vec::Vec::new();
    let mut end = image.len();
    for index in (0..image.len()).rev() {
        if image[index] == b'\\' as u16 || image[index] == b'/' as u16 { end = index + 1; break; }
        if index == 0 { end = 0; }
    }
    append_wide(&mut path, &image[..end]);
    if !no_default && !name.iter().any(|&value| value == b'\\' as u16) { append_wide(&mut path, &wide(b".")); }
    append_wide(&mut path, &wide(b"C:\\windows\\system32;C:\\windows\\system;C:\\windows"));
    if let Some(value) = env_value(environment_address, b"PATH") { append_wide(&mut path, &value); }
    let bytes = match path.len().checked_add(1).and_then(|len| len.checked_mul(2)) { Some(value) if value <= u16::MAX as usize => value, _ => return STATUS_NO_MEMORY };
    let allocation = NtCall { service: NtService::AllocateHeap, args: SyscallArgs { a0: 0, a1: 0, a2: bytes as u64, a3: 0, a4: 0, a5: 0 } };
    let Some(buffer) = crate::nt_heap::dispatch(allocation).filter(|&value| value != 0) else { return STATUS_NO_MEMORY; };
    let mut encoded = alloc::vec![0u8; bytes];
    for (index, value) in path.iter().enumerate() { encoded[index * 2..index * 2 + 2].copy_from_slice(&value.to_le_bytes()); }
    if uaccess::copy_to_user(buffer, &encoded).is_err() || uaccess::copy_to_user(result, &buffer.to_le_bytes()).is_err() { free_rtl_buffer(buffer); return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn get_search_path(result: u64) -> u64 {
    if result == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(task) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !task.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let teb = task.nt_teb();
    let Some(peb_address) = teb.checked_add(TEB_PEB_OFFSET) else { return STATUS_INVALID_PARAMETER; };
    let peb = uaccess::get_user_u64(peb_address).ok().unwrap_or(0);
    let Some(params_address) = peb.checked_add(PEB_PROCESS_PARAMETERS_OFFSET) else { return STATUS_INVALID_PARAMETER; };
    let params = uaccess::get_user_u64(params_address).ok().unwrap_or(0);
    if params == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(image_address) = params.checked_add(PARAM_IMAGE_PATH_OFFSET) else { return STATUS_INVALID_PARAMETER; };
    let Some(image) = read_nt_unicode(image_address) else { return STATUS_INVALID_PARAMETER; };
    let mut path = alloc::vec::Vec::new();
    let mut end = image.len();
    for index in (0..image.len()).rev() {
        if image[index] == b'\\' as u16 || image[index] == b'/' as u16 { end = index; break; }
        if index == 0 { end = 0; }
    }
    append_path_component(&mut path, &image[..end]);
    let safe = task.thread_group.nt_search_path_mode.load(core::sync::atomic::Ordering::Acquire) != 0;
    if !safe { append_path_component(&mut path, &wide(b".")); }
    append_path_component(&mut path, &wide(b"C:\\windows\\system32;C:\\windows\\system;C:\\windows"));
    if safe { append_path_component(&mut path, &wide(b".")); }
    let Some(environment_address) = params.checked_add(PARAM_ENVIRONMENT_OFFSET) else { return STATUS_INVALID_PARAMETER; };
    if let Some(value) = env_value(environment_address, b"PATH") { append_path_component(&mut path, &value); }
    path.push(0);
    let bytes = match path.len().checked_mul(2) { Some(value) => value, None => return STATUS_NO_MEMORY };
    let allocation = NtCall { service: NtService::AllocateHeap, args: SyscallArgs { a0: 0, a1: 0, a2: bytes as u64, a3: 0, a4: 0, a5: 0 } };
    let Some(buffer) = crate::nt_heap::dispatch(allocation).filter(|&value| value != 0) else { return STATUS_NO_MEMORY; };
    let mut encoded = alloc::vec![0u8; bytes];
    for (index, value) in path.iter().enumerate() { encoded[index * 2..index * 2 + 2].copy_from_slice(&value.to_le_bytes()); }
    if uaccess::copy_to_user(buffer, &encoded).is_err() || uaccess::copy_to_user(result, &buffer.to_le_bytes()).is_err() { free_rtl_buffer(buffer); return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn release_path(path: u64) -> u64 {
    let Some(task) = sched::live::current() else { return 0; };
    if !task.is_nt_personality() || path == 0 { return 0; }
    let free = NtCall { service: NtService::FreeHeap, args: syscall::SyscallArgs { a0: 1, a1: 0, a2: path, a3: 0, a4: 0, a5: 0 } };
    let _ = crate::nt_heap::dispatch(free);
    0
}

fn run_once_begin_initialize(once: u64, flags: u64, context: u64) -> u64 {
    const CHECK_ONLY: u64 = 0x1;
    const ASYNC: u64 = 0x2;
    if once == 0 || flags & !(CHECK_ONLY | ASYNC) != 0 { return STATUS_INVALID_PARAMETER; }
    let Some(task) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !task.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let Ok(value) = uaccess::get_user_u64(once) else { return STATUS_INVALID_PARAMETER; };
    match value & 3 {
        0 if value != 0 => STATUS_INVALID_PARAMETER,
        0 if flags & CHECK_ONLY != 0 => STATUS_UNSUCCESSFUL,
        0 => match uaccess::cmpxchg_user_u32(once, 0, 1) {
            Ok(0) => STATUS_PENDING,
            Ok(_) => run_once_begin_initialize(once, flags, context),
            Err(_) => STATUS_INVALID_PARAMETER,
        },
        1 if flags & ASYNC != 0 => STATUS_INVALID_PARAMETER,
        // Waiting on another initializer is not yet connected to the NT
        // keyed-event owner.  Do not report ownership to a second caller.
        1 => STATUS_UNSUCCESSFUL,
        2 => {
            if context != 0 && uaccess::put_user_u64(context, value & !3).is_err() { return STATUS_INVALID_PARAMETER; }
            0
        }
        3 if flags & ASYNC != 0 => STATUS_PENDING,
        3 => STATUS_INVALID_PARAMETER,
        _ => STATUS_INVALID_PARAMETER,
    }
}

fn run_once_complete(once: u64, flags: u64, context: u64) -> u64 {
    const ASYNC: u64 = 0x2;
    const INIT_FAILED: u64 = 0x4;
    if once == 0 || flags & !(ASYNC | INIT_FAILED) != 0 || context & 3 != 0 { return STATUS_INVALID_PARAMETER; }
    let Some(task) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !task.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    if flags & INIT_FAILED != 0 {
        if context != 0 || flags & ASYNC != 0 { return STATUS_INVALID_PARAMETER; }
    }
    let completed = if flags & INIT_FAILED != 0 { 0 } else { context | 2 };
    loop {
        let Ok(value) = uaccess::get_user_u64(once) else { return STATUS_INVALID_PARAMETER; };
        let state = value & 3;
        if state != 1 && state != 3 { return STATUS_UNSUCCESSFUL; }
        if state == 3 && flags & ASYNC == 0 { return STATUS_INVALID_PARAMETER; }
        match uaccess::cmpxchg_user_u64(once, value, completed) {
            Ok(seen) if seen == value => return 0,
            Ok(_) => continue,
            Err(_) => return STATUS_INVALID_PARAMETER,
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn run_once_execute_once_x86(once: u64, func: u64, param: u64, context: u64) -> u64 {
    const CALLBACK_SHADOW_BYTES: u64 = 32;
    const CALLBACK_FRAME_BYTES: u64 = 48;
    if once == 0 || func == 0 || !uaccess::access_ok(func, 1) || (context != 0 && !uaccess::access_ok(context, 8)) {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(task) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !task.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    // The loader list is ordered by load/discovery, not by a guaranteed
    // ntdll-first rule. Locate the synthetic runtime module by its published
    // base name; assuming the first entry was ntdll produced a continuation
    // inside advapi32's relay body (the exact mid-relay jump caught in smoke).
    let ntdll = crate::nt_loader_proc::module_base_by_name(task, b"ntdll.dll").unwrap_or(0);
    let Some(continuation) = elf_load::pe_loader::resolve_nt_runtime_run_once_continuation(ntdll) else { return STATUS_INVALID_PARAMETER; };
    let regs = hal_x86_64::current_pt_regs();
    if regs.is_null() { return STATUS_INVALID_PARAMETER; }
    let frame = unsafe { &mut *regs };
    let callback_rsp = frame.rsp.checked_sub(CALLBACK_FRAME_BYTES).unwrap_or(0);
    if callback_rsp == 0 || callback_rsp & 0xf != 8 { return STATUS_INVALID_PARAMETER; }
    let post_syscall_rip = frame.rip;
    let post_syscall_rsp = frame.rsp;
    #[cfg(feature = "debug-faultdiag")]
    {
        klog::write_raw(b"[WINDOWS-PE-RUNONCE-FRAME] rsp=");
        klog::write_hex_u64(post_syscall_rsp);
        for slot in 0..3u64 {
            klog::write_raw(b" word=");
            klog::write_hex_u64(uaccess::get_user_u64(post_syscall_rsp.saturating_add(slot * 8)).unwrap_or(0));
        }
        klog::write_raw(b" callback=");
        klog::write_hex_u64(func);
        klog::write_raw(b"\n");
    }
    for slot in 0..(CALLBACK_SHADOW_BYTES / 8) { if uaccess::put_user_u64(callback_rsp + 8 + slot * 8, 0).is_err() { return STATUS_INVALID_PARAMETER; } }
    if uaccess::put_user_u64(callback_rsp, continuation).is_err() { return STATUS_INVALID_PARAMETER; }
    let begin = run_once_begin_initialize(once, 0, context);
    if begin != STATUS_PENDING { return begin; }
    frame.rip = func;
    frame.rsp = callback_rsp;
    frame.rcx = once;
    frame.rdx = param;
    frame.r8 = context;
    frame.r12 = once;
    frame.r13 = context;
    frame.r14 = post_syscall_rip;
    frame.r15 = post_syscall_rsp;
    STATUS_PENDING
}

/// Transfer the active x86-64 NT syscall frame into a Windows WndProc. The
/// procedure returns through the synthetic ntdll continuation and
/// `NtCallbackReturn`, which restores the suspended syscall frame.
#[cfg(target_arch = "x86_64")]
pub(crate) fn begin_wndproc_callback(hwnd: u64, message: u64, wparam: u64, lparam: u64, wndproc: u64) -> u64 {
    begin_wndproc_callback_with_completion(hwnd, message, wparam, lparam, wndproc, sched::nt_callback::Completion::NONE)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn begin_wndproc_callback_with_completion(hwnd: u64, message: u64, wparam: u64, lparam: u64, wndproc: u64, completion: sched::nt_callback::Completion) -> u64 {
    if hwnd == 0 || wndproc == 0 || !uaccess::access_ok(wndproc, 1) { return STATUS_INVALID_PARAMETER; }
    let Some(task) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !task.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let ntdll = crate::nt_loader_proc::module_base_by_name(task, b"ntdll.dll").unwrap_or(0);
    let Some(continuation) = elf_load::pe_loader::resolve_nt_runtime_wndproc_continuation(ntdll) else {
        // Without ntdll's callback continuation there is nothing to return to.
        reject_create_callback(b"no-continuation", hwnd, message, ntdll);
        return STATUS_INVALID_PARAMETER;
    };
    let regs = hal_x86_64::current_pt_regs();
    if regs.is_null() { return STATUS_INVALID_PARAMETER; }
    let frame = unsafe { &mut *regs };
    let callback_rsp = frame.rsp.checked_sub(48).unwrap_or(0);
    if callback_rsp == 0 || callback_rsp & 0xf != 8 { return STATUS_INVALID_PARAMETER; }
    for slot in 0..4u64 { if uaccess::put_user_u64(callback_rsp + 8 + slot * 8, 0).is_err() { return STATUS_INVALID_PARAMETER; } }
    if uaccess::put_user_u64(callback_rsp, continuation).is_err() { return STATUS_INVALID_PARAMETER; }
    let post_rip = frame.rip;
    let post_rsp = frame.rsp;
    if !task.nt_callback_stack.lock().push(sched::nt_callback::Frame { rip: post_rip, rsp: post_rsp, completion }) {
        reject_create_callback(b"callback-depth", hwnd, message, post_rsp);
        return STATUS_INVALID_PARAMETER;
    }
    frame.rip = wndproc;
    frame.rsp = callback_rsp;
    frame.rcx = hwnd;
    frame.rdx = message;
    frame.r8 = wparam;
    frame.r9 = lparam;
    STATUS_PENDING
}

/// Begin a WndProc create callback with an ABI-shaped CREATESTRUCTW in the
/// callback's user stack frame. That frame remains owned by the callback stack
/// while WM_NCCREATE and WM_CREATE are chained synchronously.
#[cfg(target_arch = "x86_64")]
/// Report a create callback that could not be started. Each of these returns a
/// status the caller turns into a NULL window, and an application whose main
/// window is NULL exits at once, so an unnamed one looks like a crash.
fn reject_create_callback(reason: &'static [u8], hwnd: u64, message: u64, wndproc: u64) {
    klog::write_raw(b"[WINDOWS-WNDPROC-REJECT] reason=");
    klog::write_raw(reason);
    klog::write_raw(b" hwnd=");
    klog::write_hex_u64(hwnd);
    klog::write_raw(b" msg=");
    klog::write_hex_u64(message);
    klog::write_raw(b" wndproc=");
    klog::write_hex_u64(wndproc);
    klog::write_raw(b"\n");
}

pub(crate) fn begin_wndproc_create_callback(hwnd: u64, message: u64, wndproc: u64, params: crate::nt_window::CreateStructArgs, completion: sched::nt_callback::Completion) -> u64 {
    klog::write_raw(b"[WINDOWS-WNDPROC-ENTER] hwnd=");
    klog::write_hex_u64(hwnd);
    klog::write_raw(b" msg=");
    klog::write_hex_u64(message);
    klog::write_raw(b" wndproc=");
    klog::write_hex_u64(wndproc);
    klog::write_raw(b"\n");
    if hwnd == 0 || wndproc == 0 || !uaccess::access_ok(wndproc, 1) {
        reject_create_callback(b"bad-wndproc", hwnd, message, wndproc);
        return STATUS_INVALID_PARAMETER;
    }
    let Some(task) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !task.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let ntdll = crate::nt_loader_proc::module_base_by_name(task, b"ntdll.dll").unwrap_or(0);
    let Some(continuation) = elf_load::pe_loader::resolve_nt_runtime_wndproc_continuation(ntdll) else { return STATUS_INVALID_PARAMETER; };
    let regs = hal_x86_64::current_pt_regs();
    if regs.is_null() { return STATUS_INVALID_PARAMETER; }
    let frame = unsafe { &mut *regs };
    let callback_rsp = frame.rsp.checked_sub(crate::nt_window::CALLBACK_FRAME_BYTES).unwrap_or(0);
    let Some(layout) = crate::nt_window::callback_layout(callback_rsp) else {
        reject_create_callback(b"callback-stack", hwnd, message, callback_rsp);
        return STATUS_INVALID_PARAMETER;
    };
    let create_struct = layout.create_struct;
    let create_bytes = crate::nt_window::serialize_create_struct(params);
    for slot in 0..4u64 { if uaccess::put_user_u64(callback_rsp + 8 + slot * 8, 0).is_err() { return STATUS_INVALID_PARAMETER; } }
    if uaccess::put_user_u64(callback_rsp, continuation).is_err()
        || uaccess::copy_to_user(create_struct, &create_bytes).is_err() {
        return STATUS_INVALID_PARAMETER;
    }
    let post_rip = frame.rip;
    let post_rsp = frame.rsp;
    if !task.nt_callback_stack.lock().push(sched::nt_callback::Frame { rip: post_rip, rsp: post_rsp, completion }) { return STATUS_INVALID_PARAMETER; }
    frame.rip = wndproc;
    frame.rsp = callback_rsp;
    frame.rcx = hwnd;
    frame.rdx = message;
    frame.r8 = 0;
    frame.r9 = create_struct;
    STATUS_PENDING
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn begin_wndproc_callback(_: u64, _: u64, _: u64, _: u64, _: u64) -> u64 { STATUS_NOT_SUPPORTED }

#[cfg(target_arch = "aarch64")]
pub(crate) fn begin_wndproc_callback_with_completion(_: u64, _: u64, _: u64, _: u64, _: u64, _: sched::nt_callback::Completion) -> u64 { STATUS_NOT_SUPPORTED }

#[cfg(target_arch = "aarch64")]
pub(crate) fn begin_wndproc_create_callback(_: u64, _: u64, _: u64, _: crate::nt_window::CreateStructArgs, _: sched::nt_callback::Completion) -> u64 { STATUS_NOT_SUPPORTED }

/// Complete a synchronous callback and restore the syscall frame that
/// initiated it. Wine passes a pointer to one eight-byte LRESULT.
pub(crate) fn callback_return(call: NtCall) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let regs = hal_x86_64::current_pt_regs();
        if regs.is_null() { return STATUS_NO_CALLBACK_ACTIVE; }
        let frame = unsafe { &mut *regs };
        if call.args.a1 != 8 { return STATUS_NO_CALLBACK_ACTIVE; }
        let Ok(result) = uaccess::get_user_u64(call.args.a0) else { return STATUS_ACCESS_VIOLATION; };
        let Some(task) = sched::live::current() else { return STATUS_NO_CALLBACK_ACTIVE; };
        let Some(saved) = task.nt_callback_stack.lock().pop() else { return STATUS_NO_CALLBACK_ACTIVE; };
        frame.rip = saved.rip;
        frame.rsp = saved.rsp;
        frame.rax = result;
        if saved.completion.kind != 0 { return crate::nt_window::complete_callback(saved.completion, result); }
        result
    }
    #[cfg(target_arch = "aarch64")]
    { let _ = call; STATUS_NO_CALLBACK_ACTIVE }
}

fn append_path_component(target: &mut alloc::vec::Vec<u16>, value: &[u16]) { target.extend_from_slice(value); target.push(b';' as u16); }

fn wide(bytes: &[u8]) -> alloc::vec::Vec<u16> { bytes.iter().map(|&value| value as u16).collect() }
fn append_wide(target: &mut alloc::vec::Vec<u16>, value: &[u16]) { if !target.is_empty() { target.push(b';' as u16); } target.extend_from_slice(value); }
fn read_wide_z(source: u64) -> Option<alloc::vec::Vec<u16>> {
    let mut output = alloc::vec::Vec::new();
    for index in 0..=0x7fffu64 { let mut pair = [0u8; 2]; if uaccess::copy_from_user(&mut pair, source.checked_add(index * 2)?).is_err() { return None; } let value = u16::from_le_bytes(pair); if value == 0 { return Some(output); } output.push(value); }
    None
}
fn read_nt_unicode(descriptor: u64) -> Option<alloc::vec::Vec<u16>> {
    let mut header = [0u8; UNICODE_STRING_BYTES]; if uaccess::copy_from_user(&mut header, descriptor).is_err() { return None; }
    let length = u16::from_le_bytes([header[0], header[1]]) as usize / 2; let source = u64::from_le_bytes(header[8..16].try_into().ok()?); if length > 0x7fff || (length != 0 && source == 0) { return None; }
    let mut bytes = alloc::vec![0u8; length * 2]; if uaccess::copy_from_user(&mut bytes, source).is_err() { return None; }
    Some(bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect())
}
fn env_entries(environment: u64) -> Option<alloc::vec::Vec<u16>> {
    let mut output = alloc::vec::Vec::new(); let mut zeroes = 0;
    for index in 0..=0x1ffffu64 { let mut pair = [0u8; 2]; if uaccess::copy_from_user(&mut pair, environment.checked_add(index * 2)?).is_err() { return None; } let value = u16::from_le_bytes(pair); output.push(value); if value == 0 { zeroes += 1; if zeroes == 2 { output.pop(); return Some(output); } } else { zeroes = 0; } }
    None
}
fn env_has_name(environment: u64, name: &[u8]) -> bool { env_value(environment, name).is_some() }
fn env_value(environment: u64, name: &[u8]) -> Option<alloc::vec::Vec<u16>> {
    let all = env_entries(environment)?; let wanted = wide(name); let mut start = 0;
    while start < all.len() { let end = all[start..].iter().position(|&value| value == 0).map(|offset| start + offset).unwrap_or(all.len()); let entry = &all[start..end]; if entry.len() > wanted.len() && entry[..wanted.len()] == wanted[..] && entry[wanted.len()] == b'=' as u16 { return Some(entry[wanted.len() + 1..].to_vec()); } if end == all.len() { break; } start = end + 1; }
    None
}

fn get_current_directory(buffer_length: u64, buffer: u64) -> u64 {
    let Some(task) = sched::live::current() else { return 0; };
    if !task.is_nt_personality() { return 0; }
    let teb = task.nt_teb();
    let Some(teb_peb) = teb.checked_add(TEB_PEB_OFFSET) else { return 0; };
    let peb = uaccess::get_user_u64(teb_peb).ok().unwrap_or(0);
    let Some(params_address) = peb.checked_add(PEB_PROCESS_PARAMETERS_OFFSET) else { return 0; };
    let params = uaccess::get_user_u64(params_address).ok().unwrap_or(0);
    let Some(descriptor) = params.checked_add(PARAM_CURRENT_DIRECTORY_OFFSET) else { return 0; };
    let mut string = [0u8; UNICODE_STRING_BYTES];
    if descriptor == 0 || uaccess::copy_from_user(&mut string, descriptor).is_err() { return 0; }
    let mut length = u16::from_le_bytes([string[0], string[1]]) as usize / 2;
    let source = u64::from_le_bytes(string[8..16].try_into().unwrap());
    if length == 0 { return 0; }
    if source == 0 { return 0; }
    if length > 1 {
        let mut last = [0u8; 2];
        let mut previous = [0u8; 2];
        let Some(last_offset) = ((length - 1) as u64).checked_mul(2) else { return 0; };
        let Some(previous_offset) = ((length - 2) as u64).checked_mul(2) else { return 0; };
        let Some(last_address) = source.checked_add(last_offset) else { return 0; };
        let Some(previous_address) = source.checked_add(previous_offset) else { return 0; };
        if uaccess::copy_from_user(&mut last, last_address).is_err()
            || uaccess::copy_from_user(&mut previous, previous_address).is_err() { return 0; }
        if u16::from_le_bytes(last) == b'\\' as u16 && u16::from_le_bytes(previous) != b':' as u16 { length -= 1; }
    }
    let Some(required) = length.checked_add(1).and_then(|value| value.checked_mul(2)) else { return 0; };
    if buffer_length / 2 <= length as u64 { return required as u64; }
    if buffer == 0 { return 0; }
    let Some(bytes) = length.checked_mul(2) else { return 0; };
    let mut contents = alloc::vec![0u8; bytes];
    let Some(terminator) = buffer.checked_add(bytes as u64) else { return 0; };
    if uaccess::copy_from_user(&mut contents, source).is_err() || uaccess::copy_to_user(buffer, &contents).is_err() || uaccess::copy_to_user(terminator, &[0, 0]).is_err() { return 0; }
    (length * 2) as u64
}

fn utf16_to_string(value: &[u16]) -> Option<String> {
    let mut output = String::new();
    for &unit in value {
        output.push(core::char::from_u32(unit as u32)?);
    }
    Some(output)
}

fn set_current_directory(directory: u64) -> u64 {
    let Some(task) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !task.is_nt_personality() || directory == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(input) = read_nt_unicode(directory) else { return STATUS_INVALID_PARAMETER; };
    if input.is_empty() { return STATUS_OBJECT_NAME_INVALID; }
    let Some(mut dos_path) = utf16_to_string(&input) else { return STATUS_OBJECT_NAME_INVALID; };
    let Some(vfs_path) = crate::nt_path::normalize_path(&dos_path) else { return STATUS_OBJECT_NAME_INVALID; };
    let resolved = match crate::pathresolve::resolve_path_raw(&vfs_path, false) {
        Ok(path) => path,
        Err(error) => match crate::namei_common::errno_from_vfs(error).unsigned_abs() as i32 {
            x if x == syscall::errno::Errno::Enotdir.as_i32() => return STATUS_NOT_A_DIRECTORY,
            x if x == syscall::errno::Errno::Eacces.as_i32() => return STATUS_ACCESS_DENIED,
            x if x == syscall::errno::Errno::Enoent.as_i32() => return STATUS_OBJECT_PATH_NOT_FOUND,
            _ => return STATUS_OBJECT_NAME_NOT_FOUND,
        },
    };
    let _ = resolved;
    if !dos_path.ends_with('\\') { dos_path.push('\\'); }

    let teb = task.nt_teb();
    let Some(teb_peb) = teb.checked_add(TEB_PEB_OFFSET) else { return STATUS_ACCESS_VIOLATION; };
    let peb = match uaccess::get_user_u64(teb_peb) { Ok(value) => value, Err(_) => return STATUS_ACCESS_VIOLATION };
    let Some(params_address) = peb.checked_add(PEB_PROCESS_PARAMETERS_OFFSET) else { return STATUS_ACCESS_VIOLATION; };
    let params = match uaccess::get_user_u64(params_address) { Ok(value) => value, Err(_) => return STATUS_ACCESS_VIOLATION };
    let Some(descriptor) = params.checked_add(PARAM_CURRENT_DIRECTORY_OFFSET) else { return STATUS_ACCESS_VIOLATION; };
    let mut header = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut header, descriptor).is_err() { return STATUS_ACCESS_VIOLATION; }
    let maximum = u16::from_le_bytes([header[2], header[3]]) as usize;
    let target = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let encoded: Vec<u16> = dos_path.encode_utf16().collect();
    let Some(bytes) = encoded.len().checked_mul(2) else { return STATUS_NAME_TOO_LONG; };
    let Some(required) = bytes.checked_add(2) else { return STATUS_NAME_TOO_LONG; };
    if target == 0 || required > maximum || bytes > u16::MAX as usize { return STATUS_NAME_TOO_LONG; }
    let mut raw = vec![0u8; bytes];
    for (index, unit) in encoded.iter().enumerate() { raw[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes()); }
    let Some(terminator) = target.checked_add(bytes as u64) else { return STATUS_ACCESS_VIOLATION; };
    if uaccess::copy_to_user(target, &raw).is_err() || uaccess::copy_to_user(terminator, &[0, 0]).is_err()
        || uaccess::copy_to_user(descriptor, &(bytes as u16).to_le_bytes()).is_err() { return STATUS_ACCESS_VIOLATION; }
    STATUS_SUCCESS
}
const TEB_LAST_ERROR_OFFSET: u64 = 0x68;
const TEB_HARD_ERROR_MODE_OFFSET: u64 = 0x16b0;
const STATUS_INVALID_PARAMETER_1: u64 = 0xc000_00ef;
const THREAD_ERROR_MODE_MASK: u32 = 0x70;
fn set_thread_error_mode(mode: u32, oldmode: u64) -> u64 {
    if mode & !THREAD_ERROR_MODE_MASK != 0 { return STATUS_INVALID_PARAMETER_1; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let address = cur.nt_teb().saturating_add(TEB_HARD_ERROR_MODE_OFFSET);
    let old = uaccess::get_user_u32(address).unwrap_or(0);
    if oldmode != 0 && uaccess::put_user_u32(oldmode, old).is_err() { return STATUS_INVALID_PARAMETER; }
    if uaccess::put_user_u32(address, mode).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}
fn get_thread_error_mode() -> u64 {
    let Some(cur) = sched::live::current() else { return 0; };
    if !cur.is_nt_personality() { return 0; }
    uaccess::get_user_u32(cur.nt_teb().saturating_add(TEB_HARD_ERROR_MODE_OFFSET)).map_or(0, u64::from)
}

fn set_thread_preferred_ui_languages(call: NtCall) -> u64 {
    let flags = call.args.a0 as u32;
    if call.args.a1 == 0 { return STATUS_SUCCESS; }
    let mut words = Vec::new();
    let mut languages = 0u32;
    for index in 0..1024u64 {
        let address = match call.args.a1.checked_add(index * 2) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
        let mut pair = [0u8; 2];
        if uaccess::copy_from_user(&mut pair, address).is_err() { return STATUS_INVALID_PARAMETER; }
        let word = u16::from_le_bytes(pair);
        words.push(word);
        if word == 0 {
            if index == 0 { return STATUS_UNSUCCESSFUL; }
            if words.len() >= 2 && words[words.len() - 2] == 0 { break; }
            languages += 1;
        }
    }
    if words.last().copied() != Some(0) || languages == 0 { return STATUS_UNSUCCESSFUL; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    cur.nt_thread_ui_languages().lock().clone_from(&(flags, words));
    if call.args.a2 != 0 && uaccess::put_user_u32(call.args.a2, languages).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}
fn set_last_win32_error(error: u64) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    let Some(address) = cur.nt_teb().checked_add(TEB_LAST_ERROR_OFFSET) else { return STATUS_INVALID_PARAMETER; };
    if uaccess::put_user_u32(address, error as u32).is_err() { STATUS_INVALID_PARAMETER } else { 0 }
}
fn get_last_win32_error() -> u64 {
    let Some(cur) = sched::live::current() else { return 0; };
    let Some(address) = cur.nt_teb().checked_add(TEB_LAST_ERROR_OFFSET) else { return 0; };
    uaccess::get_user_u32(address).map_or(0, u64::from)
}
fn dos_path_to_nt(source: u64, target: u64, file_part: u64, curdir: u64) -> u64 {
    if source == 0 || target == 0 { return 0; }
    let mut input = vec![];
    for index in 0..=0x7fffu64 {
        let mut word = [0u8; 2];
        let Some(offset) = index.checked_mul(2) else { return 0; };
        let Some(address) = source.checked_add(offset) else { return 0; };
        if uaccess::copy_from_user(&mut word, address).is_err() { return 0; }
        let value = u16::from_le_bytes(word);
        if value == 0 { break; }
        input.push(value);
        if index == 0x7fff { return 0; }
    }
    if input.is_empty() { return 0; }
    let mut output = vec![];
    let slash = |value: u16| value == b'\\' as u16 || value == b'/' as u16;
    if input.len() >= 5 && slash(input[0]) && slash(input[1]) && input[2] == b'?' as u16 && input[3] == b'?' as u16 && slash(input[4]) {
        output.extend_from_slice(&[b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16]);
        output.extend_from_slice(&input[5..]);
    } else if input.len() >= 3 && input[1] == b':' as u16 && slash(input[2]) {
        output.extend_from_slice(&[b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16]);
        output.extend_from_slice(&input);
    } else if input.len() >= 2 && slash(input[0]) && slash(input[1]) {
        output.extend_from_slice(&[b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16, b'U' as u16, b'N' as u16, b'C' as u16, b'\\' as u16]);
        output.extend_from_slice(&input[2..]);
    } else { return 0; }
    let size = match output.len().checked_add(1).and_then(|len| len.checked_mul(2)) { Some(size) if size <= u16::MAX as usize => size, _ => return 0 };
    let heap_call = NtCall { service: NtService::AllocateHeap, args: SyscallArgs { a0: 0, a1: 0, a2: size as u64, a3: 0, a4: 0, a5: 0 } };
    let Some(buffer) = crate::nt_heap::dispatch(heap_call).filter(|address| *address != 0) else { return 0; };
    let mut bytes = vec![0u8; size];
    for (index, value) in output.iter().enumerate() { bytes[index * 2..index * 2 + 2].copy_from_slice(&value.to_le_bytes()); }
    if uaccess::copy_to_user(buffer, &bytes).is_err() { free_rtl_buffer(buffer); return 0; }
    let mut descriptor = [0u8; UNICODE_STRING_BYTES];
    descriptor[0..2].copy_from_slice(&((output.len() * 2) as u16).to_le_bytes()); descriptor[2..4].copy_from_slice(&(size as u16).to_le_bytes()); descriptor[8..16].copy_from_slice(&buffer.to_le_bytes());
    if uaccess::copy_to_user(target, &descriptor).is_err() { free_rtl_buffer(buffer); return 0; }
    if file_part != 0 {
        let part = output.iter().rposition(|value| slash(*value))
            .and_then(|index| index.checked_add(1))
            .and_then(|index| index.checked_mul(2))
            .and_then(|offset| buffer.checked_add(offset as u64)).unwrap_or(0);
        if uaccess::copy_to_user(file_part, &part.to_le_bytes()).is_err() { free_rtl_buffer(buffer); return 0; }
    }
    if curdir != 0 {
        let Some(task) = sched::live::current() else { return 0; };
        if !task.is_nt_personality() { return 0; }
        let teb = task.nt_teb();
        let Some(peb_address) = teb.checked_add(TEB_PEB_OFFSET) else { return 0; };
        let Some(peb) = uaccess::get_user_u64(peb_address).ok() else { return 0; };
        let Some(params_address) = peb.checked_add(PEB_PROCESS_PARAMETERS_OFFSET) else { return 0; };
        let Some(params) = uaccess::get_user_u64(params_address).ok() else { return 0; };
        let Some(path_address) = params.checked_add(PARAM_CURRENT_DIRECTORY_OFFSET) else { return 0; };
        let Some(handle_address) = params.checked_add(PARAM_CURRENT_DIRECTORY_HANDLE_OFFSET) else { return 0; };
        let mut path = [0u8; UNICODE_STRING_BYTES];
        let mut handle = [0u8; 8];
        if uaccess::copy_from_user(&mut path, path_address).is_err()
            || uaccess::copy_from_user(&mut handle, handle_address).is_err() { return 0; }
        let mut encoded = [0u8; CURDIR_BYTES];
        encoded[..UNICODE_STRING_BYTES].copy_from_slice(&path);
        encoded[UNICODE_STRING_BYTES..].copy_from_slice(&handle);
        if uaccess::copy_to_user(curdir, &encoded).is_err() { return 0; }
    }
    1
}
fn create_unicode_string_from_ascii(target: u64, source: u64) -> u64 {
    if target == 0 || source == 0 { return 0; }
    let mut ascii = vec![];
    for index in 0..=0x7fffu64 {
        let mut byte = [0u8; 1];
        if uaccess::copy_from_user(&mut byte, source.saturating_add(index)).is_err() { return 0; }
        if byte[0] == 0 { break; }
        ascii.push(byte[0]);
        if index == 0x7fff { return 0; }
    }
    let bytes = match ascii.len().checked_add(1).and_then(|len| len.checked_mul(2)) { Some(size) => size, None => return 0 };
    let heap_call = NtCall { service: NtService::AllocateHeap, args: SyscallArgs { a0: 0, a1: 0, a2: bytes as u64, a3: 0, a4: 0, a5: 0 } };
    let Some(buffer) = crate::nt_heap::dispatch(heap_call).filter(|address| *address != 0) else { return 0; };
    let mut wide = vec![0u8; bytes];
    for (index, value) in ascii.iter().enumerate() { wide[index * 2] = *value; }
    if uaccess::copy_to_user(buffer, &wide).is_err() { free_rtl_buffer(buffer); return 0; }
    let mut descriptor = [0u8; UNICODE_STRING_BYTES];
    descriptor[0..2].copy_from_slice(&((ascii.len() * 2) as u16).to_le_bytes());
    descriptor[2..4].copy_from_slice(&(bytes as u16).to_le_bytes());
    descriptor[8..16].copy_from_slice(&buffer.to_le_bytes());
    if uaccess::copy_to_user(target, &descriptor).is_err() { free_rtl_buffer(buffer); return 0; }
    1
}
fn create_unicode_string(target: u64, source: u64) -> u64 {
    if target == 0 || source == 0 { return 0; }
    let mut input = vec![];
    for index in 0..=0x7fffu64 { let address = match source.checked_add(index * 2) { Some(value) => value, None => return 0 }; let mut pair = [0u8; 2]; if uaccess::copy_from_user(&mut pair, address).is_err() { return 0; } if pair == [0, 0] { break; } input.extend_from_slice(&pair); if index == 0x7fff { return 0; } }
    let size = match input.len().checked_add(2) { Some(value) => value, None => return 0 };
    let heap_call = NtCall { service: NtService::AllocateHeap, args: SyscallArgs { a0: 0, a1: 0, a2: size as u64, a3: 0, a4: 0, a5: 0 } };
    let Some(buffer) = crate::nt_heap::dispatch(heap_call).filter(|address| *address != 0) else { return 0; };
    if uaccess::copy_to_user(buffer, &input).is_err() || uaccess::copy_to_user(buffer + input.len() as u64, &[0, 0]).is_err() { free_rtl_buffer(buffer); return 0; }
    let mut descriptor = [0u8; UNICODE_STRING_BYTES]; descriptor[0..2].copy_from_slice(&(input.len() as u16).to_le_bytes()); descriptor[2..4].copy_from_slice(&(size as u16).to_le_bytes()); descriptor[8..16].copy_from_slice(&buffer.to_le_bytes());
    if uaccess::copy_to_user(target, &descriptor).is_err() { free_rtl_buffer(buffer); return 0; } 1
}
fn free_rtl_buffer(buffer: u64) {
    let call = NtCall { service: NtService::FreeHeap, args: SyscallArgs { a0: 0, a1: 0, a2: buffer, a3: 0, a4: 0, a5: 0 } };
    let _ = crate::nt_heap::dispatch(call);
}
fn ansi_to_unicode_string(target: u64, source: u64, allocate: u64) -> u64 {
    if target == 0 || source == 0 { return STATUS_INVALID_PARAMETER; }
    let mut ansi = [0u8; 16]; let mut unicode = [0u8; 16];
    if uaccess::copy_from_user(&mut ansi, source).is_err() || uaccess::copy_from_user(&mut unicode, target).is_err() { return STATUS_INVALID_PARAMETER; }
    let length = u16::from_le_bytes([ansi[0], ansi[1]]) as usize; let maximum = u16::from_le_bytes([ansi[2], ansi[3]]) as usize;
    let source_buffer = u64::from_le_bytes(ansi[8..16].try_into().unwrap());
    if length > maximum || (length != 0 && source_buffer == 0) { return STATUS_INVALID_PARAMETER; }
    let total = match length.checked_mul(2).and_then(|size| size.checked_add(2)) { Some(size) if size <= u16::MAX as usize => size, _ => return STATUS_INVALID_PARAMETER_2 };
    let destination_maximum = u16::from_le_bytes([unicode[2], unicode[3]]) as usize; let mut destination = u64::from_le_bytes(unicode[8..16].try_into().unwrap()); let owned = allocate != 0;
    if owned {
        let heap_call = NtCall { service: NtService::AllocateHeap, args: SyscallArgs { a0: 0, a1: 0, a2: total as u64, a3: 0, a4: 0, a5: 0 } };
        let Some(buffer) = crate::nt_heap::dispatch(heap_call).filter(|address| *address != 0) else { return STATUS_INVALID_PARAMETER; }; destination = buffer;
    } else if total > destination_maximum { return STATUS_BUFFER_OVERFLOW; } else if total != 0 && destination == 0 { return STATUS_INVALID_PARAMETER; }
    let mut wide = vec![0u8; total];
    for index in 0..length { let mut byte = [0u8; 1]; if uaccess::copy_from_user(&mut byte, source_buffer + index as u64).is_err() { if owned { free_rtl_buffer(destination); } return STATUS_INVALID_PARAMETER; } wide[index * 2] = byte[0]; }
    if uaccess::copy_to_user(destination, &wide).is_err() { if owned { free_rtl_buffer(destination); } return STATUS_INVALID_PARAMETER; }
    let mut output = [0u8; 16]; output[0..2].copy_from_slice(&((length * 2) as u16).to_le_bytes()); output[2..4].copy_from_slice(&(total as u16).to_le_bytes()); output[8..16].copy_from_slice(&destination.to_le_bytes());
    if uaccess::copy_to_user(target, &output).is_err() { if owned { free_rtl_buffer(destination); } return STATUS_INVALID_PARAMETER; } 0
}
fn char_to_integer(source: u64, requested_base: u32, target: u64) -> u64 {
    if source == 0 { return STATUS_INVALID_PARAMETER; }
    let mut bytes = vec![];
    for index in 0..=4096u64 { let Some(address) = source.checked_add(index) else { return STATUS_INVALID_PARAMETER; }; let mut byte = [0u8; 1]; if uaccess::copy_from_user(&mut byte, address).is_err() { return STATUS_INVALID_PARAMETER; } if byte[0] == 0 { break; } bytes.push(byte[0]); if index == 4096 { return STATUS_INVALID_PARAMETER; } }
    let mut pos = 0usize;
    while pos < bytes.len() && bytes[pos] <= b' ' { pos += 1; } let minus = if bytes.get(pos) == Some(&b'-') { pos += 1; true } else { if bytes.get(pos) == Some(&b'+') { pos += 1; } false };
    let base = if requested_base == 0 { if bytes.get(pos) == Some(&b'0') { match bytes.get(pos + 1) { Some(b'b') => { pos += 2; 2 }, Some(b'o') => { pos += 2; 8 }, Some(b'x') => { pos += 2; 16 }, _ => 10 } } else { 10 } } else if matches!(requested_base, 2 | 8 | 10 | 16) { requested_base } else { return STATUS_INVALID_PARAMETER };
    if target == 0 { return STATUS_ACCESS_VIOLATION; }
    let mut value = 0u32;
    while pos < bytes.len() { let digit = match bytes[pos] { b'0'..=b'9' => (bytes[pos] - b'0') as u32, b'A'..=b'Z' => (bytes[pos] - b'A' + 10) as u32, b'a'..=b'z' => (bytes[pos] - b'a' + 10) as u32, _ => base }; if digit >= base { break; } value = value.wrapping_mul(base).wrapping_add(digit); pos += 1; }
    if minus { value = 0u32.wrapping_sub(value); }
    if uaccess::put_user_u32(target, value).is_err() { return STATUS_INVALID_PARAMETER; } 0
}
fn free_unicode_string(descriptor: u64) -> u64 {
    if descriptor == 0 { return 0; }
    let mut bytes = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut bytes, descriptor).is_err() { return 0; }
    let buffer = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    if buffer != 0 { free_rtl_buffer(buffer); }
    let _ = uaccess::copy_to_user(descriptor, &[0u8; UNICODE_STRING_BYTES]);
    0
}
fn free_ansi_string(descriptor: u64) -> u64 {
    if descriptor == 0 { return 0; }
    let mut bytes = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut bytes, descriptor).is_err() { return 0; }
    let buffer = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    if buffer != 0 { free_rtl_buffer(buffer); }
    let _ = uaccess::copy_to_user(descriptor, &[0u8; UNICODE_STRING_BYTES]);
    0
}
fn unicode_string_to_ansi_size(descriptor: u64) -> u64 {
    if descriptor == 0 { return 0; }
    let mut header = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut header, descriptor).is_err() { return 0; }
    let length = u16::from_le_bytes([header[0], header[1]]) as usize;
    let buffer = u64::from_le_bytes(header[8..16].try_into().unwrap());
    if length == 0 { return 1; }
    if buffer == 0 || length % 2 != 0 { return 0; }
    let mut size = 0usize;
    let mut index = 0usize;
    while index < length / 2 {
        let Some(address) = buffer.checked_add((index * 2) as u64) else { return 0; };
        let mut bytes = [0u8; 2];
        if uaccess::copy_from_user(&mut bytes, address).is_err() { return 0; }
        let unit = u16::from_le_bytes(bytes);
        let width = if (0xd800..=0xdbff).contains(&unit) && index + 1 < length / 2 {
            let Some(next_address) = buffer.checked_add(((index + 1) * 2) as u64) else { return 0; };
            let mut next_bytes = [0u8; 2];
            if uaccess::copy_from_user(&mut next_bytes, next_address).is_err() { return 0; }
            if (0xdc00..=0xdfff).contains(&u16::from_le_bytes(next_bytes)) { index += 1; 4 } else { 3 }
        } else if unit <= 0x7f { 1 } else if unit <= 0x7ff { 2 } else if (0xdc00..=0xdfff).contains(&unit) { 3 } else { 3 };
        size = match size.checked_add(width) { Some(value) => value, None => return 0 };
        index += 1;
    }
    size.checked_add(1).map_or(0, |value| value as u64)
}
fn get_ace(acl: u64, index: u32, output: u64) -> u64 {
    if acl == 0 || output == 0 { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; ACL_HEADER_BYTES];
    if uaccess::copy_from_user(&mut header, acl).is_err() { return STATUS_INVALID_PARAMETER; }
    let size = u16::from_le_bytes([header[2], header[3]]) as usize;
    let count = u16::from_le_bytes([header[4], header[5]]) as u32;
    if header[0] < 2 || header[0] > 4 || size < ACL_HEADER_BYTES || index >= count { return STATUS_INVALID_PARAMETER; }
    let mut offset = ACL_HEADER_BYTES;
    for _ in 0..index {
        let Some(end) = offset.checked_add(ACE_HEADER_BYTES) else { return STATUS_INVALID_PARAMETER; };
        if end > size { return STATUS_INVALID_PARAMETER; }
        let mut ace_header = [0u8; ACE_HEADER_BYTES];
        if uaccess::copy_from_user(&mut ace_header, acl + offset as u64).is_err() { return STATUS_INVALID_PARAMETER; }
        let ace_size = u16::from_le_bytes([ace_header[2], ace_header[3]]) as usize;
        if ace_size < ACE_HEADER_BYTES || offset.checked_add(ace_size).filter(|end| *end <= size).is_none() { return STATUS_INVALID_PARAMETER; }
        offset += ace_size;
    }
    let mut ace_header = [0u8; ACE_HEADER_BYTES];
    if offset.checked_add(ACE_HEADER_BYTES).filter(|end| *end <= size).is_none() || uaccess::copy_from_user(&mut ace_header, acl + offset as u64).is_err() { return STATUS_INVALID_PARAMETER; }
    let ace_size = u16::from_le_bytes([ace_header[2], ace_header[3]]) as usize;
    if ace_size < ACE_HEADER_BYTES || offset.checked_add(ace_size).filter(|end| *end <= size).is_none() { return STATUS_INVALID_PARAMETER; }
    if uaccess::copy_to_user(output, &(acl + offset as u64).to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    0
}
fn get_security_control(descriptor: u64, control: u64, revision: u64) -> u64 {
    if descriptor == 0 || control == 0 || revision == 0 { return STATUS_INVALID_PARAMETER; }
    let mut bytes = [0u8; 4];
    if uaccess::copy_from_user(&mut bytes, descriptor).is_err() { return STATUS_INVALID_PARAMETER; }
    if bytes[0] != 1 {
        let _ = uaccess::copy_to_user(revision, &(bytes[0] as u32).to_le_bytes());
        return STATUS_UNKNOWN_REVISION;
    }
    if uaccess::copy_to_user(revision, &1u32.to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    if uaccess::copy_to_user(control, &u16::from_le_bytes([bytes[2], bytes[3]]) .to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    0
}
fn is_text_unicode(buffer: u64, length: i64, flags_ptr: u64) -> u64 {
    if length < 2 || buffer == 0 {
        if flags_ptr != 0 { let _ = uaccess::copy_to_user(flags_ptr, &0u32.to_le_bytes()); }
        return 0;
    }
    let mut flags = u32::MAX;
    if flags_ptr != 0 {
        let mut bytes = [0u8; 4];
        if uaccess::copy_from_user(&mut bytes, flags_ptr).is_err() { return 0; }
        flags = u32::from_le_bytes(bytes);
    }
    let length = length as usize;
    let mut bytes = vec![0u8; core::cmp::min(length, 514)];
    if uaccess::copy_from_user(&mut bytes, buffer).is_err() { return 0; }
    let mut out = 0u32;
    if length & 1 != 0 { out |= TEXT_UNICODE_ODD_LENGTH; }
    let mut usable = length;
    if read_byte(buffer + (length - 1) as u64).is_some_and(|byte| byte == 0) { usable -= 1; }
    let chars = core::cmp::min(usable / 2, 256);
    if chars != 0 {
        let word = |index: usize| u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
        if word(0) == 0xfeff { out |= TEXT_UNICODE_SIGNATURE; }
        if word(0) == 0xfffe { out |= 0x0080; }
        if flags & TEXT_UNICODE_STATISTICS != 0 && (0..chars).filter(|&i| word(i) <= 0xff).count() > chars / 2 { out |= TEXT_UNICODE_STATISTICS; }
        if flags & TEXT_UNICODE_NULL_BYTES != 0 && (0..chars).any(|i| { let value = word(i); value & 0xff == 0 || value >> 8 == 0 }) { out |= TEXT_UNICODE_NULL_BYTES; }
        if flags & TEXT_UNICODE_CONTROLS != 0 && (0..chars).any(|i| matches!(word(i), 0x0009 | 0x000a | 0x000d | 0x0020 | 0x3000)) { out |= TEXT_UNICODE_CONTROLS; }
        if flags & 0x0040 != 0 && (0..chars).any(|i| matches!(word(i), 0x0d00 | 0x0a00 | 0x0900 | 0x2000)) { out |= 0x0040; }
    }
    out &= flags;
    if flags_ptr != 0 && uaccess::copy_to_user(flags_ptr, &out.to_le_bytes()).is_err() { return 0; }
    if out & (TEXT_UNICODE_REVERSE_MASK | TEXT_UNICODE_NOT_UNICODE_MASK) != 0 || out & TEXT_UNICODE_NOT_ASCII_MASK != 0 || out & 0x000f != 0 { 1 } else { 0 }
}
fn read_byte(address: u64) -> Option<u8> {
    let mut byte = [0u8; 1];
    uaccess::copy_from_user(&mut byte, address).ok()?;
    Some(byte[0])
}
fn length_security_descriptor(descriptor: u64) -> u64 {
    if descriptor == 0 { return 0; }
    let mut head = [0u8; 20];
    if uaccess::copy_from_user(&mut head, descriptor).is_err() || head[0] != 1 { return 0; }
    let control = u16::from_le_bytes([head[2], head[3]]);
    let relative = control & 0x8000 != 0;
    let base = if relative { 20usize } else { 40usize };
    let result = || -> Option<usize> {
        let field = |slot: usize| -> Option<u64> {
            if relative { Some(u32::from_le_bytes(head[slot..slot + 4].try_into().ok()?) as u64) }
            else { let mut bytes = [0u8; 8]; uaccess::copy_from_user(&mut bytes, descriptor + slot as u64).ok()?; Some(u64::from_le_bytes(bytes)) }
        };
        let sid = |address: u64| -> Option<usize> {
            let mut bytes = [0u8; 2]; uaccess::copy_from_user(&mut bytes, address).ok()?;
            let count = bytes[1] as usize;
            if bytes[0] != 1 || count > MAX_SUBAUTHORITIES { return None; }
            SID_HEADER_BYTES.checked_add(count.checked_mul(4)?)
        };
        let mut total = base;
        for slot in [4usize, 8usize] {
            if let Some(value) = field(slot) { if value != 0 { let address = if relative { descriptor.checked_add(value)? } else { value }; total = total.checked_add(sid(address)?)?; } }
        }
        for (slot, present) in [(12usize, control & 0x0010 != 0), (16usize, control & 0x0004 != 0)] {
            if present { if let Some(value) = field(slot) { if value != 0 { let address = if relative { descriptor.checked_add(value)? } else { value }; let mut acl = [0u8; 4]; uaccess::copy_from_user(&mut acl, address).ok()?; total = total.checked_add(u16::from_le_bytes([acl[2], acl[3]]) as usize)?; } } }
        }
        Some(total)
    };
    result().unwrap_or(0) as u64
}
fn make_self_relative_sd(source: u64, target: u64, length_ptr: u64) -> u64 {
    const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
    if source == 0 || length_ptr == 0 { return STATUS_INVALID_PARAMETER; }
    let mut length_bytes = [0u8; 4];
    if uaccess::copy_from_user(&mut length_bytes, length_ptr).is_err() { return STATUS_INVALID_PARAMETER; }
    let capacity = u32::from_le_bytes(length_bytes) as usize;
    let mut source_head = [0u8; 40];
    if uaccess::copy_from_user(&mut source_head, source).is_err() || source_head[0] != 1 { return STATUS_INVALID_PARAMETER; }
    let control = u16::from_le_bytes([source_head[2], source_head[3]]);
    let relative = control & 0x8000 != 0;
    let required = if relative { length_security_descriptor(source) as usize } else { length_security_descriptor(source).saturating_sub(20) as usize };
    if required == 0 || required > u32::MAX as usize { return STATUS_INVALID_PARAMETER; }
    if capacity < required {
        let _ = uaccess::copy_to_user(length_ptr, &(required as u32).to_le_bytes());
        return STATUS_BUFFER_TOO_SMALL;
    }
    if target == 0 { return STATUS_INVALID_PARAMETER; }
    if relative {
        let mut bytes = vec![0u8; required];
        if uaccess::copy_from_user(&mut bytes, source).is_err() || uaccess::copy_to_user(target, &bytes).is_err() { return STATUS_INVALID_PARAMETER; }
        return 0;
    }
    let mut output = vec![0u8; required];
    output[0] = source_head[0]; output[1] = source_head[1];
    output[2..4].copy_from_slice(&(control | 0x8000).to_le_bytes());
    let mut offset = 20usize;
    for (slot, present) in [(4usize, true), (8usize, true), (12usize, control & 0x0010 != 0), (16usize, control & 0x0004 != 0)] {
        let pointer = u64::from_le_bytes(source_head[slot..slot + 8].try_into().unwrap());
        if pointer == 0 || !present { continue; }
        let blob = if slot < 12 { read_sid(pointer) } else { read_acl(pointer) };
        let Some(blob) = blob else { return STATUS_INVALID_PARAMETER; };
        let Some(end) = offset.checked_add(blob.len()) else { return STATUS_INVALID_PARAMETER; };
        if end > output.len() { return STATUS_INVALID_PARAMETER; }
        output[slot..slot + 4].copy_from_slice(&(offset as u32).to_le_bytes());
        output[offset..end].copy_from_slice(&blob); offset = end;
    }
    if uaccess::copy_to_user(target, &output).is_err() { return STATUS_INVALID_PARAMETER; }
    0
}
fn read_sid(address: u64) -> Option<alloc::vec::Vec<u8>> {
    let mut head = [0u8; 2]; uaccess::copy_from_user(&mut head, address).ok()?;
    if head[0] != 1 || head[1] as usize > MAX_SUBAUTHORITIES { return None; }
    let size = SID_HEADER_BYTES.checked_add(head[1] as usize * 4)?; let mut bytes = vec![0u8; size];
    uaccess::copy_from_user(&mut bytes, address).ok()?; Some(bytes)
}
fn read_acl(address: u64) -> Option<alloc::vec::Vec<u8>> {
    let mut head = [0u8; 4]; uaccess::copy_from_user(&mut head, address).ok()?;
    let size = u16::from_le_bytes([head[2], head[3]]) as usize;
    if size < ACL_HEADER_BYTES { return None; }
    let mut bytes = vec![0u8; size]; uaccess::copy_from_user(&mut bytes, address).ok()?; Some(bytes)
}
fn nt_status_to_dos_error(status: u32) -> u32 {
    if status == 0 || status & 0x2000_0000 != 0 { return status; }
    let status = if status & 0xf000_0000 == 0xd000_0000 { status & !0x1000_0000 } else { status };
    match status {
        0xc000_0005 => 998,
        0xc000_0008 => 6,
        0xc000_000d => 87,
        0xc000_000f | 0xc000_0034 => 2,
        0xc000_003a => 3,
        0xc000_0022 => 5,
        0xc000_0023 => 122,
        0xc000_0002 => 120,
        0xc000_007b => 193,
        0xc000_0102 => 1460,
        0x0000_0103 => 997,
        _ => 317,
    }
}
fn query_acl(acl: u64, info: u64, length: u32, class: u32) -> u64 {
    if acl == 0 || info == 0 { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; ACL_HEADER_BYTES];
    if uaccess::copy_from_user(&mut header, acl).is_err() { return STATUS_INVALID_PARAMETER; }
    let acl_size = u16::from_le_bytes([header[2], header[3]]) as usize;
    let count = u16::from_le_bytes([header[4], header[5]]) as usize;
    if header[0] < 2 || header[0] > 4 || acl_size < ACL_HEADER_BYTES { return STATUS_INVALID_PARAMETER; }
    let mut in_use = ACL_HEADER_BYTES;
    let mut offset = ACL_HEADER_BYTES;
    for _ in 0..count {
        let mut ace = [0u8; ACE_HEADER_BYTES];
        if offset.checked_add(ACE_HEADER_BYTES).filter(|end| *end <= acl_size).is_none() || uaccess::copy_from_user(&mut ace, acl + offset as u64).is_err() { return STATUS_INVALID_PARAMETER; }
        let size = u16::from_le_bytes([ace[2], ace[3]]) as usize;
        if size < ACE_HEADER_BYTES || offset.checked_add(size).filter(|end| *end <= acl_size).is_none() { return STATUS_INVALID_PARAMETER; }
        offset += size; in_use = offset;
    }
    match class {
        1 if length >= 4 => if uaccess::copy_to_user(info, &(header[0] as u32).to_le_bytes()).is_err() { STATUS_INVALID_PARAMETER } else { 0 },
        2 if length >= 12 => {
            let bytes = [(count as u32).to_le_bytes(), (in_use as u32).to_le_bytes(), ((acl_size - in_use) as u32).to_le_bytes()].concat();
            if uaccess::copy_to_user(info, &bytes).is_err() { STATUS_INVALID_PARAMETER } else { 0 }
        }
        _ => STATUS_INVALID_PARAMETER,
    }
}
fn uniform(seed: u64) -> u64 {
    if seed == 0 { return 0; }
    let mut bytes = [0u8; 4];
    if uaccess::copy_from_user(&mut bytes, seed).is_err() { return 0; }
    let value = u32::from_le_bytes(bytes) as u64;
    let next = (value * 0x7fff_ffed + 0x7fff_ffc3) % 0x7fff_ffff;
    if uaccess::copy_to_user(seed, &(next as u32).to_le_bytes()).is_err() { return 0; }
    next
}
static RANDOM_SAVED: Spinlock<[u32; 128], ModulesLockClass> = Spinlock::new([
    0x4c8bc0aa,0x4c022957,0x2232827a,0x2f1e7626,0x7f8bdafb,0x5c37d02a,0x0ab48f72,0x2f0c4ffa,
    0x290e1954,0x6b635f23,0x5d3885c0,0x74b49ff8,0x5155fa54,0x6214ad3f,0x111e9c29,0x242a3a09,
    0x75932ae1,0x40ac432e,0x54f7ba7a,0x585ccbd5,0x6df5c727,0x0374dad1,0x7112b3f1,0x735fc311,
    0x404331a9,0x74d97781,0x64495118,0x323e04be,0x5974b425,0x4862e393,0x62389c1d,0x28a68b82,
    0x0f95da37,0x7a50bbc6,0x09b0091c,0x22cdb7b4,0x4faaed26,0x66417ccd,0x189e4bfa,0x1ce4e8dd,
    0x5274c742,0x3bdcf4dc,0x2d94e907,0x32eac016,0x26d33ca3,0x60415a8a,0x31f57880,0x68c8aa52,
    0x23eb16da,0x6204f4a1,0x373927c1,0x0d24eb7c,0x06dd7379,0x2b3be507,0x0f9c55b1,0x2c7925eb,
    0x36d67c9a,0x42f831d9,0x5e3961cb,0x65d637a8,0x24bb3820,0x4d08e33d,0x2188754f,0x147e409e,
    0x6a9620a0,0x62e26657,0x7bd8ce81,0x11da0abb,0x5f9e7b50,0x23e444b6,0x25920c78,0x5fc894f0,
    0x5e338cbb,0x404237fd,0x1d60f80f,0x320a1743,0x76013d2b,0x070294ee,0x695e243b,0x56b177fd,
    0x752492e1,0x6decd52f,0x125f5219,0x139d2e78,0x1898d11e,0x2f7ee785,0x4db405d8,0x1a028a35,
    0x63f6f323,0x1f6d0078,0x307cfd67,0x3f32a78a,0x6980796c,0x462b3d83,0x34b639f2,0x53fce379,
    0x74ba50f4,0x1abc2c4b,0x5eeaeb8d,0x335a7a0d,0x3973dd20,0x0462d66b,0x159813ff,0x1e4643fd,
    0x06bc5c62,0x3115e3fc,0x09101613,0x47af2515,0x4f11ec54,0x78b99911,0x3db8dd44,0x1ec10b9b,
    0x5b5506ca,0x773ce092,0x567be81a,0x5475b975,0x7a2cde1a,0x494536f5,0x34737bb4,0x76d9750b,
    0x2a1f6232,0x2e49644d,0x7dddcbe7,0x500cebdb,0x619dab9e,0x48c626fe,0x1cda3193,0x52dabe9d,
]);
fn random(seed: u64) -> u64 {
    if seed == 0 { return 0; }
    let mut bytes = [0u8; 4];
    if uaccess::copy_from_user(&mut bytes, seed).is_err() { return 0; }
    let value = u32::from_le_bytes(bytes) as u64;
    let rand = (value * 0x7fff_ffed + 0x7fff_ffc3) % 0x7fff_ffff;
    let next = (rand * 0x7fff_ffed + 0x7fff_ffc3) % 0x7fff_ffff;
    let position = (next as usize) & 0x7f;
    let mut saved = RANDOM_SAVED.lock();
    let result = saved[position];
    saved[position] = rand as u32;
    if uaccess::copy_to_user(seed, &(next as u32).to_le_bytes()).is_err() { return 0; }
    result as u64
}
fn get_product_info(call: NtCall) -> u64 {
    if call.args.a4 == 0 { return 0; }
    if call.args.a0 < 6 {
        return if uaccess::put_user_u32(call.args.a4, PRODUCT_UNDEFINED).is_ok() { 0 } else { 0 };
    }
    if uaccess::put_user_u32(call.args.a4, PRODUCT_ULTIMATE_N).is_err() { return 0; }
    1
}

fn get_process_preferred_ui_languages(call: NtCall) -> u64 {
    get_preferred_ui_languages(call.args.a0 as u32, call.args.a1, call.args.a2, call.args.a3)
}

fn set_process_preferred_ui_languages(call: NtCall) -> u64 {
    let flags = call.args.a0 as u32;
    if call.args.a1 == 0 { return STATUS_SUCCESS; }
    let mut words = Vec::new();
    let mut languages = 0u32;
    for index in 0..1024u64 {
        let address = match call.args.a1.checked_add(index * 2) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
        let mut pair = [0u8; 2];
        if uaccess::copy_from_user(&mut pair, address).is_err() { return STATUS_INVALID_PARAMETER; }
        let word = u16::from_le_bytes(pair);
        words.push(word);
        if word == 0 {
            if index == 0 { return STATUS_UNSUCCESSFUL; }
            if words.len() >= 2 && words[words.len() - 2] == 0 { break; }
            languages += 1;
        }
    }
    if words.last().copied() != Some(0) || languages == 0 { return STATUS_UNSUCCESSFUL; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    cur.thread_group.nt_process_ui_languages.lock().clone_from(&(flags, words));
    if call.args.a2 != 0 && uaccess::put_user_u32(call.args.a2, languages).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn get_system_preferred_ui_languages(call: NtCall) -> u64 {
    let flags = call.args.a0 as u32;
    if flags & !(MUI_LANGUAGE_NAME | MUI_LANGUAGE_ID | MUI_MACHINE_LANGUAGE_SETTINGS) != 0
        || flags & MUI_LANGUAGE_NAME != 0 && flags & MUI_LANGUAGE_ID != 0 { return STATUS_INVALID_PARAMETER; }
    get_preferred_ui_languages(flags, call.args.a2, call.args.a3, call.args.a4)
}

fn get_thread_preferred_ui_languages(call: NtCall) -> u64 {
    let flags = call.args.a0 as u32;
    if flags & !(MUI_LANGUAGE_NAME | MUI_LANGUAGE_ID) != 0
        || flags & MUI_LANGUAGE_NAME != 0 && flags & MUI_LANGUAGE_ID != 0 { return STATUS_INVALID_PARAMETER; }
    get_preferred_ui_languages(flags, call.args.a1, call.args.a2, call.args.a3)
}

fn get_user_preferred_ui_languages(call: NtCall) -> u64 {
    let flags = call.args.a0 as u32;
    if flags & !(MUI_LANGUAGE_NAME | MUI_LANGUAGE_ID) != 0
        || flags & MUI_LANGUAGE_NAME != 0 && flags & MUI_LANGUAGE_ID != 0 { return STATUS_INVALID_PARAMETER; }
    get_preferred_ui_languages(flags, call.args.a2, call.args.a3, call.args.a4)
}

fn get_version(info: u64) -> u64 {
    if info == 0 { return STATUS_INVALID_PARAMETER; }
    let mut bytes = [0u8; WINDOWS_VERSION_INFO_BYTES];
    bytes[0..4].copy_from_slice(&WINDOWS_VERSION_SIZE.to_le_bytes());
    bytes[4..8].copy_from_slice(&WINDOWS_VERSION_MAJOR.to_le_bytes());
    bytes[8..12].copy_from_slice(&WINDOWS_VERSION_MINOR.to_le_bytes());
    bytes[12..16].copy_from_slice(&WINDOWS_VERSION_BUILD.to_le_bytes());
    bytes[16..20].copy_from_slice(&WINDOWS_PLATFORM_NT.to_le_bytes());
    bytes[276..278].copy_from_slice(&0u16.to_le_bytes());
    bytes[278..280].copy_from_slice(&0u16.to_le_bytes());
    bytes[280..282].copy_from_slice(&WINDOWS_SUITE_SINGLE_USER_TS.to_le_bytes());
    bytes[282] = WINDOWS_PRODUCT_WORKSTATION;
    if uaccess::copy_to_user(info, &bytes).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
}

fn init_barrier(barrier: u64, thread_count: u32, spin_count: u32) -> u64 {
    if barrier == 0 { return STATUS_INVALID_PARAMETER; }
    let mut bytes = [0u8; 24];
    bytes[0..4].copy_from_slice(&spin_count.to_le_bytes());
    bytes[4..8].copy_from_slice(&thread_count.to_le_bytes());
    if uaccess::copy_to_user(barrier, &bytes).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
}

fn impersonate_self(level: u32) -> u64 {
    if level > 3 { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
}

fn get_preferred_ui_languages(flags: u32, count: u64, buffer: u64, size: u64) -> u64 {
    const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
    if size == 0 { return STATUS_INVALID_PARAMETER; }
    let required = if flags & MUI_LANGUAGE_ID != 0 { UI_LANGUAGE_ID_U16.len() as u32 } else { UI_LANGUAGE_NAME_U16.len() as u32 };
    let capacity = match uaccess::get_user_u32(size) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
    if capacity != 0 && buffer == 0 { return STATUS_INVALID_PARAMETER; }
    if capacity < required {
        if uaccess::put_user_u32(size, required).is_err() { return STATUS_INVALID_PARAMETER; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    if count != 0 && uaccess::put_user_u32(count, 1).is_err() { return STATUS_INVALID_PARAMETER; }
    if uaccess::put_user_u32(size, required).is_err() { return STATUS_INVALID_PARAMETER; }
    let words: &[u16] = if flags & MUI_LANGUAGE_ID != 0 { &UI_LANGUAGE_ID_U16 } else { &UI_LANGUAGE_NAME_U16 };
    let mut bytes = [0u8; 14];
    for (index, word) in words.iter().enumerate() { bytes[index * 2..index * 2 + 2].copy_from_slice(&word.to_le_bytes()); }
    if uaccess::copy_to_user(buffer, &bytes[..words.len() * 2]).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn host_version(sysname: u64, release: u64) -> u64 {
    let write = |out: u64, text: &[u8]| -> Option<u64> {
        if out == 0 { return Some(0); }
        let call = NtCall { service: NtService::AllocateHeap, args: SyscallArgs { a0: 0, a1: 0, a2: (text.len() + 1) as u64, a3: 0, a4: 0, a5: 0 } };
        let buffer = crate::nt_heap::dispatch(call).filter(|value| *value != 0)?;
        let mut bytes = alloc::vec::Vec::from(text); bytes.push(0);
        if uaccess::copy_to_user(buffer, &bytes).is_err() || uaccess::put_user_u64(out, buffer).is_err() { return None; }
        Some(0)
    };
    let _ = write(sysname, syscall::uts::UTS_SYSNAME.as_bytes());
    let _ = write(release, syscall::uts::UTS_RELEASE.as_bytes());
    0
}
fn flush_slist(list: u64) -> u64 {
    if list == 0 { return 0; }
    let mut header = [0u8; 16];
    if uaccess::copy_from_user(&mut header, list).is_err() { return 0; }
    let next = u64::from_le_bytes(header[8..16].try_into().unwrap()) & !0xf;
    if next == 0 { return 0; }
    let Some(region) = list.checked_add(8) else { return 0; };
    if uaccess::copy_to_user(list, &[0u8; 8]).is_err() || uaccess::copy_to_user(region, &1u64.to_le_bytes()).is_err() { return 0; }
    next
}
fn are_bits_clear(bitmap: u64, start: u32, count: u32) -> u64 {
    if bitmap == 0 { return 0; }
    let mut descriptor = [0u8; 16];
    if uaccess::copy_from_user(&mut descriptor, bitmap).is_err() { return 0; }
    let size = u32::from_le_bytes(descriptor[0..4].try_into().unwrap());
    let buffer = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
    if count == 0 || start >= size || count > size - start || buffer == 0 { return 0; }
    for bit in start..start + count {
        let Some(address) = buffer.checked_add((bit / 8) as u64) else { return 0; };
        let mut byte = [0u8; 1];
        if uaccess::copy_from_user(&mut byte, address).is_err() || byte[0] & (1 << (bit & 7)) != 0 { return 0; }
    }
    1
}
fn are_bits_set(bitmap: u64, start: u32, count: u32) -> u64 {
    if bitmap == 0 { return 0; }
    let mut descriptor = [0u8; 16];
    if uaccess::copy_from_user(&mut descriptor, bitmap).is_err() { return 0; }
    let size = u32::from_le_bytes(descriptor[0..4].try_into().unwrap());
    let buffer = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
    if count == 0 || start >= size || count > size - start || buffer == 0 { return 0; }
    for bit in start..start + count {
        let Some(address) = buffer.checked_add((bit / 8) as u64) else { return 0; };
        let mut byte = [0u8; 1];
        if uaccess::copy_from_user(&mut byte, address).is_err() || byte[0] & (1 << (bit & 7)) == 0 { return 0; }
    }
    1
}
fn set_bits(bitmap: u64, start: u32, count: u32) -> u64 {
    if bitmap == 0 { return 0; }
    let mut descriptor = [0u8; 16];
    if uaccess::copy_from_user(&mut descriptor, bitmap).is_err() { return 0; }
    let size = u32::from_le_bytes(descriptor[0..4].try_into().unwrap());
    let buffer = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
    if count == 0 || start >= size || count > size - start || buffer == 0 { return 0; }
    for bit in start..start + count {
        let Some(address) = buffer.checked_add((bit / 8) as u64) else { return 0; };
        let mut byte = [0u8; 1];
        if uaccess::copy_from_user(&mut byte, address).is_err() { return 0; }
        byte[0] |= 1 << (bit & 7);
        if uaccess::copy_to_user(address, &byte).is_err() { return 0; }
    }
    0
}
fn initialize_bitmap(bitmap: u64, buffer: u64, size: u32) -> u64 {
    if bitmap == 0 { return STATUS_INVALID_PARAMETER; }
    let mut descriptor = [0u8; 16];
    descriptor[0..4].copy_from_slice(&size.to_le_bytes());
    descriptor[8..16].copy_from_slice(&buffer.to_le_bytes());
    if uaccess::copy_to_user(bitmap, &descriptor).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
}
fn push_slist(list: u64, entry: u64) -> u64 {
    if list == 0 || entry == 0 || entry & 0xf != 0 { return 0; }
    let Some(list_tail) = list.checked_add(8) else { return 0; };
    let mut header = [0u8; 16];
    if uaccess::copy_from_user(&mut header, list).is_err() { return 0; }
    let old_head = u64::from_le_bytes(header[8..16].try_into().unwrap()) & !0xf;
    let first = u64::from_le_bytes(header[0..8].try_into().unwrap());
    let depth = (first as u16).wrapping_add(1);
    let sequence = (((first >> 16) & 0x0000_ffff_ffff_ffff).wrapping_add(1)) & 0x0000_ffff_ffff_ffff;
    if uaccess::put_user_u64(entry, old_head).is_err() { return 0; }
    let new_first = depth as u64 | (sequence << 16);
    let new_second = (entry & !0xf) | (u64::from_le_bytes(header[8..16].try_into().unwrap()) & 0xf);
    if uaccess::copy_to_user(list, &new_first.to_le_bytes()).is_err() || uaccess::copy_to_user(list_tail, &new_second.to_le_bytes()).is_err() { return 0; }
    old_head
}
fn create_security_descriptor(descriptor: u64, revision: u32) -> u64 {
    if descriptor == 0 { return STATUS_INVALID_PARAMETER; }
    if revision != 1 { return STATUS_UNKNOWN_REVISION; }
    let mut bytes = [0u8; SECURITY_DESCRIPTOR_BYTES]; bytes[0] = 1;
    if uaccess::copy_to_user(descriptor, &bytes).is_err() { return STATUS_INVALID_PARAMETER; }
    0
}
fn create_acl(acl: u64, size: u32, revision: u32) -> u64 {
    if acl == 0 || revision < 2 || revision > 4 { return STATUS_INVALID_PARAMETER; }
    if size < ACL_HEADER_BYTES as u32 { return 0xc000_0023; }
    if size > u16::MAX as u32 { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; ACL_HEADER_BYTES]; header[0] = revision as u8;
    header[2..4].copy_from_slice(&(size as u16).to_le_bytes());
    if uaccess::copy_to_user(acl, &header).is_err() { return STATUS_INVALID_PARAMETER; }
    0
}
fn add_aces(acl: u64, revision: u32, source: u64, source_len: u32) -> u64 {
    if acl == 0 || revision > 4 || source_len > u16::MAX as u32 || (source_len != 0 && source == 0) { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; ACL_HEADER_BYTES];
    if uaccess::copy_from_user(&mut header, acl).is_err() { return STATUS_INVALID_PARAMETER; }
    let acl_revision = header[0] as u32;
    let acl_size = u16::from_le_bytes([header[2], header[3]]) as usize;
    let ace_count = u16::from_le_bytes([header[4], header[5]]) as usize;
    if acl_revision < 2 || acl_revision > 4 || acl_size < ACL_HEADER_BYTES { return STATUS_INVALID_PARAMETER; }
    if revision < acl_revision { return STATUS_REVISION_MISMATCH; }
    let mut target = ACL_HEADER_BYTES;
    for _ in 0..ace_count {
        let mut ace_header = [0u8; ACE_HEADER_BYTES];
        if target.checked_add(ACE_HEADER_BYTES).filter(|end| *end <= acl_size).is_none() || uaccess::copy_from_user(&mut ace_header, acl + target as u64).is_err() { return STATUS_INVALID_PARAMETER; }
        let size = u16::from_le_bytes([ace_header[2], ace_header[3]]) as usize;
        if size < ACE_HEADER_BYTES || target.checked_add(size).filter(|end| *end <= acl_size).is_none() { return STATUS_INVALID_PARAMETER; }
        target += size;
    }
    let mut bytes = vec![0u8; source_len as usize];
    if source_len != 0 && uaccess::copy_from_user(&mut bytes, source).is_err() { return STATUS_INVALID_PARAMETER; }
    let mut count = 0usize; let mut offset = 0usize;
    while offset < bytes.len() {
        if offset + ACE_HEADER_BYTES > bytes.len() { return STATUS_INVALID_PARAMETER; }
        let size = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        if size < ACE_HEADER_BYTES || offset.checked_add(size).filter(|end| *end <= bytes.len()).is_none() { return STATUS_INVALID_PARAMETER; }
        count += 1; offset += size;
    }
    if target.checked_add(bytes.len()).filter(|end| *end <= acl_size).is_none() || ace_count.checked_add(count).filter(|count| *count <= u16::MAX as usize).is_none() { return STATUS_INVALID_PARAMETER; }
    if !bytes.is_empty() && uaccess::copy_to_user(acl + target as u64, &bytes).is_err() { return STATUS_INVALID_PARAMETER; }
    header[0] = revision as u8; header[4..6].copy_from_slice(&((ace_count + count) as u16).to_le_bytes());
    if uaccess::copy_to_user(acl, &header).is_err() { return STATUS_INVALID_PARAMETER; }
    0
}
fn add_access_ace(acl: u64, revision: u32, flags: u32, mask: u32, sid: u64, ace_type: u8) -> u64 {
    if acl == 0 || sid == 0 || revision > 4 { return STATUS_INVALID_PARAMETER; }
    let mut acl_header = [0u8; ACL_HEADER_BYTES];
    if uaccess::copy_from_user(&mut acl_header, acl).is_err() { return STATUS_INVALID_PARAMETER; }
    let acl_revision = acl_header[0] as u32;
    let acl_size = u16::from_le_bytes([acl_header[2], acl_header[3]]) as usize;
    let ace_count = u16::from_le_bytes([acl_header[4], acl_header[5]]) as usize;
    if acl_revision > 4 || acl_size < ACL_HEADER_BYTES { return STATUS_INVALID_ACL; }
    if revision > 4 || (revision != 0 && acl_revision != 0 && revision < acl_revision) { return STATUS_REVISION_MISMATCH; }
    let mut sid_header = [0u8; SID_HEADER_BYTES];
    if uaccess::copy_from_user(&mut sid_header, sid).is_err() || sid_header[0] != 1 || sid_header[1] as usize > MAX_SUBAUTHORITIES { return STATUS_INVALID_SID; }
    let sid_len = SID_HEADER_BYTES + sid_header[1] as usize * 4;
    let mut sid_bytes = [0u8; SID_HEADER_BYTES + MAX_SUBAUTHORITIES * 4];
    if uaccess::copy_from_user(&mut sid_bytes[..sid_len], sid).is_err() { return STATUS_INVALID_SID; }
    let mut offset = ACL_HEADER_BYTES;
    for _ in 0..ace_count {
        let Some(end) = offset.checked_add(ACE_HEADER_BYTES) else { return STATUS_INVALID_ACL; };
        if end > acl_size { return STATUS_INVALID_ACL; }
        let mut header = [0u8; ACE_HEADER_BYTES];
        if uaccess::copy_from_user(&mut header, acl + offset as u64).is_err() { return STATUS_INVALID_ACL; }
        let size = u16::from_le_bytes([header[2], header[3]]) as usize;
        if size < ACE_HEADER_BYTES || offset.checked_add(size).filter(|end| *end <= acl_size).is_none() { return STATUS_INVALID_ACL; }
        offset += size;
    }
    let ace_size = ACE_HEADER_BYTES + core::mem::size_of::<u32>() + sid_len;
    if ace_size > u16::MAX as usize || offset.checked_add(ace_size).filter(|end| *end <= acl_size).is_none() { return STATUS_ALLOTTED_SPACE_EXCEEDED; }
    let mut ace = [0u8; ACE_HEADER_BYTES + 4 + SID_HEADER_BYTES + MAX_SUBAUTHORITIES * 4];
    ace[0] = ace_type; ace[1] = flags as u8; ace[2..4].copy_from_slice(&(ace_size as u16).to_le_bytes());
    ace[4..8].copy_from_slice(&mask.to_le_bytes()); ace[8..8 + sid_len].copy_from_slice(&sid_bytes[..sid_len]);
    if uaccess::copy_to_user(acl + offset as u64, &ace[..ace_size]).is_err() { return STATUS_INVALID_PARAMETER; }
    acl_header[0] = core::cmp::max(acl_revision, revision) as u8;
    acl_header[4..6].copy_from_slice(&((ace_count + 1) as u16).to_le_bytes());
    if uaccess::copy_to_user(acl, &acl_header).is_err() { return STATUS_INVALID_PARAMETER; }
    0
}
