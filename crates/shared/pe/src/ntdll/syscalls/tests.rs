//! Provenance for the NTDLL system-service boundary.
//!
//! Each case pins a decision taken from the x86-64 system-service table of the
//! Windows runtime this tree targets, so the boundary is re-checkable here
//! rather than by re-reading another tree.

use alloc::string::String;
use super::{is_kernel_syscall, role, service_count, Role};

/// The x86-64 boundary the runtime publishes. A service added or removed
/// changes this count, which is the whole point of pinning it.
#[test]
fn the_boundary_carries_the_full_x86_64_system_service_set() {
    assert_eq!(service_count(), 264);
}

/// Binary search is only correct on a sorted table, and an out-of-order entry
/// would silently classify a service as user-mode.
#[test]
fn the_service_table_is_sorted_and_free_of_duplicates() {
    let mut previous: &[u8] = b"";
    for name in super::SERVICES {
        assert!(previous < name, "service table out of order at {}", String::from_utf8_lossy(name));
        previous = name;
    }
}

/// Services drawn from across the table, including the longest name.
#[test]
fn system_services_are_classified_as_kernel_entries() {
    for name in [b"NtAccessCheck".as_slice(), b"NtReadFile", b"NtWriteFile", b"NtCreateFile",
                 b"NtAllocateVirtualMemory", b"NtWaitForSingleObject", b"NtCallbackReturn",
                 b"NtQueryInformationProcess", b"NtCreateThreadEx", b"NtClose",
                 b"NtConvertBetweenAuxiliaryCounterAndPerformanceCounter",
                 b"NtWaitForAlertByThreadId", b"NtWaitForKeyedEvent"] {
        assert_eq!(role(name), Role::KernelSyscall, "{} is a system service", String::from_utf8_lossy(name));
    }
}

/// The alternate entry points of the same services.
#[test]
fn the_alternate_service_entry_points_are_kernel_entries() {
    for name in [b"ZwReadFile".as_slice(), b"ZwClose", b"ZwAllocateVirtualMemory",
                 b"ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter"] {
        assert!(is_kernel_syscall(name), "{} is a service alias", String::from_utf8_lossy(name));
    }
}

/// The reason this is an enumerated set and not an `Nt` prefix rule: these
/// names begin with `Nt` and run entirely in user mode.
#[test]
fn nt_prefixed_user_mode_exports_are_not_kernel_entries() {
    for name in [b"NtCurrentTeb".as_slice(), b"NtdllDefWindowProc_A", b"NtdllDefWindowProc_W",
                 b"NtGetTickCount", b"Ntdll"] {
        assert_eq!(role(name), Role::UserMode, "{} runs in user mode", String::from_utf8_lossy(name));
    }
}

/// A `Zw` name with no matching service is an ordinary export, not a service.
#[test]
fn an_unmatched_alternate_prefix_stays_user_mode() {
    assert_eq!(role(b"ZwNoSuchServiceExists"), Role::UserMode);
    assert_eq!(role(b"Zw"), Role::UserMode);
}

/// The routines the PE toolchain emits calls to. Every one of these is library
/// code on the Windows ABI: a stack probe, the language exception handler, the
/// RTL string and image helpers, the lock and condition-variable primitives.
#[test]
fn the_compiler_and_rtl_support_surface_is_user_mode() {
    for name in [b"__chkstk".as_slice(), b"__C_specific_handler",
                 b"RtlAcquireSRWLockExclusive", b"RtlAcquireSRWLockShared",
                 b"RtlReleaseSRWLockExclusive", b"RtlReleaseSRWLockShared",
                 b"RtlTryAcquireSRWLockExclusive", b"RtlWakeConditionVariable",
                 b"RtlAddFunctionTable", b"RtlDeleteFunctionTable", b"RtlInstallFunctionTableCallback",
                 b"RtlCompareString", b"RtlEqualUnicodeString", b"RtlInitString",
                 b"RtlCopyUnicodeString", b"RtlComputeCrc32", b"RtlImageRvaToSection",
                 b"RtlIsCurrentProcess", b"_wcslwr"] {
        assert_eq!(role(name), Role::UserMode, "{} runs in user mode", String::from_utf8_lossy(name));
    }
}

/// The C runtime entries the library re-exports never enter the kernel.
#[test]
fn the_c_runtime_exports_are_user_mode() {
    for name in [b"memcpy".as_slice(), b"memmove", b"memset", b"strlen", b"strcpy",
                 b"wcslen", b"tolower", b"isalpha", b"_vsnprintf", b"longjmp"] {
        assert_eq!(role(name), Role::UserMode, "{} runs in user mode", String::from_utf8_lossy(name));
    }
}
