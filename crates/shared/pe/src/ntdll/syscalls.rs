//! The NTDLL system-service boundary: which exported names enter the kernel.
//!
//! On the Windows ABI `ntdll.dll` is a user-mode library. Exactly one class of
//! its exports leaves user mode: the system services, each a stub that issues
//! the architecture's syscall instruction. Every other export — the RTL
//! routines, the loader, the heap, the lock and condition-variable
//! primitives, the compiler and unwinder support entries, and the C runtime
//! entries ntdll re-exports — executes entirely at user privilege and must
//! never cost a kernel entry.
//!
//! The table is the x86-64 system-service set, sorted so lookup is a binary
//! search and so a name added out of order is visible in review. A name that
//! merely begins with `Nt` is not a system service: `NtCurrentTeb` and
//! `NtdllDefWindowProc_W` are ordinary user-mode exports, which is why this is
//! an enumerated set rather than a prefix rule.

/// Where an NTDLL export executes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Role {
    /// A system service: the stub issues a syscall and the kernel does the work.
    KernelSyscall,
    /// User-mode library code. A kernel entry here is a privilege the ABI does not ask for.
    UserMode,
}

/// System services, sorted by name.
pub(crate) const SERVICES: [&[u8]; 264] = [
    b"NtAcceptConnectPort", b"NtAccessCheck", b"NtAccessCheckAndAuditAlarm", b"NtAccessCheckByTypeAndAuditAlarm", b"NtAddAtom",
    b"NtAdjustGroupsToken", b"NtAdjustPrivilegesToken", b"NtAlertMultipleThreadByThreadId", b"NtAlertResumeThread", b"NtAlertThread",
    b"NtAlertThreadByThreadId", b"NtAllocateLocallyUniqueId", b"NtAllocateReserveObject", b"NtAllocateUuids", b"NtAllocateVirtualMemory",
    b"NtAllocateVirtualMemoryEx", b"NtAlpcAcceptConnectPort", b"NtAlpcConnectPort", b"NtAlpcCreatePort", b"NtAlpcDisconnectPort",
    b"NtAlpcImpersonateClientOfPort", b"NtAlpcSendWaitReceivePort", b"NtApphelpCacheControl", b"NtAreMappedFilesTheSame",
    b"NtAssignProcessToJobObject", b"NtCallbackReturn", b"NtCancelIoFile", b"NtCancelIoFileEx", b"NtCancelSynchronousIoFile", b"NtCancelTimer",
    b"NtClearEvent", b"NtClose", b"NtCloseObjectAuditAlarm", b"NtCommitTransaction", b"NtCompareObjects", b"NtCompareTokens",
    b"NtCompleteConnectPort", b"NtConnectPort", b"NtContinue", b"NtContinueEx", b"NtConvertBetweenAuxiliaryCounterAndPerformanceCounter",
    b"NtCreateDebugObject", b"NtCreateDirectoryObject", b"NtCreateEvent", b"NtCreateFile", b"NtCreateIoCompletion", b"NtCreateJobObject",
    b"NtCreateKey", b"NtCreateKeyTransacted", b"NtCreateKeyedEvent", b"NtCreateLowBoxToken", b"NtCreateMailslotFile", b"NtCreateMutant",
    b"NtCreateNamedPipeFile", b"NtCreatePagingFile", b"NtCreatePort", b"NtCreateProcessEx", b"NtCreateSection", b"NtCreateSectionEx",
    b"NtCreateSemaphore", b"NtCreateSymbolicLinkObject", b"NtCreateThread", b"NtCreateThreadEx", b"NtCreateTimer", b"NtCreateToken",
    b"NtCreateTransaction", b"NtCreateUserProcess", b"NtDebugActiveProcess", b"NtDebugContinue", b"NtDelayExecution", b"NtDeleteAtom",
    b"NtDeleteFile", b"NtDeleteKey", b"NtDeleteValueKey", b"NtDeviceIoControlFile", b"NtDisplayString", b"NtDuplicateObject", b"NtDuplicateToken",
    b"NtEnumerateKey", b"NtEnumerateValueKey", b"NtFilterToken", b"NtFindAtom", b"NtFlushBuffersFile", b"NtFlushBuffersFileEx",
    b"NtFlushInstructionCache", b"NtFlushKey", b"NtFlushProcessWriteBuffers", b"NtFlushVirtualMemory", b"NtFreeVirtualMemory", b"NtFsControlFile",
    b"NtGetContextThread", b"NtGetCurrentProcessorNumber", b"NtGetNextProcess", b"NtGetNextThread", b"NtGetNlsSectionPtr", b"NtGetWriteWatch",
    b"NtImpersonateAnonymousToken", b"NtImpersonateClientOfPort", b"NtInitializeNlsFiles", b"NtInitiatePowerAction", b"NtIsProcessInJob",
    b"NtListenPort", b"NtLoadDriver", b"NtLoadKey", b"NtLoadKey2", b"NtLoadKeyEx", b"NtLockFile", b"NtLockVirtualMemory", b"NtMakePermanentObject",
    b"NtMakeTemporaryObject", b"NtMapUserPhysicalPagesScatter", b"NtMapViewOfSection", b"NtMapViewOfSectionEx", b"NtNotifyChangeDirectoryFile",
    b"NtNotifyChangeKey", b"NtNotifyChangeMultipleKeys", b"NtOpenDirectoryObject", b"NtOpenEvent", b"NtOpenFile", b"NtOpenIoCompletion",
    b"NtOpenJobObject", b"NtOpenKey", b"NtOpenKeyEx", b"NtOpenKeyTransacted", b"NtOpenKeyTransactedEx", b"NtOpenKeyedEvent", b"NtOpenMutant",
    b"NtOpenProcess", b"NtOpenProcessToken", b"NtOpenProcessTokenEx", b"NtOpenSection", b"NtOpenSemaphore", b"NtOpenSymbolicLinkObject",
    b"NtOpenThread", b"NtOpenThreadToken", b"NtOpenThreadTokenEx", b"NtOpenTimer", b"NtPowerInformation", b"NtPrivilegeCheck",
    b"NtProtectVirtualMemory", b"NtPulseEvent", b"NtQueryAttributesFile", b"NtQueryDefaultLocale", b"NtQueryDefaultUILanguage",
    b"NtQueryDirectoryFile", b"NtQueryDirectoryObject", b"NtQueryEaFile", b"NtQueryEvent", b"NtQueryFullAttributesFile", b"NtQueryInformationAtom",
    b"NtQueryInformationFile", b"NtQueryInformationJobObject", b"NtQueryInformationProcess", b"NtQueryInformationThread", b"NtQueryInformationToken",
    b"NtQueryInstallUILanguage", b"NtQueryIoCompletion", b"NtQueryKey", b"NtQueryLicenseValue", b"NtQueryMultipleValueKey", b"NtQueryMutant",
    b"NtQueryObject", b"NtQueryPerformanceCounter", b"NtQuerySection", b"NtQuerySecurityObject", b"NtQuerySemaphore", b"NtQuerySymbolicLinkObject",
    b"NtQuerySystemEnvironmentValue", b"NtQuerySystemEnvironmentValueEx", b"NtQuerySystemInformation", b"NtQuerySystemInformationEx",
    b"NtQuerySystemTime", b"NtQueryTimer", b"NtQueryTimerResolution", b"NtQueryValueKey", b"NtQueryVirtualMemory", b"NtQueryVolumeInformationFile",
    b"NtQueueApcThread", b"NtQueueApcThreadEx", b"NtQueueApcThreadEx2", b"NtRaiseException", b"NtRaiseHardError", b"NtReadFile",
    b"NtReadFileScatter", b"NtReadRequestData", b"NtReadVirtualMemory", b"NtRegisterThreadTerminatePort", b"NtReleaseKeyedEvent", b"NtReleaseMutant",
    b"NtReleaseSemaphore", b"NtRemoveIoCompletion", b"NtRemoveIoCompletionEx", b"NtRemoveProcessDebug", b"NtRenameKey", b"NtReplaceKey",
    b"NtReplyPort", b"NtReplyWaitReceivePort", b"NtReplyWaitReceivePortEx", b"NtRequestWaitReplyPort", b"NtResetEvent", b"NtResetWriteWatch",
    b"NtRestoreKey", b"NtResumeProcess", b"NtResumeThread", b"NtRollbackTransaction", b"NtSaveKey", b"NtSecureConnectPort", b"NtSetContextThread",
    b"NtSetDebugFilterState", b"NtSetDefaultLocale", b"NtSetDefaultUILanguage", b"NtSetEaFile", b"NtSetEvent", b"NtSetEventBoostPriority",
    b"NtSetInformationDebugObject", b"NtSetInformationFile", b"NtSetInformationJobObject", b"NtSetInformationKey", b"NtSetInformationObject",
    b"NtSetInformationProcess", b"NtSetInformationThread", b"NtSetInformationToken", b"NtSetInformationVirtualMemory", b"NtSetIntervalProfile",
    b"NtSetIoCompletion", b"NtSetIoCompletionEx", b"NtSetLdtEntries", b"NtSetSecurityObject", b"NtSetSystemInformation", b"NtSetSystemTime",
    b"NtSetThreadExecutionState", b"NtSetTimer", b"NtSetTimerResolution", b"NtSetValueKey", b"NtSetVolumeInformationFile", b"NtShutdownSystem",
    b"NtSignalAndWaitForSingleObject", b"NtSuspendProcess", b"NtSuspendThread", b"NtSystemDebugControl", b"NtTerminateJobObject",
    b"NtTerminateProcess", b"NtTerminateThread", b"NtTestAlert", b"NtTraceControl", b"NtTraceEvent", b"NtUnloadDriver", b"NtUnloadKey",
    b"NtUnlockFile", b"NtUnlockVirtualMemory", b"NtUnmapViewOfSection", b"NtUnmapViewOfSectionEx", b"NtWaitForAlertByThreadId",
    b"NtWaitForDebugEvent", b"NtWaitForKeyedEvent", b"NtWaitForMultipleObjects", b"NtWaitForMultipleObjects32", b"NtWaitForSingleObject",
    b"NtWorkerFactoryWorkerReady", b"NtWriteFile", b"NtWriteFileGather", b"NtWriteRequestData", b"NtWriteVirtualMemory", b"NtYieldExecution"
];

/// The service names, in table order. # C: O(1) per item
pub fn service_names() -> impl Iterator<Item = &'static str> {
    SERVICES.iter().map(|name| core::str::from_utf8(name).unwrap_or(""))
}

/// Classify one NTDLL export name.
/// # C: O(log N) over the system-service table
pub fn role(name: &[u8]) -> Role {
    if SERVICES.binary_search(&name).is_ok() { return Role::KernelSyscall; }
    // `Zw` names are the alternate entry points of the same services.
    if let Some(rest) = name.strip_prefix(b"Zw") {
        let mut probe = [0u8; MAX_SERVICE_BYTES];
        let end = rest.len() + 2;
        if end <= MAX_SERVICE_BYTES {
            probe[0] = b'N'; probe[1] = b't';
            probe[2..end].copy_from_slice(rest);
            if SERVICES.binary_search(&&probe[..end]).is_ok() { return Role::KernelSyscall; }
        }
    }
    Role::UserMode
}

/// Longest system-service name, bounding the `Zw` alias probe buffer.
const MAX_SERVICE_BYTES: usize = 64;

/// Whether the export leaves user mode. # C: O(log N)
pub fn is_kernel_syscall(name: &[u8]) -> bool { matches!(role(name), Role::KernelSyscall) }

/// Count of system services on the x86-64 boundary. # C: O(1)
pub fn service_count() -> usize { SERVICES.len() }

#[path = "syscalls/tests.rs"]
#[cfg(test)]
mod tests;
