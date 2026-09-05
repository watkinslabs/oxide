use alloc::sync::Arc; use crate::pe_init; use crate::pe_modules; use crate::process_env; use hal::UserVirtAddr; use pe::{self, SectionFlags}; use vmm::{AddressSpace, MmapPlacement, VmaBacking, VmaFlags, VmaProt};
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PeLoadedImage {
    pub base: u64,
    pub preferred_base: u64,
    pub entry: UserVirtAddr,
    pub size: u32,
    pub exception_directory: (u32, u32),
    pub tls_directory: (u32, u32),
}
pub struct PeLoadedModule<'a> {
    pub name: &'a [u8],
    pub image: PeLoadedImage,
}
pub struct PeModuleBase<'a> {
    pub name: &'a [u8],
    pub base: u64, pub size: u32,
}
pub struct NtRuntime {
    pub base: UserVirtAddr,
    pub bytes: usize,
    pub relay_call: u64,
    pub wine_dispatcher: u64,
    pub wine_unix_dispatcher: u64,
    pub wine_unixlib_handle: u64,
    addresses: [u64; 509],
}
const NTDLL_EXPORTS: [&[u8]; 509] = [
    b"NtAllocateVirtualMemory", b"NtFreeVirtualMemory", b"NtProtectVirtualMemory", b"NtQueryVirtualMemory",
    b"NtTerminateProcess", b"NtCreateEvent", b"NtClose", b"NtSetEvent", b"NtResetEvent", b"NtWaitForSingleObject",
    b"NtCreateFile", b"NtOpenFile", b"NtReadFile", b"NtWriteFile", b"NtQueryInformationFile", b"NtSetInformationFile", b"NtQueryDirectoryFile", b"NtWaitForMultipleObjects",
    b"NtCreateSection", b"NtMapViewOfSection", b"NtUnmapViewOfSection", b"NtQueryInformationProcess", b"NtCreateThreadEx", b"NtTerminateThread", b"NtQueryInformationThread",
    b"RtlAllocateHeap", b"RtlFreeHeap", b"NtdllDefWindowProc_A", b"NtdllDefWindowProc_W", b"RtlReAllocateHeap", b"LdrResolveDelayLoadedAPI", b"RtlUnwind", b"NtCreateSemaphore", b"NtReleaseSemaphore", b"NtCreateMutant", b"NtReleaseMutant", b"NtQueryMutant", b"NtLockFile", b"NtUnlockFile", b"NtDuplicateObject", b"NtCreateTimer", b"NtSetTimer", b"NtCancelTimer", b"NtCreateIoCompletion", b"NtSetIoCompletion", b"NtRemoveIoCompletion", b"NtSignalAndWaitForSingleObject", b"NtOpenProcessToken", b"NtOpenThreadToken", b"NtQueryInformationToken", b"RtlInitUnicodeString", b"RtlInitUnicodeStringEx", b"NtQueryObject", b"RtlInitAnsiString", b"RtlInitAnsiStringEx", b"NtQuerySecurityObject", b"RtlQueryPerformanceCounter", b"RtlQueryPerformanceFrequency", b"NtRenameKey", b"NtSetSecurityObject", b"RtlAddAccessAllowedAce", b"RtlAddAccessAllowedAceEx", b"RtlAddAccessDeniedAce", b"RtlAddAccessDeniedAceEx", b"RtlAddAce", b"RtlAddAuditAccessAce", b"RtlAddAuditAccessAceEx", b"RtlCreateAcl", b"RtlCreateSecurityDescriptor", b"RtlCreateUnicodeStringFromAsciiz", b"RtlDosPathNameToNtPathName_U", b"RtlFreeUnicodeString", b"RtlGetAce", b"RtlGetControlSecurityDescriptor", b"RtlIsTextUnicode", b"RtlLengthSecurityDescriptor", b"RtlMakeSelfRelativeSD", b"RtlNtStatusToDosError", b"RtlQueryInformationAcl", b"RtlSelfRelativeToAbsoluteSD", b"RtlUniform", b"RtlDeleteCriticalSection", b"RtlEnterCriticalSection", b"RtlLeaveCriticalSection", b"_vsnprintf", b"RtlSizeHeap", b"RtlExitUserThread", b"RtlQueryUnbiasedInterruptTime", b"DbgUiGetThreadDebugObject", b"DbgUiIssueRemoteBreakin", b"LdrGetDllDirectory", b"LdrGetProcedureAddress", b"LdrSetDllDirectory", b"NtAddAtom", b"NtAssignProcessToJobObject", b"NtCreateJobObject", b"NtCreateMailslotFile", b"NtDeleteAtom", b"NtDeviceIoControlFile", b"NtFindAtom", b"NtFsControlFile", b"NtOpenJobObject", b"NtPowerInformation", b"NtQueryInformationAtom", b"NtQueryInformationJobObject", b"NtQuerySection", b"NtQuerySystemInformation", b"NtQuerySystemTime", b"NtSetInformationDebugObject", b"NtSetInformationJobObject", b"NtSetInformationProcess", b"NtSetInformationThread", b"NtSetThreadExecutionState", b"NtTerminateJobObject", b"RtlAcquirePebLock", b"RtlReleasePebLock", b"RtlAddAtomToAtomTable",
    b"RtlAnsiStringToUnicodeString", b"RtlCaptureContext", b"RtlCharToInteger", b"RtlCreateAtomTable", b"RtlCreateHeap", b"RtlCreateUnicodeString", b"RtlDeleteAtomFromAtomTable", b"RtlDeregisterWait", b"RtlDestroyAtomTable", b"RtlDestroyHeap", b"RtlDetermineDosPathNameType_U", b"RtlDosPathNameToNtPathName_U_WithStatus", b"RtlExitUserProcess", b"RtlGetProcessHeaps", b"RtlGetUserInfoHeap", b"RtlImageNtHeader", b"RtlInitializeCriticalSection", b"RtlInitializeCriticalSectionAndSpinCount", b"RtlInitializeCriticalSectionEx", b"RtlIsNameLegalDOS8Dot3", b"RtlLockHeap", b"RtlUnlockHeap", b"RtlLookupAtomInAtomTable", b"RtlOemStringToUnicodeString", b"RtlQueryAtomInAtomTable", b"RtlRegisterWait", b"RtlRestoreContext", b"RtlSetIoCompletionCallback", b"RtlGetLastWin32Error", b"RtlRestoreLastWin32Error", b"RtlSetLastWin32Error", b"RtlSetSearchPathMode", b"RtlSetUnhandledExceptionFilter", b"RtlSetUserValueHeap", b"RtlTimeFieldsToTime", b"RtlTimeToTimeFields", b"RtlTimeToSecondsSince1970", b"RtlUnicodeStringToAnsiSize", b"RtlUnicodeStringToAnsiString", b"RtlUnicodeStringToInteger", b"RtlUnicodeStringToOemSize", b"RtlUnicodeStringToOemString", b"RtlUnicodeToMultiByteN", b"RtlUnicodeToMultiByteSize", b"RtlUnicodeToOemN", b"RtlUpcaseUnicodeString", b"RtlUpperChar", b"_wcsicmp", b"_wcsnicmp", b"isalpha", b"islower", b"memcpy", b"memmove", b"memset", b"strcat", b"strchr", b"strcpy", b"strlen", b"strpbrk", b"strrchr", b"tolower", b"wcscat", b"wcschr", b"wcscmp", b"wcscpy", b"wcslen", b"wcsncmp", b"wcsrchr", b"wcstoul", b"__wine_dbg_header", b"__wine_dbg_output", b"__wine_dbg_strdup", b"RtlGUIDFromString", b"RtlRandom", b"wine_get_host_version", b"RtlInterlockedFlushSList", b"RtlInterlockedPushEntrySList", b"RtlTryEnterCriticalSection", b"RtlAreBitsClear", b"RtlAreBitsSet", b"RtlInitializeBitMap", b"RtlLookupFunctionEntry", b"RtlPcToFileHeader", b"RtlSetBits", b"RtlUnwindEx", b"_setjmp", b"_setjmpex", b"longjmp", b"__wine_dbg_get_channel_flags", b"LdrGetDllFullName", b"LdrLoadDll", b"LdrQueryImageFileExecutionOptions", b"NtCallbackReturn", b"NtOpenDirectoryObject",
    b"RtlFindActivationContextSectionString", b"RtlImageDirectoryEntryToData", b"RtlImageRvaToVa", b"RtlInitializeNtUserPfn", b"RtlMultiByteToUnicodeN", b"RtlMultiByteToUnicodeSize", b"RtlRetrieveNtUserPfn", b"RtlResetNtUserPfn", b"ApiSetQueryApiSetPresenceEx", b"DbgBreakPoint", b"DbgUiConnectToDbg", b"DbgUiContinue", b"DbgUiRemoteBreakin", b"DbgUiStopDebugging", b"DbgUiWaitStateChange", b"DbgUiConvertStateChangeStructure", b"DbgUiDebugActiveProcess", b"LdrAccessResource", b"LdrAddDllDirectory", b"LdrRemoveDllDirectory", b"LdrAddRefDll", b"LdrDisableThreadCalloutsForDll", b"LdrFindResourceDirectory_U", b"LdrFindResource_U", b"LdrGetDllHandleEx", b"LdrGetDllPath", b"LdrSetDefaultDllDirectories", b"LdrUnloadDll", b"NtAccessCheck", b"NtAdjustGroupsToken", b"NtAdjustPrivilegesToken", b"NtAllocateLocallyUniqueId", b"NtAllocateVirtualMemoryEx", b"NtCancelIoFile", b"NtCancelIoFileEx", b"NtCancelSynchronousIoFile", b"NtCompareObjects", b"NtConvertBetweenAuxiliaryCounterAndPerformanceCounter", b"NtCreateKey", b"NtCreateNamedPipeFile", b"NtCreateSectionEx",
    b"NtCreateSymbolicLinkObject",
    b"NtCreateUserProcess",
    b"NtDelayExecution",
    b"NtDeleteKey",
    b"NtDeleteValueKey",
    b"NtDuplicateToken",
    b"NtEnumerateKey",
    b"NtEnumerateValueKey",
    b"NtFilterToken",
    b"NtFlushBuffersFile",
    b"NtFlushInstructionCache",
    b"NtFlushKey",
    b"NtFlushVirtualMemory",
    b"NtGetContextThread",
    b"NtGetNlsSectionPtr",
    b"NtGetTickCount",
    b"NtGetWriteWatch",
    b"NtImpersonateAnonymousToken",
    b"NtIsProcessInJob",
    b"NtLoadKey",
    b"NtLockVirtualMemory",
    b"NtMakeTemporaryObject",
    b"NtMapViewOfSectionEx",
    b"NtNotifyChangeDirectoryFile",
    b"NtNotifyChangeKey",
    b"NtOpenEvent",
    b"NtOpenKey",
    b"NtOpenKeyEx",
    b"NtOpenMutant",
    b"NtOpenProcess",
    b"NtOpenSection",
    b"NtOpenSemaphore",
    b"NtOpenSymbolicLinkObject",
    b"NtOpenThread",
    b"NtOpenTimer",
    b"NtPrivilegeCheck",
    b"NtPulseEvent",
    b"NtQueryAttributesFile",
    b"NtQueryDefaultLocale",
    b"NtQueryDefaultUILanguage",
    b"NtQueryDirectoryObject",
    b"NtQueryFullAttributesFile",
    b"NtQueryInstallUILanguage",
    b"NtQueryKey",
    b"NtQueryPerformanceCounter",
    b"NtQuerySymbolicLinkObject",
    b"NtQuerySystemInformationEx",
    b"NtQueryValueKey",
    b"NtQueryVolumeInformationFile",
    b"NtQueueApcThread",
    b"NtQueueApcThreadEx2",
    b"NtRaiseException",
    b"NtReadFileScatter",
    b"NtReadVirtualMemory",
    b"NtRemoveIoCompletionEx",
    b"NtResetWriteWatch",
    b"NtResumeThread",
    b"NtSaveKey",
    b"NtSetContextThread",
    b"NtSetInformationObject",
    b"NtSetInformationToken",
    b"NtSetInformationVirtualMemory",
    b"NtSetSystemInformation",
    b"NtSetSystemTime",
    b"NtSetValueKey",
    b"NtSuspendThread",
    b"NtUnloadKey",
    b"NtUnlockVirtualMemory",
    b"NtUnmapViewOfSectionEx",
    b"NtWriteFileGather",
    b"NtWriteVirtualMemory",
    b"NtYieldExecution",
    b"RtlActivateActivationContext",
    b"RtlActivateActivationContextEx",
    b"RtlAddAccessAllowedObjectAce",
    b"RtlAddAccessDeniedObjectAce",
    b"RtlAddAuditAccessObjectAce",
    b"RtlAddMandatoryAce",
    b"RtlAddRefActivationContext",
    b"RtlAllocateAndInitializeSid",
    b"RtlAreAllAccessesGranted",
    b"RtlAreAnyAccessesGranted",
    b"RtlBarrier",
    b"RtlClearBits",
    b"RtlCompactHeap",
    b"RtlCompareUnicodeStrings",
    b"RtlConvertSidToUnicodeString",
    b"RtlConvertToAutoInheritSecurityObject",
    b"RtlCopyContext",
    b"RtlCopySid",
    b"RtlCreateActivationContext",
    b"RtlCreateEnvironment",
    b"RtlCreateProcessParametersEx",
    b"RtlCreateTimer",
    b"RtlCreateTimerQueue",
    b"RtlCreateUserStack",
    b"RtlDeactivateActivationContext",
    b"RtlReleaseActivationContext",
    b"RtlDeleteAce",
    b"RtlDeleteBarrier",
    b"RtlDeleteSecurityObject",
    b"RtlDeleteTimer",
    b"RtlDeleteTimerQueueEx",
    b"RtlDeregisterWaitEx",
    b"RtlDeriveCapabilitySidsFromName",
    b"RtlDestroyEnvironment",
    b"RtlDestroyProcessParameters",
    b"RtlDoesFileExists_U",
    b"RtlDosSearchPath_U",
    b"RtlDowncaseUnicodeChar",
    b"RtlDuplicateUnicodeString",
    b"RtlEqualPrefixSid",
    b"RtlEqualSid",
    b"RtlExpandEnvironmentStrings_U",
    b"RtlFindActivationContextSectionGuid",
    b"RtlFindClearBitsAndSet",
    b"RtlFindMessage",
    b"RtlFirstFreeAce",
    b"RtlFlsAlloc",
    b"RtlFlsFree",
    b"RtlFlsGetValue",
    b"RtlFlsSetValue",
    b"RtlFormatMessage",
    b"RtlFormatMessageEx",
    b"RtlFreeThreadActivationContextStack",
    b"RtlFreeActivationContextStack",
    b"RtlFreeAnsiString",
    b"RtlFreeSid",
    b"RtlFreeUserStack",
    b"RtlGetActiveActivationContext",
    b"RtlGetCurrentDirectory_U",
    b"RtlGetCurrentPeb",
    b"RtlGetDaclSecurityDescriptor",
    b"RtlGetEnabledExtendedFeatures",
    b"RtlGetExePath",
    b"RtlGetExtendedContextLength2",
    b"RtlGetExtendedFeaturesMask",
    b"RtlGetFullPathName_U",
    b"RtlGetGroupSecurityDescriptor",
    b"RtlGetLocaleFileMappingAddress",
    b"RtlGetNativeSystemInformation",
    b"RtlGetOwnerSecurityDescriptor",
    b"RtlGetProductInfo",
    b"RtlGetProcessPreferredUILanguages",
    b"RtlGetSaclSecurityDescriptor",
    b"RtlGetSearchPath",
    b"RtlGetSystemPreferredUILanguages",
    b"RtlGetSystemTimePrecise",
    b"RtlGetThreadErrorMode",
    b"RtlGetThreadPreferredUILanguages",
    b"RtlGetUserPreferredUILanguages",
    b"RtlGetVersion",
    b"RtlIdentifierAuthoritySid",
    b"RtlIdnToAscii",
    b"RtlIdnToNameprepUnicode",
    b"RtlIdnToUnicode",
    b"RtlImpersonateSelf",
    b"RtlInitBarrier",
    b"RtlInitCodePageTable",
    b"RtlInitializeExtendedContext2",
    b"RtlInitializeSid",
    b"RtlIsDosDeviceName_U",
    b"RtlIsNormalizedString",
    b"RtlIsProcessorFeaturePresent",
    b"RtlLengthRequiredSid",
    b"RtlLengthSid",
    b"RtlLocalTimeToSystemTime",
    b"RtlLocateExtendedFeature",
    b"RtlMapGenericMask",
    b"RtlNewSecurityObject",
    b"RtlNewSecurityObjectEx",
    b"RtlNewSecurityObjectWithMultipleInheritance",
    b"RtlNormalizeProcessParams",
    b"RtlNormalizeString",
    b"RtlOpenCurrentUser",
    b"RtlProcessFlsData",
    b"RtlQueryActivationContextApplicationSettings",
    b"RtlQueryDynamicTimeZoneInformation",
    b"RtlQueryEnvironmentVariable_U",
    b"RtlQueryHeapInformation",
    b"RtlQueryInformationActivationContext",
    b"RtlQueryTimeZoneInformation",
    b"RtlQueueWorkItem",
    b"RtlRaiseException",
    b"RtlRaiseStatus",
    b"RtlReleasePath",
    b"RtlRunOnceBeginInitialize",
    b"RtlRunOnceComplete",
    b"RtlRunOnceExecuteOnce",
    b"RtlSetControlSecurityDescriptor",
    b"RtlSetCurrentDirectory_U",
    b"RtlSetCurrentEnvironment",
    b"RtlSetDaclSecurityDescriptor",
    b"RtlSetEnvironmentVariable",
    b"RtlSetExtendedFeaturesMask",
    b"RtlSetGroupSecurityDescriptor",
    b"RtlSetOwnerSecurityDescriptor",
    b"RtlSetHeapInformation",
    b"RtlSetProcessPreferredUILanguages",
    b"RtlSetSaclSecurityDescriptor",
    b"RtlSetThreadErrorMode",
    b"RtlSetThreadPreferredUILanguages",
    b"RtlSetTimeZoneInformation",
    b"RtlSleepConditionVariableCS",
    b"RtlSleepConditionVariableSRW",
    b"RtlSubAuthorityCountSid",
    b"RtlSubAuthoritySid",
    b"RtlSystemTimeToLocalTime",
    b"RtlUTF8ToUnicodeN",
    b"RtlUnicodeToUTF8N",
    b"RtlUpdateTimer",
    b"RtlValidAcl",
    b"RtlValidSecurityDescriptor",
    b"RtlValidSid",
    b"RtlValidateHeap",
    b"RtlWaitOnAddress",
    b"RtlWakeAddressAll",
    b"RtlWakeAddressSingle",
    b"RtlWalkHeap",
    b"RtlWow64EnableFsRedirection",
    b"RtlWow64EnableFsRedirectionEx",
    b"RtlWow64GetProcessMachines",
    b"RtlWow64GetThreadContext",
    b"RtlWow64SetThreadContext",
    b"RtlZombifyActivationContext",
    b"TpAllocCleanupGroup",
    b"TpAllocIoCompletion",
    b"TpAllocPool",
    b"TpAllocTimer",
    b"TpAllocWait",
    b"TpAllocWork",
    b"TpCallbackMayRunLong",
    b"TpQueryPoolStackInformation",
    b"TpSetPoolStackInformation",
    b"TpSimpleTryPost",
    b"_strnicmp",
    b"_vsnwprintf",
    b"isalnum",
    b"iswalnum",
    b"isxdigit",
    b"memcmp",
    b"strcmp",
    b"strncmp",
    b"strtol",
    b"towupper",
    b"wcscspn",
    b"wcsnlen",
    b"wcspbrk",
    b"wcsspn",
    b"wcsstr",
    b"wcstol",
    b"LdrGetDllHandle",
    b"RtlFindExportedRoutineByName",
    b"NtTestAlert", b"NtContinue", b"NtMakePermanentObject", b"RtlDeNormalizeProcessParams",
];
const WINE_SYSCALL_DISPATCHER: &[u8] = b"__wine_syscall_dispatcher";
fn runtime_stub_bytes(index: usize) -> usize {
    if index == 505 { pe::nt_stub::X64_ZERO_ARG_STUB_BYTES }
    else if matches!(index, 6 | 88 | 242 | 435 | 436 | 437 | 483 | 507) { pe::nt_stub::X64_UNARY_STUB_BYTES } else { pe::nt_stub::X64_SIX_ARG_STUB_BYTES }
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PeEntryState {
    pub rip: UserVirtAddr,
    pub rsp: UserVirtAddr,
    pub gs_base: UserVirtAddr,
    pub personality: ExecutionPersonality,
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExecutionPersonality { Linux, Nt }
#[derive(Debug)]
pub struct PeProcess {
    pub image: PeLoadedImage,
    pub environment: process_env::NtProcessEnvironment,
    pub entry: PeEntryState,
    pub initializers: alloc::vec::Vec<PeModuleInitializer>,
    pub initializer_trampoline: Option<pe_init::PeInitTrampoline>,
}
/// One dependency DLL initializer the runtime must call before application startup.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PeInitializerKind { TlsCallback, DllEntry }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PeModuleInitializer { pub base: u64, pub entry: UserVirtAddr, pub kind: PeInitializerKind }

struct PeImageTransaction<'a> {
    as_: &'a AddressSpace,
    base: UserVirtAddr,
    bytes: usize,
    committed: bool,
}

impl PeImageTransaction<'_> {
    fn new(as_: &AddressSpace, base: UserVirtAddr, bytes: usize) -> PeImageTransaction<'_> {
        PeImageTransaction { as_, base, bytes, committed: false }
    }
    fn commit(&mut self) { self.committed = true; }
}

impl Drop for PeImageTransaction<'_> {
    fn drop(&mut self) {
        if !self.committed { let _ = self.as_.munmap(self.base, self.bytes); }
    }
}

fn executable_entry(as_: &AddressSpace, entry: UserVirtAddr) -> bool {
    as_.find_vma(entry).is_some_and(|vma| vma.prot.contains(VmaProt::EXEC))
}

pub trait ImportResolver {
    fn resolve(&self, dll: &[u8], import: &pe::ImportThunk<'_>) -> Result<u64, pe::Error>;
}
pub struct PeExportModule<'a> {
    pub name: &'a [u8],
    pub image: pe::Image<'a>,
    pub base: u64,
}
pub struct PeExportResolver<'a> {
    pub modules: &'a [PeExportModule<'a>],
}
pub struct PeExportRef<'m, 'b> {
    pub name: &'b [u8],
    pub image: &'m pe::Image<'b>,
    pub base: u64,
}
pub struct PeGraphResolver<'m, 'b, R> {
    pub modules: &'m [PeExportRef<'m, 'b>],
    pub fallback: &'m R,
}
impl ImportResolver for PeExportResolver<'_> {
    fn resolve(&self, dll: &[u8], import: &pe::ImportThunk<'_>) -> Result<u64, pe::Error> {
        let module = self.modules.iter().find(|module| ascii_eq_ignore_case(module.name, dll)).ok_or(pe::Error::Unsupported)?;
        let rva = module.image.executable_export_rva(import)?.ok_or(pe::Error::Unsupported)?;
        module.base.checked_add(rva as u64).ok_or(pe::Error::Einval)
    }
}
impl<R: ImportResolver> ImportResolver for PeGraphResolver<'_, '_, R> {
    fn resolve(&self, dll: &[u8], import: &pe::ImportThunk<'_>) -> Result<u64, pe::Error> {
        self.resolve_graph(dll, import, 0)
    }
}
impl<'m, 'b, R: ImportResolver> PeGraphResolver<'m, 'b, R> {
    fn resolve_graph(&self, dll: &[u8], import: &pe::ImportThunk<'_>, depth: u8) -> Result<u64, pe::Error> {
        if depth >= 16 { return Err(pe::Error::Unsupported); }
        if ascii_eq_ignore_case(dll, b"ntdll.dll") {
            if let Ok(address) = self.fallback.resolve(dll, import) { return Ok(address); }
        }
        if let Some(target) = pe::apiset::target(dll) {
            return self.resolve_graph(target, import, depth + 1);
        }
        if let Some(module) = self.modules.iter().find(|module| ascii_eq_ignore_case(module.name, dll)) {
            let target = module.image.export_target(import)?.ok_or(pe::Error::Unsupported)?;
            return match target {
                pe::ExportTarget::Rva(_) => module.image.executable_export_rva(import)?.and_then(|rva| module.base.checked_add(rva as u64)).ok_or(pe::Error::Unsupported),
                pe::ExportTarget::Forwarder(forwarder) => {
                    let dot = forwarder.iter().position(|byte| *byte == b'.').ok_or(pe::Error::Einval)?;
                    if dot == 0 || dot + 1 >= forwarder.len() { return Err(pe::Error::Einval); }
                    let mut forwarded_dll = [0u8; 256];
                    let mut dll_len = dot.min(forwarded_dll.len());
                    forwarded_dll[..dll_len].copy_from_slice(&forwarder[..dll_len]);
                    if dll_len < 4 || !ascii_eq_ignore_case(&forwarded_dll[dll_len - 4..dll_len], b".dll") {
                        if dll_len + 4 > forwarded_dll.len() { return Err(pe::Error::Einval); }
                        forwarded_dll[dll_len..dll_len + 4].copy_from_slice(b".dll"); dll_len += 4;
                    }
                    let symbol = &forwarder[dot + 1..];
                    let forwarded = if symbol.first() == Some(&b'#') {
                        let mut ordinal = 0u32;
                        for byte in &symbol[1..] { if !byte.is_ascii_digit() { return Err(pe::Error::Einval); } ordinal = ordinal.checked_mul(10).and_then(|n| n.checked_add((byte - b'0') as u32)).ok_or(pe::Error::Einval)?; }
                        pe::ImportThunk::Ordinal(u16::try_from(ordinal).map_err(|_| pe::Error::Einval)?)
                    } else { pe::ImportThunk::Name { hint: 0, name: symbol } };
                    self.resolve_graph(&forwarded_dll[..dll_len], &forwarded, depth + 1)
                }
            };
        }
        self.fallback.resolve(dll, import)
    }
}
impl ImportResolver for NtRuntime {
    fn resolve(&self, dll: &[u8], import: &pe::ImportThunk<'_>) -> Result<u64, pe::Error> {
        if !ascii_eq_ignore_case(dll, b"ntdll.dll") { return Err(pe::Error::Unsupported); }
        let pe::ImportThunk::Name { name, .. } = import else { return Err(pe::Error::Unsupported); };
        for (index, export) in NTDLL_EXPORTS.iter().enumerate() {
            if *name == *export { return Ok(self.addresses[index]); }
        }
        Err(pe::Error::Unsupported)
    }
}

/// Resolve one export from the kernel-provided synthetic ntdll page.
/// The page is executable stubs rather than a PE image, so its export table
/// is owned by this runtime catalog instead of being read from user memory.
pub fn resolve_nt_runtime_export(base: u64, name: &[u8]) -> Option<u64> {
    let mut offset = 0u64;
    for (index, export) in NTDLL_EXPORTS.iter().enumerate() {
        if *export == name { return base.checked_add(offset); }
        offset = offset.checked_add(runtime_stub_bytes(index) as u64)?;
    }
    None
}

/// Resolve the private synchronous window-procedure continuation.
pub fn resolve_nt_runtime_wndproc_continuation(base: u64) -> Option<u64> {
    let mut offset = 0u64;
    for (index, _) in NTDLL_EXPORTS.iter().enumerate() { offset = offset.checked_add(runtime_stub_bytes(index) as u64)?; }
    offset = offset.checked_add(pe::nt_stub::encode_x64_run_once_continuation(syscall::nt::NtService::RtlRunOnceComplete.entry()).len() as u64)?;
    base.checked_add(offset)
}

/// Resolve the private native APC return leg in the synthetic ntdll page.
pub fn resolve_nt_runtime_apc_continuation(base: u64) -> Option<u64> {
    let mut offset = 0u64;
    for (index, _) in NTDLL_EXPORTS.iter().enumerate() { offset = offset.checked_add(runtime_stub_bytes(index) as u64)?; }
    offset = offset.checked_add(pe::nt_stub::encode_x64_run_once_continuation(syscall::nt::NtService::RtlRunOnceComplete.entry()).len() as u64)?;
    offset = offset.checked_add(pe::nt_stub::encode_x64_wndproc_continuation(syscall::nt::NtService::CallbackReturn.entry()).len() as u64)?;
    base.checked_add(offset)
}

/// Resolve the address of a runtime-owned exported entry.
/// # C: O(1)
pub fn resolve_nt_runtime_data_export(base: u64, name: &[u8]) -> Option<u64> {
    if name != WINE_SYSCALL_DISPATCHER && name != b"__wine_unix_call_dispatcher" && name != b"__wine_unixlib_handle" { return None; }
    let mut offset = 0u64;
    for (index, _) in NTDLL_EXPORTS.iter().enumerate() { offset = offset.checked_add(runtime_stub_bytes(index) as u64)?; }
    let continuation = pe::nt_stub::encode_x64_run_once_continuation(syscall::nt::NtService::RtlRunOnceComplete.entry());
    let wndproc_continuation = pe::nt_stub::encode_x64_wndproc_continuation(syscall::nt::NtService::CallbackReturn.entry());
    let apc_continuation = pe::nt_stub::encode_x64_apc_continuation();
    let relay = pe::nt_stub::X64_RELAY_STUB_BYTES as u64;
    let relay_offset = offset.checked_add(continuation.len() as u64)?.checked_add(wndproc_continuation.len() as u64)?
        .checked_add(apc_continuation.len() as u64)?.checked_add(8)?;
    let dispatcher_offset = relay_offset.checked_add(relay)?;
    let unix_dispatcher_offset = dispatcher_offset.checked_add(pe::nt_stub::encode_x64_wine_dispatcher_stub(syscall::nt::NtService::WineSyscall.entry()).len() as u64)?;
    let handle_offset = unix_dispatcher_offset.checked_add(pe::nt_stub::encode_x64_unix_call_dispatcher_stub(syscall::nt::NtService::WineUnixCall.entry()).len() as u64)?;
    let target = if name == WINE_SYSCALL_DISPATCHER { dispatcher_offset } else if name == b"__wine_unix_call_dispatcher" { unix_dispatcher_offset } else { handle_offset };
    base.checked_add(target)
}
pub fn map_nt_runtime(as_: &AddressSpace) -> Result<NtRuntime, pe::Error> {
    let page = hal::PAGE_SIZE_BYTES as usize;
    let continuation = pe::nt_stub::encode_x64_run_once_continuation(syscall::nt::NtService::RtlRunOnceComplete.entry());
    let stub_bytes: usize = NTDLL_EXPORTS.iter().enumerate().map(|(index, _)| runtime_stub_bytes(index)).sum();
    let wine_dispatcher = pe::nt_stub::encode_x64_wine_dispatcher_stub(syscall::nt::NtService::WineSyscall.entry());
    let wine_unix_dispatcher = pe::nt_stub::encode_x64_unix_call_dispatcher_stub(syscall::nt::NtService::WineUnixCall.entry());
    let wndproc_continuation = pe::nt_stub::encode_x64_wndproc_continuation(syscall::nt::NtService::CallbackReturn.entry());
    let apc_continuation = pe::nt_stub::encode_x64_apc_continuation();
    let code_bytes = stub_bytes + continuation.len() + wndproc_continuation.len() + apc_continuation.len() + 8 + pe::nt_stub::X64_RELAY_STUB_BYTES + wine_dispatcher.len() + wine_unix_dispatcher.len() + 8;
    let mapped_bytes = (code_bytes + page - 1) / page * page;
    let mut code = alloc::vec![0u8; mapped_bytes];
    let mut addresses = [0u64; 509];
    let mut offset = 0usize;
    for index in 0..NTDLL_EXPORTS.len() {
        // Keep the debug exports tied to their actual catalog indexes. This
        // block predates the generated selector table and is the one place
        // where the handwritten table differs from the export array.
        let selector = if index == 185 { syscall::nt::NtService::Wcstoul }
        else if index == 186 { syscall::nt::NtService::WineDbgHeader }
        else if index == 187 { syscall::nt::NtService::WineDbgOutput }
        else if index == 188 { syscall::nt::NtService::WineDbgStrdup }
        else { match index {
            0 => syscall::nt::NtService::AllocateVirtualMemory,
            1 => syscall::nt::NtService::FreeVirtualMemory,
            2 => syscall::nt::NtService::ProtectVirtualMemory,
            3 => syscall::nt::NtService::QueryVirtualMemory,
            4 => syscall::nt::NtService::TerminateProcess,
            5 => syscall::nt::NtService::CreateEvent,
            6 => syscall::nt::NtService::Close,
            7 => syscall::nt::NtService::SetEvent,
            8 => syscall::nt::NtService::ResetEvent,
            9 => syscall::nt::NtService::WaitForSingleObject,
            10 => syscall::nt::NtService::CreateFile,
            11 => syscall::nt::NtService::OpenFile,
            12 => syscall::nt::NtService::ReadFile,
            13 => syscall::nt::NtService::WriteFile,
            14 => syscall::nt::NtService::QueryInformationFile,
            15 => syscall::nt::NtService::SetInformationFile,
            16 => syscall::nt::NtService::QueryDirectoryFile,
            17 => syscall::nt::NtService::WaitForMultipleObjects,
            18 => syscall::nt::NtService::CreateSection,
            19 => syscall::nt::NtService::MapViewOfSection,
            20 => syscall::nt::NtService::UnmapViewOfSection,
            21 => syscall::nt::NtService::QueryInformationProcess,
            22 => syscall::nt::NtService::CreateThreadEx,
            23 => syscall::nt::NtService::TerminateThread,
            24 => syscall::nt::NtService::QueryInformationThread,
            25 => syscall::nt::NtService::AllocateHeap,
            26 => syscall::nt::NtService::FreeHeap,
            27 | 28 => syscall::nt::NtService::DefaultWindowProc,
            29 => syscall::nt::NtService::ReallocateHeap,
            30 => syscall::nt::NtService::ResolveDelayLoadedApi,
            31 => syscall::nt::NtService::RtlUnwind,
            32 => syscall::nt::NtService::CreateSemaphore,
            33 => syscall::nt::NtService::ReleaseSemaphore,
            34 => syscall::nt::NtService::CreateMutant,
            35 => syscall::nt::NtService::ReleaseMutant,
            36 => syscall::nt::NtService::QueryMutant,
            37 => syscall::nt::NtService::LockFile,
            38 => syscall::nt::NtService::UnlockFile,
            39 => syscall::nt::NtService::DuplicateObject,
            40 => syscall::nt::NtService::CreateTimer,
            41 => syscall::nt::NtService::SetTimer,
            42 => syscall::nt::NtService::CancelTimer,
            43 => syscall::nt::NtService::CreateIoCompletion,
            44 => syscall::nt::NtService::SetIoCompletion,
            45 => syscall::nt::NtService::RemoveIoCompletion,
            46 => syscall::nt::NtService::SignalAndWait,
            47 => syscall::nt::NtService::OpenProcessToken,
            48 => syscall::nt::NtService::OpenThreadToken,
            49 => syscall::nt::NtService::QueryToken,
            50 => syscall::nt::NtService::RtlInitUnicodeString,
            51 => syscall::nt::NtService::RtlInitUnicodeStringEx,
            52 => syscall::nt::NtService::QueryObject,
            53 => syscall::nt::NtService::RtlInitAnsiString,
            54 => syscall::nt::NtService::RtlInitAnsiStringEx,
            55 => syscall::nt::NtService::QuerySecurityObject,
            56 => syscall::nt::NtService::RtlQueryPerformanceCounter,
            57 => syscall::nt::NtService::RtlQueryPerformanceFrequency,
            58 => syscall::nt::NtService::RenameKey,
            59 => syscall::nt::NtService::SetSecurityObject,
            60 => syscall::nt::NtService::RtlAddAccessAllowedAce,
            61 => syscall::nt::NtService::RtlAddAccessAllowedAceEx,
            62 => syscall::nt::NtService::RtlAddAccessDeniedAce,
            63 => syscall::nt::NtService::RtlAddAccessDeniedAceEx,
            64 => syscall::nt::NtService::RtlAddAce,
            65 => syscall::nt::NtService::RtlAddAuditAccessAce,
            66 => syscall::nt::NtService::RtlAddAuditAccessAceEx,
            67 => syscall::nt::NtService::RtlCreateAcl,
            68 => syscall::nt::NtService::RtlCreateSecurityDescriptor,
            69 => syscall::nt::NtService::RtlCreateUnicodeStringFromAsciiz,
            70 => syscall::nt::NtService::RtlDosPathNameToNtPathNameU,
            71 => syscall::nt::NtService::RtlFreeUnicodeString,
            72 => syscall::nt::NtService::RtlGetAce,
            73 => syscall::nt::NtService::RtlGetControlSecurityDescriptor,
            74 => syscall::nt::NtService::RtlIsTextUnicode,
            75 => syscall::nt::NtService::RtlLengthSecurityDescriptor,
            76 => syscall::nt::NtService::RtlMakeSelfRelativeSD,
            77 => syscall::nt::NtService::RtlNtStatusToDosError,
            78 => syscall::nt::NtService::RtlQueryInformationAcl,
            79 => syscall::nt::NtService::RtlSelfRelativeToAbsoluteSD,
            80 => syscall::nt::NtService::RtlUniform,
            81 => syscall::nt::NtService::RtlDeleteCriticalSection,
            82 => syscall::nt::NtService::RtlEnterCriticalSection,
            83 => syscall::nt::NtService::RtlLeaveCriticalSection,
            84 => syscall::nt::NtService::Vsnprintf,
            85 => syscall::nt::NtService::RtlSizeHeap,
            86 => syscall::nt::NtService::RtlExitUserThread,
            87 => syscall::nt::NtService::RtlQueryUnbiasedInterruptTime,
            88 => syscall::nt::NtService::DbgUiGetThreadDebugObject,
            89 => syscall::nt::NtService::DbgUiIssueRemoteBreakin,
            90 => syscall::nt::NtService::LdrGetDllDirectory,
            91 => syscall::nt::NtService::LdrGetProcedureAddress,
            92 => syscall::nt::NtService::LdrSetDllDirectory,
            93 => syscall::nt::NtService::AddAtom,
            94 => syscall::nt::NtService::AssignProcessToJobObject,
            95 => syscall::nt::NtService::CreateJobObject,
            96 => syscall::nt::NtService::CreateMailslotFile,
            97 => syscall::nt::NtService::DeleteAtom,
            98 => syscall::nt::NtService::DeviceIoControlFile,
            99 => syscall::nt::NtService::FindAtom,
            100 => syscall::nt::NtService::FsControlFile,
            101 => syscall::nt::NtService::OpenJobObject,
            102 => syscall::nt::NtService::PowerInformation,
            103 => syscall::nt::NtService::QueryInformationAtom,
            104 => syscall::nt::NtService::QueryInformationJobObject,
            105 => syscall::nt::NtService::QuerySection,
            106 => syscall::nt::NtService::QuerySystemInformation,
            107 => syscall::nt::NtService::QuerySystemTime,
            108 => syscall::nt::NtService::SetInformationDebugObject,
            109 => syscall::nt::NtService::SetInformationJobObject,
            110 => syscall::nt::NtService::SetInformationProcess,
            111 => syscall::nt::NtService::SetInformationThread,
            112 => syscall::nt::NtService::SetThreadExecutionState, 113 => syscall::nt::NtService::TerminateJobObject,
            114 => syscall::nt::NtService::RtlAcquirePebLock, 115 => syscall::nt::NtService::RtlReleasePebLock, 116 => syscall::nt::NtService::RtlAddAtomToAtomTable, 117 => syscall::nt::NtService::RtlAnsiStringToUnicodeString, 118 => syscall::nt::NtService::RtlCaptureContext, 119 => syscall::nt::NtService::RtlCharToInteger, 120 => syscall::nt::NtService::RtlCreateAtomTable, 121 => syscall::nt::NtService::RtlCreateHeap, 122 => syscall::nt::NtService::RtlCreateUnicodeString, 123 => syscall::nt::NtService::RtlDeleteAtomFromAtomTable, 124 => syscall::nt::NtService::RtlDeregisterWait, 125 => syscall::nt::NtService::RtlDestroyAtomTable, 126 => syscall::nt::NtService::RtlDestroyHeap, 127 => syscall::nt::NtService::RtlDetermineDosPathNameTypeU, 128 => syscall::nt::NtService::RtlDosPathNameToNtPathNameUWithStatus, 129 => syscall::nt::NtService::RtlExitUserProcess, 130 => syscall::nt::NtService::RtlGetProcessHeaps, 131 => syscall::nt::NtService::RtlGetUserInfoHeap, 132 => syscall::nt::NtService::RtlImageNtHeader, 133 => syscall::nt::NtService::RtlInitializeCriticalSection, 134 => syscall::nt::NtService::RtlInitializeCriticalSectionAndSpinCount, 135 => syscall::nt::NtService::RtlInitializeCriticalSectionEx, 136 => syscall::nt::NtService::RtlIsNameLegalDOS8Dot3, 137 => syscall::nt::NtService::RtlLockHeap, 138 => syscall::nt::NtService::RtlUnlockHeap, 139 => syscall::nt::NtService::RtlLookupAtomInAtomTable, 140 => syscall::nt::NtService::RtlOemStringToUnicodeString, 141 => syscall::nt::NtService::RtlQueryAtomInAtomTable, 142 => syscall::nt::NtService::RtlRegisterWait, 143 => syscall::nt::NtService::RtlRestoreContext, 144 => syscall::nt::NtService::RtlSetIoCompletionCallback, 145 => syscall::nt::NtService::RtlGetLastWin32Error, 146 => syscall::nt::NtService::RtlRestoreLastWin32Error, 147 => syscall::nt::NtService::RtlSetLastWin32Error, 148 => syscall::nt::NtService::RtlSetSearchPathMode, 149 => syscall::nt::NtService::RtlSetUnhandledExceptionFilter, 150 => syscall::nt::NtService::RtlSetUserValueHeap, 151 => syscall::nt::NtService::RtlTimeFieldsToTime, 152 => syscall::nt::NtService::RtlTimeToTimeFields, 153 => syscall::nt::NtService::RtlUnicodeStringToAnsiSize, 154 => syscall::nt::NtService::RtlUnicodeStringToAnsiString, 155 => syscall::nt::NtService::RtlUnicodeStringToInteger, 156 => syscall::nt::NtService::RtlUnicodeStringToOemSize, 157 => syscall::nt::NtService::RtlUnicodeStringToOemString, 158 => syscall::nt::NtService::RtlUnicodeToMultiByteN,
            159 => syscall::nt::NtService::RtlUnicodeToMultiByteSize,
            160 => syscall::nt::NtService::RtlUnicodeToOemN,
            161 => syscall::nt::NtService::RtlUpcaseUnicodeString,
            162 => syscall::nt::NtService::RtlUpperChar,
            163 => syscall::nt::NtService::Wcsicmp,
            164 => syscall::nt::NtService::Wcsnicmp,
            165 => syscall::nt::NtService::Isalpha,
            166 => syscall::nt::NtService::Islower,
            167 => syscall::nt::NtService::Memcpy,
            168 => syscall::nt::NtService::Memmove,
            169 => syscall::nt::NtService::Memset,
            170 => syscall::nt::NtService::Strcat,
            171 => syscall::nt::NtService::Strchr,
            172 => syscall::nt::NtService::Strcpy,
            173 => syscall::nt::NtService::Strlen,
            174 => syscall::nt::NtService::Strpbrk,
            175 => syscall::nt::NtService::Strrchr,
            176 => syscall::nt::NtService::Tolower,
            177 => syscall::nt::NtService::Wcscat,
            178 => syscall::nt::NtService::Wcschr,
            179 => syscall::nt::NtService::Wcscmp,
            180 => syscall::nt::NtService::Wcscpy,
            181 => syscall::nt::NtService::Wcslen,
            182 => syscall::nt::NtService::Wcsncmp,
            183 => syscall::nt::NtService::Wcsrchr,
            184 => syscall::nt::NtService::Wcstoul,
            185 => syscall::nt::NtService::WineDbgHeader,
            186 => syscall::nt::NtService::WineDbgOutput,
            187 => syscall::nt::NtService::WineDbgStrdup,
            188 => syscall::nt::NtService::RtlGUIDFromString,
            189 => syscall::nt::NtService::RtlRandom,
            190 => syscall::nt::NtService::WineGetHostVersion,
            191 => syscall::nt::NtService::RtlInterlockedFlushSList,
            192 => syscall::nt::NtService::RtlInterlockedPushEntrySList,
            193 => syscall::nt::NtService::RtlTryEnterCriticalSection,
            194 => syscall::nt::NtService::RtlAreBitsClear,
            195 => syscall::nt::NtService::RtlAreBitsSet,
            196 => syscall::nt::NtService::RtlInitializeBitMap,
            197 => syscall::nt::NtService::RtlLookupFunctionEntry,
            198 => syscall::nt::NtService::RtlPcToFileHeader,
            199 => syscall::nt::NtService::RtlSetBits,
            200 => syscall::nt::NtService::RtlTimeToSecondsSince1970,
            201 => syscall::nt::NtService::RtlUnwindEx,
            202 => syscall::nt::NtService::Setjmp,
            203 => syscall::nt::NtService::Setjmpex,
            204 => syscall::nt::NtService::Longjmp,
            205 => syscall::nt::NtService::WineDbgGetChannelFlags,
            206 => syscall::nt::NtService::LdrGetDllFullName,
            207 => syscall::nt::NtService::LdrLoadDll,
            208 => syscall::nt::NtService::LdrQueryImageFileExecutionOptions,
            209 => syscall::nt::NtService::CallbackReturn,
            210 => syscall::nt::NtService::OpenDirectoryObject,
            211 => syscall::nt::NtService::RtlFindActivationContextSectionString,
            212 => syscall::nt::NtService::RtlImageDirectoryEntryToData,
            213 => syscall::nt::NtService::RtlImageRvaToVa,
            214 => syscall::nt::NtService::RtlInitializeNtUserPfn,
            215 => syscall::nt::NtService::RtlMultiByteToUnicodeN,
            216 => syscall::nt::NtService::RtlMultiByteToUnicodeSize,
            217 => syscall::nt::NtService::RtlRetrieveNtUserPfn,
            218 => syscall::nt::NtService::RtlResetNtUserPfn,
            219 => syscall::nt::NtService::ApiSetQueryApiSetPresenceEx,
            221 => syscall::nt::NtService::DbgUiConnectToDbg,
            222 => syscall::nt::NtService::DbgUiContinue,
            223 => syscall::nt::NtService::DbgUiRemoteBreakin,
            224 => syscall::nt::NtService::DbgUiStopDebugging,
            225 => syscall::nt::NtService::DbgUiWaitStateChange,
            226 => syscall::nt::NtService::DbgUiConvertStateChangeStructure,
            227 => syscall::nt::NtService::DbgUiDebugActiveProcess,
            228 => syscall::nt::NtService::LdrAccessResource,
            229 => syscall::nt::NtService::LdrAddDllDirectory,
            230 => syscall::nt::NtService::LdrRemoveDllDirectory,
            231 => syscall::nt::NtService::LdrAddRefDll,
            232 => syscall::nt::NtService::LdrDisableThreadCalloutsForDll,
            233 => syscall::nt::NtService::LdrFindResourceDirectory,
            234 => syscall::nt::NtService::LdrFindResource,
            235 => syscall::nt::NtService::LdrGetDllHandleEx,
            236 => syscall::nt::NtService::LdrGetDllPath,
            237 => syscall::nt::NtService::LdrSetDefaultDllDirectories,
            238 => syscall::nt::NtService::LdrUnloadDll,
            239 => syscall::nt::NtService::NtAccessCheck,
            240 => syscall::nt::NtService::NtAdjustGroupsToken,
            241 => syscall::nt::NtService::NtAdjustPrivilegesToken,
            242 => syscall::nt::NtService::NtAllocateLocallyUniqueId,
            243 => syscall::nt::NtService::NtAllocateVirtualMemoryEx,
            244 => syscall::nt::NtService::NtCancelIoFile,
            245 => syscall::nt::NtService::NtCancelIoFileEx,
            246 => syscall::nt::NtService::NtCancelSynchronousIoFile,
            247 => syscall::nt::NtService::NtCompareObjects,
            248 => syscall::nt::NtService::NtConvertBetweenAuxiliaryCounterAndPerformanceCounter,
            249 => syscall::nt::NtService::CreateKey,
            250 => syscall::nt::NtService::NtCreateNamedPipeFile,
            251 => syscall::nt::NtService::NtCreateSectionEx,
            252 => syscall::nt::NtService::NtCreateSymbolicLinkObject,
            253 => syscall::nt::NtService::NtCreateUserProcess,
            254 => syscall::nt::NtService::NtDelayExecution,
            255 => syscall::nt::NtService::NtDeleteKey,
            256 => syscall::nt::NtService::NtDeleteValueKey,
            257 => syscall::nt::NtService::NtDuplicateToken,
            258 => syscall::nt::NtService::NtEnumerateKey,
            259 => syscall::nt::NtService::NtEnumerateValueKey,
            260 => syscall::nt::NtService::NtFilterToken,
            261 => syscall::nt::NtService::NtFlushBuffersFile,
            262 => syscall::nt::NtService::NtFlushInstructionCache,
            263 => syscall::nt::NtService::NtFlushKey,
            264 => syscall::nt::NtService::NtFlushVirtualMemory,
            265 => syscall::nt::NtService::NtGetContextThread,
            266 => syscall::nt::NtService::NtGetNlsSectionPtr,
            267 => syscall::nt::NtService::NtGetTickCount,
            268 => syscall::nt::NtService::NtGetWriteWatch,
            269 => syscall::nt::NtService::NtImpersonateAnonymousToken,
            270 => syscall::nt::NtService::NtIsProcessInJob,
            271 => syscall::nt::NtService::NtLoadKey,
            272 => syscall::nt::NtService::NtLockVirtualMemory,
            273 => syscall::nt::NtService::NtMakeTemporaryObject,
            274 => syscall::nt::NtService::NtMapViewOfSectionEx,
            275 => syscall::nt::NtService::NtNotifyChangeDirectoryFile,
            276 => syscall::nt::NtService::NtNotifyChangeKey,
            277 => syscall::nt::NtService::NtOpenEvent,
            278 => syscall::nt::NtService::OpenKey,
            279 => syscall::nt::NtService::NtOpenKeyEx,
            280 => syscall::nt::NtService::NtOpenMutant,
            281 => syscall::nt::NtService::NtOpenProcess,
            282 => syscall::nt::NtService::NtOpenSection,
            283 => syscall::nt::NtService::NtOpenSemaphore,
            284 => syscall::nt::NtService::NtOpenSymbolicLinkObject,
            285 => syscall::nt::NtService::NtOpenThread,
            286 => syscall::nt::NtService::NtOpenTimer,
            287 => syscall::nt::NtService::NtPrivilegeCheck,
            288 => syscall::nt::NtService::NtPulseEvent,
            289 => syscall::nt::NtService::NtQueryAttributesFile,
            290 => syscall::nt::NtService::NtQueryDefaultLocale,
            291 => syscall::nt::NtService::NtQueryDefaultUILanguage,
            292 => syscall::nt::NtService::NtQueryDirectoryObject,
            293 => syscall::nt::NtService::NtQueryFullAttributesFile,
            294 => syscall::nt::NtService::NtQueryInstallUILanguage,
            295 => syscall::nt::NtService::NtQueryKey,
            296 => syscall::nt::NtService::NtQueryPerformanceCounter,
            297 => syscall::nt::NtService::NtQuerySymbolicLinkObject,
            298 => syscall::nt::NtService::NtQuerySystemInformationEx,
            299 => syscall::nt::NtService::NtQueryValueKey,
            300 => syscall::nt::NtService::NtQueryVolumeInformationFile,
            301 => syscall::nt::NtService::NtQueueApcThread,
            302 => syscall::nt::NtService::NtQueueApcThreadEx2,
            303 => syscall::nt::NtService::NtRaiseException,
            304 => syscall::nt::NtService::NtReadFileScatter,
            305 => syscall::nt::NtService::NtReadVirtualMemory,
            306 => syscall::nt::NtService::NtRemoveIoCompletionEx,
            307 => syscall::nt::NtService::NtResetWriteWatch,
            308 => syscall::nt::NtService::NtResumeThread,
            309 => syscall::nt::NtService::NtSaveKey,
            310 => syscall::nt::NtService::NtSetContextThread,
            311 => syscall::nt::NtService::NtSetInformationObject,
            312 => syscall::nt::NtService::NtSetInformationToken,
            313 => syscall::nt::NtService::NtSetInformationVirtualMemory,
            314 => syscall::nt::NtService::NtSetSystemInformation,
            315 => syscall::nt::NtService::NtSetSystemTime,
            316 => syscall::nt::NtService::NtSetValueKey,
            317 => syscall::nt::NtService::NtSuspendThread,
            318 => syscall::nt::NtService::NtUnloadKey,
            319 => syscall::nt::NtService::NtUnlockVirtualMemory,
            320 => syscall::nt::NtService::NtUnmapViewOfSectionEx,
            321 => syscall::nt::NtService::NtWriteFileGather,
            322 => syscall::nt::NtService::NtWriteVirtualMemory,
            323 => syscall::nt::NtService::NtYieldExecution,
            324 => syscall::nt::NtService::RtlActivateActivationContext,
            325 => syscall::nt::NtService::RtlActivateActivationContextEx,
            326 => syscall::nt::NtService::RtlAddAccessAllowedObjectAce,
            327 => syscall::nt::NtService::RtlAddAccessDeniedObjectAce,
            328 => syscall::nt::NtService::RtlAddAuditAccessObjectAce,
            329 => syscall::nt::NtService::RtlAddMandatoryAce,
            330 => syscall::nt::NtService::RtlAddRefActivationContext,
            331 => syscall::nt::NtService::RtlAllocateAndInitializeSid,
            332 => syscall::nt::NtService::RtlAreAllAccessesGranted,
            333 => syscall::nt::NtService::RtlAreAnyAccessesGranted,
            334 => syscall::nt::NtService::RtlBarrier,
            335 => syscall::nt::NtService::RtlClearBits,
            336 => syscall::nt::NtService::RtlCompactHeap,
            337 => syscall::nt::NtService::RtlCompareUnicodeStrings,
            338 => syscall::nt::NtService::RtlConvertSidToUnicodeString,
            339 => syscall::nt::NtService::RtlConvertToAutoInheritSecurityObject,
            340 => syscall::nt::NtService::RtlCopyContext,
            341 => syscall::nt::NtService::RtlCopySid,
            342 => syscall::nt::NtService::RtlCreateActivationContext,
            343 => syscall::nt::NtService::RtlCreateEnvironment,
            344 => syscall::nt::NtService::RtlCreateProcessParametersEx,
            345 => syscall::nt::NtService::RtlCreateTimer,
            346 => syscall::nt::NtService::RtlCreateTimerQueue,
            347 => syscall::nt::NtService::RtlCreateUserStack,
            348 => syscall::nt::NtService::RtlDeactivateActivationContext,
            349 => syscall::nt::NtService::RtlReleaseActivationContext,
            350 => syscall::nt::NtService::RtlDeleteAce,
            351 => syscall::nt::NtService::RtlDeleteBarrier,
            352 => syscall::nt::NtService::RtlDeleteSecurityObject,
            353 => syscall::nt::NtService::RtlDeleteTimer,
            354 => syscall::nt::NtService::RtlDeleteTimerQueueEx,
            355 => syscall::nt::NtService::RtlDeregisterWaitEx,
            356 => syscall::nt::NtService::RtlDeriveCapabilitySidsFromName,
            357 => syscall::nt::NtService::RtlDestroyEnvironment,
            358 => syscall::nt::NtService::RtlDestroyProcessParameters,
            359 => syscall::nt::NtService::RtlDoesFileExistsU,
            360 => syscall::nt::NtService::RtlDosSearchPathU,
            361 => syscall::nt::NtService::RtlDowncaseUnicodeChar,
            362 => syscall::nt::NtService::RtlDuplicateUnicodeString,
            363 => syscall::nt::NtService::RtlEqualPrefixSid,
            364 => syscall::nt::NtService::RtlEqualSid,
            365 => syscall::nt::NtService::RtlExpandEnvironmentStringsU,
            366 => syscall::nt::NtService::RtlFindActivationContextSectionGuid,
            367 => syscall::nt::NtService::RtlFindClearBitsAndSet,
            368 => syscall::nt::NtService::RtlFindMessage,
            369 => syscall::nt::NtService::RtlFirstFreeAce,
            370 => syscall::nt::NtService::RtlFlsAlloc,
            371 => syscall::nt::NtService::RtlFlsFree,
            372 => syscall::nt::NtService::RtlFlsGetValue,
            373 => syscall::nt::NtService::RtlFlsSetValue,
            374 => syscall::nt::NtService::RtlFormatMessage,
            375 => syscall::nt::NtService::RtlFormatMessageEx,
            376 => syscall::nt::NtService::RtlFreeThreadActivationContextStack,
            377 => syscall::nt::NtService::RtlFreeActivationContextStack,
            378 => syscall::nt::NtService::RtlFreeAnsiString,
            379 => syscall::nt::NtService::RtlFreeSid,
            380 => syscall::nt::NtService::RtlFreeUserStack,
            381 => syscall::nt::NtService::RtlGetActiveActivationContext,
            382 => syscall::nt::NtService::RtlGetCurrentDirectoryU,
            383 => syscall::nt::NtService::RtlGetCurrentPeb,
            384 => syscall::nt::NtService::RtlGetDaclSecurityDescriptor,
            385 => syscall::nt::NtService::RtlGetEnabledExtendedFeatures,
            386 => syscall::nt::NtService::RtlGetExePath,
            387 => syscall::nt::NtService::RtlGetExtendedContextLength2,
            388 => syscall::nt::NtService::RtlGetExtendedFeaturesMask,
            389 => syscall::nt::NtService::RtlGetFullPathNameU,
            390 => syscall::nt::NtService::RtlGetGroupSecurityDescriptor,
            391 => syscall::nt::NtService::RtlGetLocaleFileMappingAddress,
            392 => syscall::nt::NtService::RtlGetNativeSystemInformation,
            393 => syscall::nt::NtService::RtlGetOwnerSecurityDescriptor,
            394 => syscall::nt::NtService::RtlGetProductInfo,
            395 => syscall::nt::NtService::RtlGetProcessPreferredUILanguages,
            396 => syscall::nt::NtService::RtlGetSaclSecurityDescriptor,
            397 => syscall::nt::NtService::RtlGetSearchPath,
            398 => syscall::nt::NtService::RtlGetSystemPreferredUILanguages,
            399 => syscall::nt::NtService::RtlGetSystemTimePrecise,
            400 => syscall::nt::NtService::RtlGetThreadErrorMode,
            401 => syscall::nt::NtService::RtlGetThreadPreferredUILanguages,
            402 => syscall::nt::NtService::RtlGetUserPreferredUILanguages,
            403 => syscall::nt::NtService::RtlGetVersion,
            404 => syscall::nt::NtService::RtlIdentifierAuthoritySid,
            405 => syscall::nt::NtService::RtlIdnToAscii,
            406 => syscall::nt::NtService::RtlIdnToNameprepUnicode,
            407 => syscall::nt::NtService::RtlIdnToUnicode,
            408 => syscall::nt::NtService::RtlImpersonateSelf,
            409 => syscall::nt::NtService::RtlInitBarrier,
            410 => syscall::nt::NtService::RtlInitCodePageTable,
            411 => syscall::nt::NtService::RtlInitializeExtendedContext2,
            412 => syscall::nt::NtService::RtlInitializeSid,
            413 => syscall::nt::NtService::RtlIsDosDeviceNameU,
            414 => syscall::nt::NtService::RtlIsNormalizedString,
            415 => syscall::nt::NtService::RtlIsProcessorFeaturePresent,
            416 => syscall::nt::NtService::RtlLengthRequiredSid,
            417 => syscall::nt::NtService::RtlLengthSid,
            418 => syscall::nt::NtService::RtlLocalTimeToSystemTime,
            419 => syscall::nt::NtService::RtlLocateExtendedFeature,
            420 => syscall::nt::NtService::RtlMapGenericMask,
            421 => syscall::nt::NtService::RtlNewSecurityObject,
            422 => syscall::nt::NtService::RtlNewSecurityObjectEx,
            423 => syscall::nt::NtService::RtlNewSecurityObjectWithMultipleInheritance,
            424 => syscall::nt::NtService::RtlNormalizeProcessParams,
            425 => syscall::nt::NtService::RtlNormalizeString,
            426 => syscall::nt::NtService::RtlOpenCurrentUser,
            427 => syscall::nt::NtService::RtlProcessFlsData,
            428 => syscall::nt::NtService::RtlQueryActivationContextApplicationSettings,
            429 => syscall::nt::NtService::RtlQueryDynamicTimeZoneInformation,
            430 => syscall::nt::NtService::RtlQueryEnvironmentVariableU,
            431 => syscall::nt::NtService::RtlQueryHeapInformation,
            432 => syscall::nt::NtService::RtlQueryInformationActivationContext,
            433 => syscall::nt::NtService::RtlQueryTimeZoneInformation,
            434 => syscall::nt::NtService::RtlQueueWorkItem,
            435 => syscall::nt::NtService::RtlRaiseException,
            436 => syscall::nt::NtService::RtlRaiseStatus,
            437 => syscall::nt::NtService::RtlReleasePath,
            438 => syscall::nt::NtService::RtlRunOnceBeginInitialize,
            439 => syscall::nt::NtService::RtlRunOnceComplete,
            440 => syscall::nt::NtService::RtlRunOnceExecuteOnce,
            441 => syscall::nt::NtService::RtlSetControlSecurityDescriptor,
            442 => syscall::nt::NtService::RtlSetCurrentDirectoryU,
            443 => syscall::nt::NtService::RtlSetCurrentEnvironment,
            444 => syscall::nt::NtService::RtlSetDaclSecurityDescriptor,
            445 => syscall::nt::NtService::RtlSetEnvironmentVariable,
            446 => syscall::nt::NtService::RtlSetExtendedFeaturesMask,
            447 => syscall::nt::NtService::RtlSetGroupSecurityDescriptor,
            448 => syscall::nt::NtService::RtlSetOwnerSecurityDescriptor,
            449 => syscall::nt::NtService::RtlSetHeapInformation,
            450 => syscall::nt::NtService::RtlSetProcessPreferredUILanguages,
            451 => syscall::nt::NtService::RtlSetSaclSecurityDescriptor,
            452 => syscall::nt::NtService::RtlSetThreadErrorMode,
            453 => syscall::nt::NtService::RtlSetThreadPreferredUILanguages,
            454 => syscall::nt::NtService::RtlSetTimeZoneInformation,
            455 => syscall::nt::NtService::RtlSleepConditionVariableCS,
            456 => syscall::nt::NtService::RtlSleepConditionVariableSRW,
            457 => syscall::nt::NtService::RtlSubAuthorityCountSid,
            458 => syscall::nt::NtService::RtlSubAuthoritySid,
            459 => syscall::nt::NtService::RtlSystemTimeToLocalTime,
            460 => syscall::nt::NtService::RtlUTF8ToUnicodeN,
            461 => syscall::nt::NtService::RtlUnicodeToUTF8N,
            462 => syscall::nt::NtService::RtlUpdateTimer,
            463 => syscall::nt::NtService::RtlValidAcl,
            464 => syscall::nt::NtService::RtlValidSecurityDescriptor,
            465 => syscall::nt::NtService::RtlValidSid,
            466 => syscall::nt::NtService::RtlValidateHeap,
            467 => syscall::nt::NtService::RtlWaitOnAddress,
            468 => syscall::nt::NtService::RtlWakeAddressAll,
            469 => syscall::nt::NtService::RtlWakeAddressSingle,
            470 => syscall::nt::NtService::RtlWalkHeap,
            471 => syscall::nt::NtService::RtlWow64EnableFsRedirection,
            472 => syscall::nt::NtService::RtlWow64EnableFsRedirectionEx,
            473 => syscall::nt::NtService::RtlWow64GetProcessMachines,
            474 => syscall::nt::NtService::RtlWow64GetThreadContext,
            475 => syscall::nt::NtService::RtlWow64SetThreadContext,
            476 => syscall::nt::NtService::RtlZombifyActivationContext,
            477 => syscall::nt::NtService::TpAllocCleanupGroup,
            478 => syscall::nt::NtService::TpAllocIoCompletion,
            479 => syscall::nt::NtService::TpAllocPool,
            480 => syscall::nt::NtService::TpAllocTimer,
            481 => syscall::nt::NtService::TpAllocWait,
            482 => syscall::nt::NtService::TpAllocWork,
            483 => syscall::nt::NtService::TpCallbackMayRunLong,
            484 => syscall::nt::NtService::TpQueryPoolStackInformation,
            485 => syscall::nt::NtService::TpSetPoolStackInformation,
            486 => syscall::nt::NtService::TpSimpleTryPost,
            487 => syscall::nt::NtService::Strnicmp,
            488 => syscall::nt::NtService::Vsnwprintf,
            489 => syscall::nt::NtService::Isalnum,
            490 => syscall::nt::NtService::Iswalnum,
            491 => syscall::nt::NtService::Isxdigit,
            492 => syscall::nt::NtService::Memcmp,
            493 => syscall::nt::NtService::Strcmp,
            494 => syscall::nt::NtService::Strncmp,
            495 => syscall::nt::NtService::Strtol,
            496 => syscall::nt::NtService::Towupper,
            497 => syscall::nt::NtService::Wcscspn,
            498 => syscall::nt::NtService::Wcsnlen,
            499 => syscall::nt::NtService::Wcspbrk,
            500 => syscall::nt::NtService::Wcsspn,
            501 => syscall::nt::NtService::Wcsstr,
            502 => syscall::nt::NtService::Wcstol,
            503 => syscall::nt::NtService::LdrGetDllHandle,
            504 => syscall::nt::NtService::RtlFindExportedRoutineByName,
            505 => syscall::nt::NtService::NtTestAlert,
            506 => syscall::nt::NtService::NtContinue,
            507 => syscall::nt::NtService::NtMakePermanentObject,
            508 => syscall::nt::NtService::RtlDeNormalizeProcessParams,
            _ => syscall::nt::NtService::FreeHeap,
        }};
        let bytes = if index == 505 { pe::nt_stub::encode_x64_zero_arg_stub(selector.entry()).to_vec() }
            else if matches!(index, 6 | 88 | 242 | 435 | 436 | 437 | 483 | 507) { pe::nt_stub::encode_x64_unary_stub(selector.entry()).to_vec() }
            else { pe::nt_stub::encode_x64_six_arg_stub(selector.entry()).to_vec() };
        if offset.checked_add(bytes.len()).filter(|&end| end <= code.len()).is_none() { return Err(pe::Error::Einval); }
        code[offset..offset + bytes.len()].copy_from_slice(&bytes);
        addresses[index] = offset as u64;
        debug_assert_eq!(bytes.len(), runtime_stub_bytes(index));
        offset += bytes.len();
    }
    code[offset..offset + continuation.len()].copy_from_slice(&continuation);
    offset += continuation.len();
    code[offset..offset + wndproc_continuation.len()].copy_from_slice(&wndproc_continuation);
    offset += wndproc_continuation.len();
    code[offset..offset + apc_continuation.len()].copy_from_slice(&apc_continuation);
    let relay_offset = offset + apc_continuation.len() + 8;
    let relay = pe::nt_stub::encode_x64_relay_stub(syscall::nt::NtService::RelayCall.entry());
    code[relay_offset..relay_offset + relay.len()].copy_from_slice(&relay);
    let dispatcher_offset = relay_offset + relay.len();
    code[dispatcher_offset..dispatcher_offset + wine_dispatcher.len()].copy_from_slice(&wine_dispatcher);
    let unix_dispatcher_offset = dispatcher_offset + wine_dispatcher.len();
    code[unix_dispatcher_offset..unix_dispatcher_offset + wine_unix_dispatcher.len()].copy_from_slice(&wine_unix_dispatcher);
    let handle_offset = unix_dispatcher_offset + wine_unix_dispatcher.len();
    code[handle_offset..handle_offset + 8].copy_from_slice(&syscall::nt::WINE_UNIXLIB_HANDLE.to_le_bytes());
    let data = as_.stash_bytes(code.into_boxed_slice());
    let base = as_.mmap(None, mapped_bytes, VmaProt::READ | VmaProt::EXEC, VmaFlags::PRIVATE,
        VmaBacking::KernelBytes { data, off: 0 }, false).map_err(|_| pe::Error::Einval)?;
    for address in &mut addresses { *address = base.as_u64().checked_add(*address).ok_or(pe::Error::Einval)?; }
    let relay_call = base.as_u64().checked_add(relay_offset as u64).ok_or(pe::Error::Einval)?;
    let wine_dispatcher = base.as_u64().checked_add(dispatcher_offset as u64).ok_or(pe::Error::Einval)?;
    let wine_unix_dispatcher = base.as_u64().checked_add(unix_dispatcher_offset as u64).ok_or(pe::Error::Einval)?;
    let wine_unixlib_handle = base.as_u64().checked_add(handle_offset as u64).ok_or(pe::Error::Einval)?;
    Ok(NtRuntime { base, bytes: mapped_bytes, relay_call, wine_dispatcher, wine_unix_dispatcher, wine_unixlib_handle, addresses })
}

/// Resolve the private run-once callback continuation in the synthetic ntdll page.
pub fn resolve_nt_runtime_run_once_continuation(base: u64) -> Option<u64> {
    let mut offset = 0u64;
    for (index, _) in NTDLL_EXPORTS.iter().enumerate() { offset = offset.checked_add(runtime_stub_bytes(index) as u64)?; }
    base.checked_add(offset)
}
fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
}
struct RejectImports;
impl ImportResolver for RejectImports {
    fn resolve(&self, _dll: &[u8], _import: &pe::ImportThunk<'_>) -> Result<u64, pe::Error> {
        Err(pe::Error::Unsupported)
    }
}
pub fn initial_entry_state(image: &PeLoadedImage, stack_top: u64) -> Result<PeEntryState, pe::Error> {
    let rsp = stack_top.checked_sub(process_env::X64_SHADOW_SPACE).ok_or(pe::Error::Einval)? & !0xf;
    Ok(PeEntryState { rip: image.entry, rsp: UserVirtAddr::new(rsp).ok_or(pe::Error::Einval)?, gs_base: UserVirtAddr::new(0).ok_or(pe::Error::Einval)?, personality: ExecutionPersonality::Nt })
}
pub fn initial_entry_state_with_environment(image: &PeLoadedImage, stack_top: u64, env: &process_env::NtProcessEnvironment) -> Result<PeEntryState, pe::Error> {
    let mut state = initial_entry_state(image, stack_top)?;
    state.gs_base = env.teb;
    Ok(state)
}

/// Admit the complete first-user-context contract against one address space.
/// The PE entry must be executable, the stack must be the canonical anonymous
/// writable VMA with room for the Windows x64 home area, and GS/PEB must point
/// into the environment block being committed.
/// # C: O(1)
fn validate_entry_context(as_: &AddressSpace, image: &PeLoadedImage,
    env: &process_env::NtProcessEnvironment, stack_base: u64, stack_top: u64,
    state: &PeEntryState) -> Result<(), pe::Error> {
    if !executable_entry(as_, state.rip) || state.rip != image.entry || state.gs_base != env.teb { return Err(pe::Error::Einval); }
    if stack_base == 0 { return Ok(()); }
    let stack_vma = as_.find_vma(UserVirtAddr::new(stack_top.checked_sub(1).ok_or(pe::Error::Einval)?).ok_or(pe::Error::Einval)?)
        .ok_or(pe::Error::Einval)?;
    if stack_base >= stack_top || stack_vma.start.as_u64() != stack_base
        || stack_vma.end.as_u64() != stack_top || !stack_vma.prot.contains(VmaProt::READ | VmaProt::WRITE)
        || !matches!(stack_vma.backing, VmaBacking::Anonymous) { return Err(pe::Error::Einval); }
    let rsp = state.rsp.as_u64();
    if rsp < stack_base || rsp.checked_add(process_env::X64_SHADOW_SPACE).ok_or(pe::Error::Einval)? > stack_top { return Err(pe::Error::Einval); }
    let env_end = env.base.as_u64().checked_add(env.bytes as u64).ok_or(pe::Error::Einval)?;
    for address in [env.peb.as_u64(), env.teb.as_u64()] {
        if address < env.base.as_u64() || address >= env_end || as_.find_vma(UserVirtAddr::new(address).ok_or(pe::Error::Einval)?).is_none() { return Err(pe::Error::Einval); }
    }
    Ok(())
}
pub fn load_pe_process(blob: &[u8], as_: &AddressSpace, input: &process_env::EnvironmentInput<'_>, stack_top: u64) -> Result<PeProcess, pe::Error> {
    load_pe_process_with_resolver(blob, as_, input, stack_top, &RejectImports)
}
pub fn load_pe_process_with_resolver<R: ImportResolver>(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_top: u64, resolver: &R) -> Result<PeProcess, pe::Error> {
    load_pe_process_with_resolver_and_modules(blob, as_, input, stack_top, resolver, &[])
}
pub fn load_pe_process_with_catalog(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_top: u64,
    runtime: &NtRuntime, catalog: &pe::catalog::ModuleCatalog) -> Result<PeProcess, pe::Error> {
    load_pe_process_with_catalog_and_params(blob, as_, input, stack_top, runtime, catalog, None)
}
pub fn load_pe_process_with_catalog_and_params(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_top: u64, runtime: &NtRuntime,
    catalog: &pe::catalog::ModuleCatalog,
    params: Option<&process_env::NtProcessParameters<'_>>) -> Result<PeProcess, pe::Error> {
    load_pe_process_with_catalog_with_stack_bounds(blob, as_, input, 0, stack_top, runtime, runtime, catalog, params)
}
pub fn load_pe_process_with_catalog_and_params_with_stack_bounds(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_base: u64, stack_top: u64, runtime: &NtRuntime,
    catalog: &pe::catalog::ModuleCatalog,
    params: Option<&process_env::NtProcessParameters<'_>>) -> Result<PeProcess, pe::Error> {
    load_pe_process_with_catalog_with_stack_bounds(blob, as_, input, stack_base, stack_top, runtime, runtime, catalog, params)
}
fn load_pe_process_with_catalog_with_stack_bounds<R: ImportResolver>(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_base: u64, stack_top: u64, runtime: &NtRuntime, fallback: &R,
    catalog: &pe::catalog::ModuleCatalog, params: Option<&process_env::NtProcessParameters<'_>>) -> Result<PeProcess, pe::Error> {
    let source = catalog;
    let owned = pe::discover_owned_modules_with_builtins(input.image_path.as_bytes(), blob, &source,
        |name| ascii_eq_ignore_case(name, b"ntdll.dll") && source.load(name).is_none())?;
    let loaded = load_owned_pe_module_graph(&owned, as_, fallback, runtime.relay_call)?;
    let mut environment_input = input.clone();
    environment_input.image_base = loaded[0].image.base;
    environment_input.image_size = loaded[0].image.size;
    let mut modules = alloc::vec::Vec::new();
    for (index, module) in loaded.iter().enumerate() {
        let full_name = if index == 0 { input.image_path } else {
            match core::str::from_utf8(module.name) {
                Ok(name) => name,
                Err(_) => { unmap_loaded_modules(as_, &loaded); return Err(pe::Error::Einval); }
            }
        };
        let base_name = full_name.rsplit(['\\', '/']).next().unwrap_or(full_name);
        modules.push(process_env::NtModuleInput {
            base: module.image.base, entry: module.image.entry.as_u64(),
            size: module.image.size, full_name, base_name,
        });
    }
    if !loaded.iter().any(|module| ascii_eq_ignore_case(module.name, b"ntdll.dll")) {
        modules.push(process_env::NtModuleInput {
            base: runtime.base.as_u64(), entry: 0, size: runtime.bytes as u32,
            full_name: "C:\\Windows\\System32\\ntdll.dll", base_name: "ntdll.dll",
        });
    }
    let environment = match params.map_or_else(
        || process_env::build_with_modules_and_stack(&environment_input, &modules, stack_base, stack_top, as_),
        |params| process_env::build_with_modules_and_params_and_stack(&environment_input, &modules, params, stack_base, stack_top, as_)) {
        Ok(environment) => environment,
        Err(error) => {
            unmap_loaded_modules(as_, &loaded);
            return Err(error);
        }
    };
    let mut entry = match initial_entry_state_with_environment(&loaded[0].image, stack_top, &environment) {
        Ok(entry) => entry,
        Err(error) => {
            let _ = as_.munmap(environment.base, environment.bytes);
            unmap_loaded_modules(as_, &loaded);
            return Err(error);
        }
    };
    if validate_entry_context(as_, &loaded[0].image, &environment, stack_base, stack_top, &entry).is_err() {
        let _ = as_.munmap(environment.base, environment.bytes);
        unmap_loaded_modules(as_, &loaded);
        return Err(pe::Error::Einval);
    }
    let initializers = match pe_init::collect_initializers(&loaded, &owned) {
        Ok(initializers) => initializers,
        Err(error) => { let _ = as_.munmap(environment.base, environment.bytes); unmap_loaded_modules(as_, &loaded); return Err(error); }
    };
    let exit_entry = match resolve_nt_runtime_export(runtime.base.as_u64(), b"RtlExitUserProcess")
        .and_then(UserVirtAddr::new) { Some(entry) => entry, None => {
            let _ = as_.munmap(environment.base, environment.bytes);
            unmap_loaded_modules(as_, &loaded);
            return Err(pe::Error::Unsupported);
        }};
    let initializer_trampoline = match pe_init::map_with_exit(as_, entry.rip, &initializers, exit_entry) {
        Ok(trampoline) => Some(trampoline),
        Err(error) => { let _ = as_.munmap(environment.base, environment.bytes); unmap_loaded_modules(as_, &loaded); return Err(error); }
    };
    if let Some(trampoline) = initializer_trampoline { entry.rip = trampoline.entry; }
    let mut runtime_modules = loaded.iter().zip(&owned).map(|(module, owned)| -> Result<_, pe::Error> { Ok(pe_modules::PeRuntimeModule { base: module.image.base, size: module.image.size, exception_rva: module.image.exception_directory.0, exception_size: module.image.exception_directory.1, exception_functions: pe::parse(&owned.blob)?.exception_functions()? }) }).collect::<Result<alloc::vec::Vec<_>, _>>()?;
    if !loaded.iter().any(|module| ascii_eq_ignore_case(module.name, b"ntdll.dll")) {
        runtime_modules.push(pe_modules::PeRuntimeModule { base: runtime.base.as_u64(), size: runtime.bytes as u32, exception_rva: 0, exception_size: 0, exception_functions: alloc::vec::Vec::new() });
    }
    pe_modules::register(as_, &runtime_modules);
    for (module, owned_module) in loaded.iter().zip(&owned) {
        if let Some(rvas) = pe::parse(&owned_module.blob)?.export_rvas()? {
            pe_modules::register_exports(as_, module.image.base, rvas);
        }
    }
    Ok(PeProcess { image: loaded[0].image, environment, entry, initializers, initializer_trampoline })
}

#[cfg(test)]
fn load_pe_process_with_catalog_with_fallback<R: ImportResolver>(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_top: u64, runtime: &NtRuntime, fallback: &R,
    catalog: &pe::catalog::ModuleCatalog, params: Option<&process_env::NtProcessParameters<'_>>) -> Result<PeProcess, pe::Error> {
    load_pe_process_with_catalog_with_stack_bounds(blob, as_, input, 0, stack_top, runtime, fallback, catalog, params)
}
fn unmap_loaded_modules(as_: &AddressSpace, loaded: &[PeLoadedModule<'_>]) {
    for module in loaded {
        if let Some(base) = UserVirtAddr::new(module.image.base) {
            let _ = as_.munmap(base, module.image.size as usize);
        }
    }
}
pub fn load_pe_process_with_resolver_and_modules<R: ImportResolver>(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_top: u64, resolver: &R, additional_modules: &[process_env::NtModuleInput<'_>]) -> Result<PeProcess, pe::Error> {
    load_pe_process_with_resolver_and_modules_and_params(blob, as_, input, stack_top, resolver, additional_modules, None)
}
pub fn load_pe_process_with_resolver_and_modules_and_params<R: ImportResolver>(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_top: u64, resolver: &R,
    additional_modules: &[process_env::NtModuleInput<'_>], params: Option<&process_env::NtProcessParameters<'_>>) -> Result<PeProcess, pe::Error> {
    load_pe_process_with_resolver_and_modules_and_params_with_stack_bounds(blob, as_, input, 0, stack_top, resolver, additional_modules, params)
}
pub fn load_pe_process_with_resolver_and_modules_and_params_with_stack_bounds<R: ImportResolver>(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_base: u64, stack_top: u64, resolver: &R,
    additional_modules: &[process_env::NtModuleInput<'_>], params: Option<&process_env::NtProcessParameters<'_>>) -> Result<PeProcess, pe::Error> {
    let image = load_pe_image_with_resolver(blob, as_, resolver)?;
    // PEB image metadata belongs to the mapped image, not to caller-supplied
    // bookkeeping. Keep the other process strings/IDs from the caller while
    // deriving these two fields from the validated PE headers and placement.
    let mut environment_input = input.clone();
    environment_input.image_base = image.base;
    environment_input.image_size = image.size;
    let root_name = input.image_path.rsplit(['\\', '/']).next().unwrap_or(input.image_path);
    let mut modules = alloc::vec![process_env::NtModuleInput { base: image.base, entry: image.entry.as_u64(), size: image.size, full_name: input.image_path, base_name: root_name }];
    modules.extend_from_slice(additional_modules);
    let environment = match params.map_or_else(
        || process_env::build_with_modules_and_stack(&environment_input, &modules, stack_base, stack_top, as_),
        |params| process_env::build_with_modules_and_params_and_stack(&environment_input, &modules, params, stack_base, stack_top, as_)) {
        Ok(environment) => environment,
        Err(error) => { let _ = as_.munmap(UserVirtAddr::new(image.base).ok_or(pe::Error::Einval)?, image.size as usize); return Err(error); }
    };
    let entry = match initial_entry_state_with_environment(&image, stack_top, &environment) {
        Ok(entry) => entry,
        Err(error) => { let _ = as_.munmap(environment.base, environment.bytes); let _ = as_.munmap(UserVirtAddr::new(image.base).ok_or(pe::Error::Einval)?, image.size as usize); return Err(error); }
    };
    if validate_entry_context(as_, &image, &environment, stack_base, stack_top, &entry).is_err() {
        let _ = as_.munmap(environment.base, environment.bytes);
        let _ = as_.munmap(UserVirtAddr::new(image.base).ok_or(pe::Error::Einval)?, image.size as usize);
        return Err(pe::Error::Einval);
    }
    let initializers = match pe_init::collect_root_initializers(blob, &image) { Ok(initializers) => initializers, Err(error) => { let _ = as_.munmap(environment.base, environment.bytes); let _ = as_.munmap(UserVirtAddr::new(image.base).ok_or(pe::Error::Einval)?, image.size as usize); return Err(error); } };
    let initializer_trampoline = match pe_init::map(as_, entry.rip, &initializers) {
        Ok(trampoline) => trampoline,
        Err(error) => { let _ = as_.munmap(environment.base, environment.bytes); let _ = as_.munmap(UserVirtAddr::new(image.base).ok_or(pe::Error::Einval)?, image.size as usize); return Err(error); }
    };
    let entry = if let Some(trampoline) = initializer_trampoline { PeEntryState { rip: trampoline.entry, ..entry } } else { entry };
    pe_modules::register(as_, &[pe_modules::PeRuntimeModule { base: image.base, size: image.size, exception_rva: image.exception_directory.0, exception_size: image.exception_directory.1, exception_functions: pe::parse(blob)?.exception_functions()? }]);
    Ok(PeProcess { image, environment, entry, initializers, initializer_trampoline })
}
/// Map one validated PE32+ image into the common address space. # C: O(SizeOfImage + N_sections)
pub fn load_pe_image(blob: &[u8], as_: &AddressSpace) -> Result<PeLoadedImage, pe::Error> {
    load_pe_image_with_resolver(blob, as_, &RejectImports)
}
pub fn load_pe_image_with_resolver<R: ImportResolver>(blob: &[u8], as_: &AddressSpace, resolver: &R) -> Result<PeLoadedImage, pe::Error> {
    load_pe_image_with_resolver_at(blob, as_, resolver, None, 0)
}
/// Map one validated image using the shared import resolver and optional exact placement. # C: O(SizeOfImage + N_sections)
pub fn load_pe_image_with_resolver_at<R: ImportResolver>(blob: &[u8], as_: &AddressSpace, resolver: &R, exact_base: Option<UserVirtAddr>, relay_call: u64) -> Result<PeLoadedImage, pe::Error> {
    let parsed = pe::parse(blob)?;
    // Validate callback-array termination and image-relative addresses before
    // binding or reserving anything; malformed TLS must leave no VMA behind.
    let _tls_callbacks = parsed.tls_callback_rvas()?;
    let mut image = parsed.materialize()?;
    let len = parsed.size_of_image as usize;
    // Reserve the whole image first. This obtains the preferred base when it
    // is clear, or an ASLR fallback, without exposing a partially mapped PE.
    // The new exec address space is private and not concurrently modified.
    let reservation = match exact_base {
        Some(base) => as_.mmap_with_may_at(MmapPlacement::Fixed(base), len, VmaProt::READ | VmaProt::WRITE,
            VmaProt::READ | VmaProt::WRITE | VmaProt::EXEC, VmaFlags::PRIVATE, VmaBacking::Anonymous).map_err(|_| pe::Error::Einval)?,
        None => as_.mmap(UserVirtAddr::new(parsed.image_base), len, VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE, VmaBacking::Anonymous, false).map_err(|_| pe::Error::Einval)?,
    };
    let base = reservation.as_u64();
    if let Err(error) = pe::apply_relocations(&mut image, &parsed, base) {
        let _ = as_.munmap(reservation, len);
        return Err(error);
    }
    // Relocations apply to image-owned absolute pointers. Bind external IAT
    // addresses only afterward; otherwise the relocation delta is added to
    // an already-final external function pointer.
    if let Err(error) = bind_imports(&parsed, &mut image, resolver) {
        let _ = as_.munmap(reservation, len);
        return Err(error);
    }
    // Wine owns relay installation. Its loader first records each original
    // EAT target in relay_private_data, then patches the EAT to the generated
    // Windows-ABI thunk. Patching here would make Wine record the thunk as
    // orig_func and the native RelayCall would recurse into that thunk.
    // Imports still resolve relay_export_rva through PeGraphResolver; direct
    // exports remain untouched until Wine has initialized its descriptor.
    if relay_call != 0 {
        if let Some(descriptor_rva) = parsed.relay_descriptor_rva()? {
            let slot = (descriptor_rva as usize).checked_add(8).ok_or(pe::Error::Einval)?;
            let end = slot.checked_add(8).ok_or(pe::Error::Einval)?;
            image.get_mut(slot..end).ok_or(pe::Error::Einval)?.copy_from_slice(&relay_call.to_le_bytes());
            klog::write_raw(b"[WINDOWS-PE-RELAY] base=");
            klog::write_hex_u64(base);
            klog::write_raw(b" descriptor=");
            klog::write_hex_u64(base.checked_add(descriptor_rva as u64).ok_or(pe::Error::Einval)?);
            klog::write_raw(b" dispatcher=");
            klog::write_hex_u64(relay_call);
            klog::write_raw(b"\n");
        }
    }
    as_.munmap(reservation, len).map_err(|_| pe::Error::Einval)?;
    let data: Arc<[u8]> = as_.stash_bytes(image.into_boxed_slice());
    as_.mmap_with_may_at(MmapPlacement::FixedNoReplace(reservation), len,
        VmaProt::READ, VmaProt::READ | VmaProt::WRITE | VmaProt::EXEC,
        VmaFlags::PRIVATE, VmaBacking::KernelBytes { data, off: 0 })
        .map_err(|_| pe::Error::Einval)?;
    let mut transaction = PeImageTransaction::new(as_, reservation, len);
    let header_len = align_up(parsed.size_of_headers, parsed.section_alignment);
    as_.mprotect(reservation, header_len as usize, VmaProt::READ).map_err(|_| pe::Error::Einval)?;
    for section in &parsed.sections {
        let span = align_up(section.virtual_size.max(section.raw_size), parsed.section_alignment);
        if span == 0 { continue; }
        let prot = section_prot(section.characteristics)?;
        let start = base.checked_add(section.virtual_address as u64).ok_or(pe::Error::Einval)?;
        as_.mprotect(UserVirtAddr::new(start).ok_or(pe::Error::Einval)?, span as usize, prot).map_err(|_| pe::Error::Einval)?;
    }
    let entry = UserVirtAddr::new(base.checked_add(parsed.entry_rva as u64).ok_or(pe::Error::Einval)?).ok_or(pe::Error::Einval)?;
    // The transfer address is executable code, not merely an in-range RVA.
    // Keep this check in the loader transaction so a malformed image cannot
    // publish a task that will fault on its first user instruction.
    if !executable_entry(as_, entry) { return Err(pe::Error::Einval); }
    let exception = parsed.directories[pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    let tls = parsed.directories[pe::IMAGE_DIRECTORY_ENTRY_TLS];
    transaction.commit();
    Ok(PeLoadedImage { base, preferred_base: parsed.image_base, entry, size: parsed.size_of_image, exception_directory: (exception.rva, exception.size), tls_directory: (tls.rva, tls.size) })
}
pub fn load_pe_module_set_with_resolver<'a, R: ImportResolver>(modules: &[pe::Module<'a>], as_: &AddressSpace, resolver: &R) -> Result<alloc::vec::Vec<PeLoadedModule<'a>>, pe::Error> {
    let mut loaded = alloc::vec::Vec::new();
    for module in modules {
        match load_pe_image_with_resolver(module.image.raw, as_, resolver) {
            Ok(image) => loaded.push(PeLoadedModule { name: module.name, image }),
            Err(error) => {
                for module in loaded { if let Some(base) = UserVirtAddr::new(module.image.base) { let _ = as_.munmap(base, module.image.size as usize); } }
                return Err(error);
            }
        }
    }
    Ok(loaded)
}
pub fn load_pe_module_graph<'a, R: ImportResolver>(modules: &[pe::Module<'a>], as_: &AddressSpace, fallback: &R, relay_call: u64) -> Result<alloc::vec::Vec<PeLoadedModule<'a>>, pe::Error> {
    let mut bases: alloc::vec::Vec<PeModuleBase<'a>> = alloc::vec::Vec::new();
    for module in modules {
        let size = module.image.size_of_image as usize;
        let reservation = match as_.mmap(UserVirtAddr::new(module.image.image_base), size, VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE, VmaBacking::Anonymous, false) {
            Ok(base) => base,
            Err(_) => {
                for entry in &bases { let _ = as_.munmap(UserVirtAddr::new(entry.base).ok_or(pe::Error::Einval)?, entry.size as usize); }
                return Err(pe::Error::Einval);
            }
        };
        bases.push(PeModuleBase { name: module.name, base: reservation.as_u64(), size: module.image.size_of_image });
    }
    for module in &bases {
        klog::write_raw(b"[WINDOWS-PE-MODULE] name=");
        klog::write_raw(module.name);
        klog::write_raw(b" base=");
        klog::write_hex_u64(module.base);
        klog::write_raw(b" size=");
        klog::write_hex_u64(module.size as u64);
        klog::write_raw(b"\n");
    }
    let mut exports = alloc::vec::Vec::new();
    for (module, base) in modules.iter().zip(&bases) { exports.push(PeExportRef { name: module.name, image: &module.image, base: base.base }); }
    let resolver = PeGraphResolver { modules: &exports, fallback };
    let mut loaded = alloc::vec::Vec::new();
    for (module, base) in modules.iter().zip(&bases) {
        match load_pe_image_with_resolver_at(module.image.raw, as_, &resolver, UserVirtAddr::new(base.base), relay_call) {
            Ok(image) => loaded.push(PeLoadedModule { name: module.name, image }),
            Err(error) => {
                for entry in &bases { if let Some(address) = UserVirtAddr::new(entry.base) { let _ = as_.munmap(address, entry.size as usize); } }
                return Err(error);
            }
        }
    }
    Ok(loaded)
}
pub fn load_owned_pe_module_graph<'a, R: ImportResolver>(modules: &'a [pe::OwnedModule], as_: &AddressSpace, fallback: &R, relay_call: u64) -> Result<alloc::vec::Vec<PeLoadedModule<'a>>, pe::Error> {
    let mut views = alloc::vec::Vec::new();
    for module in modules {
        views.push(pe::Module { name: &module.name, image: pe::parse(&module.blob)? });
    }
    load_pe_module_graph(&views, as_, fallback, relay_call)
}
fn bind_imports<R: ImportResolver>(parsed: &pe::Image<'_>, image: &mut [u8], resolver: &R) -> Result<(), pe::Error> {
    for import in parsed.imports()? {
        let thunks = parsed.import_thunks(&import)?;
        for (index, thunk) in thunks.iter().enumerate() {
            let offset = (import.first_thunk as usize).checked_add(index.checked_mul(8).ok_or(pe::Error::Einval)?).ok_or(pe::Error::Einval)?;
            let end = offset.checked_add(8).ok_or(pe::Error::Einval)?;
            if end > image.len() || !parsed.sections.iter().any(|section| {
                let section_end = section.virtual_address.saturating_add(section.virtual_size.max(section.raw_size));
                (offset as u32) >= section.virtual_address && (end as u32) <= section_end
                    && section.characteristics.contains(pe::SectionFlags::MEM_WRITE)
            }) { return Err(pe::Error::Einval); }
            let address = match resolver.resolve(import.name, thunk) {
                Ok(address) => address,
                Err(error) => return Err(error),
            };
            #[cfg(feature = "debug-faultdiag")]
            if import.name.eq_ignore_ascii_case(b"ntdll.dll")
                && matches!(thunk, pe::ImportThunk::Name { name, .. } if *name == b"RtlGetVersion" || *name == b"RtlRunOnceExecuteOnce") {
                klog::write_raw(b"[WINDOWS-PE-BIND-NT] name=");
                if let pe::ImportThunk::Name { name, .. } = thunk { klog::write_raw(name); }
                klog::write_raw(b" address=");
                klog::write_hex_u64(address);
                klog::write_raw(b"\n");
            }
            #[cfg(feature = "debug-faultdiag")]
            if (0x1800_04c00..0x1800_05000).contains(&address) {
                klog::write_raw(b"[WINDOWS-PE-BIND] dll=");
                klog::write_raw(import.name);
                klog::write_raw(b" symbol=");
                match thunk {
                    pe::ImportThunk::Name { name, .. } => klog::write_raw(name),
                    pe::ImportThunk::Ordinal(ordinal) => klog::write_dec_u64(*ordinal as u64),
                }
                klog::write_raw(b" address=");
                klog::write_hex_u64(address);
                klog::write_raw(b"\n");
            }
            image[offset..end].copy_from_slice(&address.to_le_bytes());
        }
    }
    Ok(()) } fn section_prot(flags: SectionFlags) -> Result<VmaProt, pe::Error> {
    let mut prot = VmaProt::empty(); if flags.contains(SectionFlags::MEM_READ) { prot |= VmaProt::READ; } if flags.contains(SectionFlags::MEM_WRITE) { prot |= VmaProt::WRITE; } if flags.contains(SectionFlags::MEM_EXECUTE) { prot |= VmaProt::EXEC; } Ok(prot) } fn align_up(v: u32, a: u32) -> u32 { v.saturating_add(a - 1) & !(a - 1) } #[cfg(test)] #[path = "tests/pe_loader.rs"] mod tests;
