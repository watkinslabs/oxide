use alloc::sync::Arc; use crate::pe_init; use crate::process_env; use hal::UserVirtAddr; use pe::{self, SectionFlags}; use vmm::{AddressSpace, MmapPlacement, VmaBacking, VmaFlags, VmaProt};
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
    addresses: [u64; 177],
}
const NTDLL_EXPORTS: [&[u8]; 177] = [
    b"NtAllocateVirtualMemory", b"NtFreeVirtualMemory", b"NtProtectVirtualMemory", b"NtQueryVirtualMemory",
    b"NtTerminateProcess", b"NtCreateEvent", b"NtClose", b"NtSetEvent", b"NtResetEvent", b"NtWaitForSingleObject",
    b"NtCreateFile", b"NtOpenFile", b"NtReadFile", b"NtWriteFile", b"NtQueryInformationFile", b"NtSetInformationFile", b"NtQueryDirectoryFile", b"NtWaitForMultipleObjects",
    b"NtCreateSection", b"NtMapViewOfSection", b"NtUnmapViewOfSection", b"NtQueryInformationProcess", b"NtCreateThreadEx", b"NtTerminateThread", b"NtQueryInformationThread",
    b"RtlAllocateHeap", b"RtlFreeHeap", b"NtdllDefWindowProc_A", b"NtdllDefWindowProc_W", b"RtlReAllocateHeap", b"LdrResolveDelayLoadedAPI", b"RtlUnwind", b"NtCreateSemaphore", b"NtReleaseSemaphore", b"NtCreateMutant", b"NtReleaseMutant", b"NtQueryMutant", b"NtLockFile", b"NtUnlockFile", b"NtDuplicateObject", b"NtCreateTimer", b"NtSetTimer", b"NtCancelTimer", b"NtCreateIoCompletion", b"NtSetIoCompletion", b"NtRemoveIoCompletion", b"NtSignalAndWaitForSingleObject", b"NtOpenProcessToken", b"NtOpenThreadToken", b"NtQueryInformationToken", b"RtlInitUnicodeString", b"RtlInitUnicodeStringEx", b"NtQueryObject", b"RtlInitAnsiString", b"RtlInitAnsiStringEx", b"NtQuerySecurityObject", b"RtlQueryPerformanceCounter", b"RtlQueryPerformanceFrequency", b"NtRenameKey", b"NtSetSecurityObject", b"RtlAddAccessAllowedAce", b"RtlAddAccessAllowedAceEx", b"RtlAddAccessDeniedAce", b"RtlAddAccessDeniedAceEx", b"RtlAddAce", b"RtlAddAuditAccessAce", b"RtlAddAuditAccessAceEx", b"RtlCreateAcl", b"RtlCreateSecurityDescriptor", b"RtlCreateUnicodeStringFromAsciiz", b"RtlDosPathNameToNtPathName_U", b"RtlFreeUnicodeString", b"RtlGetAce", b"RtlGetControlSecurityDescriptor", b"RtlIsTextUnicode", b"RtlLengthSecurityDescriptor", b"RtlMakeSelfRelativeSD", b"RtlNtStatusToDosError", b"RtlQueryInformationAcl", b"RtlSelfRelativeToAbsoluteSD", b"RtlUniform", b"RtlDeleteCriticalSection", b"RtlEnterCriticalSection", b"RtlLeaveCriticalSection", b"_vsnprintf", b"RtlSizeHeap", b"RtlExitUserThread", b"RtlQueryUnbiasedInterruptTime", b"DbgUiGetThreadDebugObject", b"DbgUiIssueRemoteBreakin", b"LdrGetDllDirectory", b"LdrGetProcedureAddress", b"LdrSetDllDirectory", b"NtAddAtom", b"NtAssignProcessToJobObject", b"NtCreateJobObject", b"NtCreateMailslotFile", b"NtDeleteAtom", b"NtDeviceIoControlFile", b"NtFindAtom", b"NtFsControlFile", b"NtOpenJobObject", b"NtPowerInformation", b"NtQueryInformationAtom", b"NtQueryInformationJobObject", b"NtQuerySection", b"NtQuerySystemInformation", b"NtQuerySystemTime", b"NtSetInformationDebugObject", b"NtSetInformationJobObject", b"NtSetInformationProcess", b"NtSetInformationThread", b"NtSetThreadExecutionState", b"NtTerminateJobObject", b"RtlAcquirePebLock", b"RtlReleasePebLock", b"RtlAddAtomToAtomTable",
    b"RtlAnsiStringToUnicodeString", b"RtlCaptureContext", b"RtlCharToInteger", b"RtlCreateAtomTable", b"RtlCreateHeap", b"RtlCreateUnicodeString", b"RtlDeleteAtomFromAtomTable", b"RtlDeregisterWait", b"RtlDestroyAtomTable", b"RtlDestroyHeap", b"RtlDetermineDosPathNameType_U", b"RtlDosPathNameToNtPathName_U_WithStatus", b"RtlExitUserProcess", b"RtlGetProcessHeaps", b"RtlGetUserInfoHeap", b"RtlImageNtHeader", b"RtlInitializeCriticalSection", b"RtlInitializeCriticalSectionAndSpinCount", b"RtlInitializeCriticalSectionEx", b"RtlIsNameLegalDOS8Dot3", b"RtlLockHeap", b"RtlUnlockHeap", b"RtlLookupAtomInAtomTable", b"RtlOemStringToUnicodeString", b"RtlQueryAtomInAtomTable", b"RtlRegisterWait", b"RtlRestoreContext", b"RtlSetIoCompletionCallback", b"RtlGetLastWin32Error", b"RtlRestoreLastWin32Error", b"RtlSetLastWin32Error", b"RtlSetSearchPathMode", b"RtlSetUnhandledExceptionFilter", b"RtlSetUserValueHeap", b"RtlTimeFieldsToTime", b"RtlTimeToTimeFields", b"RtlUnicodeStringToAnsiSize", b"RtlUnicodeStringToAnsiString", b"RtlUnicodeStringToInteger", b"RtlUnicodeStringToOemSize", b"RtlUnicodeStringToOemString", b"RtlUnicodeToMultiByteN", b"RtlUnicodeToMultiByteSize", b"RtlUnicodeToOemN", b"RtlUpcaseUnicodeString", b"RtlUpperChar", b"_wcsicmp", b"_wcsnicmp", b"isalpha", b"islower", b"memcpy", b"memmove", b"memset", b"strcat", b"strchr", b"strcpy", b"strlen", b"strpbrk", b"strrchr", b"tolower",
];
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
pub struct PeModuleInitializer { pub base: u64, pub entry: UserVirtAddr }
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
        let rva = module.image.export_rva(import)?.ok_or(pe::Error::Unsupported)?;
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
        if let Some(module) = self.modules.iter().find(|module| ascii_eq_ignore_case(module.name, dll)) {
            let target = module.image.export_target(import)?.ok_or(pe::Error::Unsupported)?;
            return match target {
                pe::ExportTarget::Rva(rva) => module.base.checked_add(rva as u64).ok_or(pe::Error::Einval),
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
pub fn map_nt_runtime(as_: &AddressSpace) -> Result<NtRuntime, pe::Error> {
    let page = hal::PAGE_SIZE_BYTES as usize;
    let code_bytes = NTDLL_EXPORTS.len() * pe::nt_stub::X64_SIX_ARG_STUB_BYTES;
    let mapped_bytes = (code_bytes + page - 1) / page * page;
    let mut code = alloc::vec![0u8; mapped_bytes];
    let mut addresses = [0u64; 177];
    let mut offset = 0usize;
    for index in 0..177 {
        let selector = match index {
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
            _ => syscall::nt::NtService::FreeHeap,
        };
        let bytes = if matches!(index, 6 | 88) { pe::nt_stub::encode_x64_unary_stub(selector.entry()).to_vec() } else { pe::nt_stub::encode_x64_six_arg_stub(selector.entry()).to_vec() };
        if offset.checked_add(bytes.len()).filter(|&end| end <= code.len()).is_none() { return Err(pe::Error::Einval); }
        code[offset..offset + bytes.len()].copy_from_slice(&bytes);
        addresses[index] = offset as u64;
        offset += bytes.len();
    }
    let data = as_.stash_bytes(code.into_boxed_slice());
    let base = as_.mmap(None, mapped_bytes, VmaProt::READ | VmaProt::EXEC, VmaFlags::PRIVATE,
        VmaBacking::KernelBytes { data, off: 0 }, false).map_err(|_| pe::Error::Einval)?;
    for address in &mut addresses { *address = base.as_u64().checked_add(*address).ok_or(pe::Error::Einval)?; }
    Ok(NtRuntime { base, bytes: mapped_bytes, addresses })
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
    load_pe_process_with_catalog_with_fallback(blob, as_, input, stack_top, runtime, runtime, catalog)
}
fn load_pe_process_with_catalog_with_fallback<R: ImportResolver>(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_top: u64, runtime: &NtRuntime, fallback: &R,
    catalog: &pe::catalog::ModuleCatalog) -> Result<PeProcess, pe::Error> {
    let source = catalog;
    let owned = pe::discover_owned_modules_with_builtins(input.image_path.as_bytes(), blob, &source,
        |name| ascii_eq_ignore_case(name, b"ntdll.dll") && source.load(name).is_none())?;
    let loaded = load_owned_pe_module_graph(&owned, as_, fallback)?;
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
    let environment = match process_env::build_with_modules(&environment_input, &modules, as_) {
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
    let initializers = match pe_init::collect_initializers(&loaded, &owned) {
        Ok(initializers) => initializers,
        Err(error) => { let _ = as_.munmap(environment.base, environment.bytes); unmap_loaded_modules(as_, &loaded); return Err(error); }
    };
    let initializer_trampoline = match pe_init::map(as_, entry.rip, &initializers) {
        Ok(trampoline) => trampoline,
        Err(error) => { let _ = as_.munmap(environment.base, environment.bytes); unmap_loaded_modules(as_, &loaded); return Err(error); }
    };
    if let Some(trampoline) = initializer_trampoline { entry.rip = trampoline.entry; }
    Ok(PeProcess { image: loaded[0].image, environment, entry, initializers, initializer_trampoline })
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
    let environment = match process_env::build_with_modules(&environment_input, &modules, as_) {
        Ok(environment) => environment,
        Err(error) => { let _ = as_.munmap(UserVirtAddr::new(image.base).ok_or(pe::Error::Einval)?, image.size as usize); return Err(error); }
    };
    let entry = match initial_entry_state_with_environment(&image, stack_top, &environment) {
        Ok(entry) => entry,
        Err(error) => { let _ = as_.munmap(environment.base, environment.bytes); let _ = as_.munmap(UserVirtAddr::new(image.base).ok_or(pe::Error::Einval)?, image.size as usize); return Err(error); }
    };
    let initializers = match pe_init::collect_root_initializers(blob, &image) { Ok(initializers) => initializers, Err(error) => { let _ = as_.munmap(environment.base, environment.bytes); let _ = as_.munmap(UserVirtAddr::new(image.base).ok_or(pe::Error::Einval)?, image.size as usize); return Err(error); } };
    let initializer_trampoline = match pe_init::map(as_, entry.rip, &initializers) {
        Ok(trampoline) => trampoline,
        Err(error) => { let _ = as_.munmap(environment.base, environment.bytes); let _ = as_.munmap(UserVirtAddr::new(image.base).ok_or(pe::Error::Einval)?, image.size as usize); return Err(error); }
    };
    let entry = if let Some(trampoline) = initializer_trampoline { PeEntryState { rip: trampoline.entry, ..entry } } else { entry };
    Ok(PeProcess { image, environment, entry, initializers, initializer_trampoline })
}
/// Map one validated PE32+ image into the common address space. # C: O(SizeOfImage + N_sections)
pub fn load_pe_image(blob: &[u8], as_: &AddressSpace) -> Result<PeLoadedImage, pe::Error> {
    load_pe_image_with_resolver(blob, as_, &RejectImports)
}
pub fn load_pe_image_with_resolver<R: ImportResolver>(blob: &[u8], as_: &AddressSpace, resolver: &R) -> Result<PeLoadedImage, pe::Error> {
    load_pe_image_with_resolver_at(blob, as_, resolver, None)
}
fn load_pe_image_with_resolver_at<R: ImportResolver>(blob: &[u8], as_: &AddressSpace, resolver: &R, exact_base: Option<UserVirtAddr>) -> Result<PeLoadedImage, pe::Error> {
    let parsed = pe::parse(blob)?;
    // Validate callback-array termination and image-relative addresses before
    // binding or reserving anything; malformed TLS must leave no VMA behind.
    let _tls_callbacks = parsed.tls_callback_rvas()?;
    let mut image = parsed.materialize()?;
    bind_imports(&parsed, &mut image, resolver)?;
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
    as_.munmap(reservation, len).map_err(|_| pe::Error::Einval)?;
    let data: Arc<[u8]> = as_.stash_bytes(image.into_boxed_slice());
    as_.mmap_with_may_at(MmapPlacement::FixedNoReplace(reservation), len,
        VmaProt::READ, VmaProt::READ | VmaProt::WRITE | VmaProt::EXEC,
        VmaFlags::PRIVATE, VmaBacking::KernelBytes { data, off: 0 })
        .map_err(|_| pe::Error::Einval)?;
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
    let exception = parsed.directories[pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    let tls = parsed.directories[pe::IMAGE_DIRECTORY_ENTRY_TLS];
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
pub fn load_pe_module_graph<'a, R: ImportResolver>(modules: &[pe::Module<'a>], as_: &AddressSpace, fallback: &R) -> Result<alloc::vec::Vec<PeLoadedModule<'a>>, pe::Error> {
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
    let mut exports = alloc::vec::Vec::new();
    for (module, base) in modules.iter().zip(&bases) { exports.push(PeExportRef { name: module.name, image: &module.image, base: base.base }); }
    let resolver = PeGraphResolver { modules: &exports, fallback };
    let mut loaded = alloc::vec::Vec::new();
    for (module, base) in modules.iter().zip(&bases) {
        match load_pe_image_with_resolver_at(module.image.raw, as_, &resolver, UserVirtAddr::new(base.base)) {
            Ok(image) => loaded.push(PeLoadedModule { name: module.name, image }),
            Err(error) => {
                for entry in &bases { if let Some(address) = UserVirtAddr::new(entry.base) { let _ = as_.munmap(address, entry.size as usize); } }
                return Err(error);
            }
        }
    }
    Ok(loaded)
}
pub fn load_owned_pe_module_graph<'a, R: ImportResolver>(modules: &'a [pe::OwnedModule], as_: &AddressSpace, fallback: &R) -> Result<alloc::vec::Vec<PeLoadedModule<'a>>, pe::Error> {
    let mut views = alloc::vec::Vec::new();
    for module in modules {
        views.push(pe::Module { name: &module.name, image: pe::parse(&module.blob)? });
    }
    load_pe_module_graph(&views, as_, fallback)
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
            image[offset..end].copy_from_slice(&address.to_le_bytes());
        }
    }
    Ok(()) } fn section_prot(flags: SectionFlags) -> Result<VmaProt, pe::Error> {
    let mut prot = VmaProt::empty(); if flags.contains(SectionFlags::MEM_READ) { prot |= VmaProt::READ; } if flags.contains(SectionFlags::MEM_WRITE) { prot |= VmaProt::WRITE; } if flags.contains(SectionFlags::MEM_EXECUTE) { prot |= VmaProt::EXEC; } Ok(prot) } fn align_up(v: u32, a: u32) -> u32 { v.saturating_add(a - 1) & !(a - 1) } #[cfg(test)] #[path = "tests/pe_loader.rs"] mod tests;
