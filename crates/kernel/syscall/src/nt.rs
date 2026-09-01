use crate::{Errno, SyscallArgs, UserPtr};
/// NT calls use a distinct entry path; Linux syscall numbers never enter it.
pub const NT_SERVICE_NAMESPACE: u64 = 0x4e54_0000_0000_0000;
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum NtService {
    AllocateVirtualMemory = 0, FreeVirtualMemory = 1, ProtectVirtualMemory = 2,
    QueryVirtualMemory = 3, TerminateProcess = 4, CreateEvent = 5,
    Close = 6, SetEvent = 7, ResetEvent = 8, WaitForSingleObject = 9,
    CreateFile = 10, OpenFile = 11, ReadFile = 12, WriteFile = 13,
    QueryInformationFile = 14, SetInformationFile = 15, QueryDirectoryFile = 16,
    WaitForMultipleObjects = 17,
    CreateSection = 18, MapViewOfSection = 19, UnmapViewOfSection = 20,
    QueryInformationProcess = 21, CreateThreadEx = 22, TerminateThread = 23,
    QueryInformationThread = 24, AllocateHeap = 25, FreeHeap = 26,
    CreateWindow = 27, DestroyWindow = 28, PostMessage = 29, PeekMessage = 30,
    GetMessage = 31, DefaultWindowProc = 32, ReallocateHeap = 33, ResolveDelayLoadedApi = 34, RtlUnwind = 35, CreateSemaphore = 36, ReleaseSemaphore = 37, ExecuteWithCatalog = 38, CreateMutant = 39, ReleaseMutant = 40, QueryMutant = 41, CreateKey = 42, OpenKey = 43, QueryValueKey = 44, SetValueKey = 45, LockFile = 46, UnlockFile = 47, DuplicateObject = 48, CreateTimer = 49, SetTimer = 50, CancelTimer = 51, CreateIoCompletion = 52, SetIoCompletion = 53, RemoveIoCompletion = 54, SignalAndWait = 55, OpenProcessToken = 56, OpenThreadToken = 57, QueryToken = 58, RtlInitUnicodeString = 59, RtlInitUnicodeStringEx = 60, QueryObject = 61, RtlInitAnsiString = 62, RtlInitAnsiStringEx = 63, QuerySecurityObject = 64, RtlQueryPerformanceCounter = 65, RtlQueryPerformanceFrequency = 66, RenameKey = 67, SetSecurityObject = 68, RtlAddAccessAllowedAce = 69, RtlAddAccessAllowedAceEx = 70, RtlAddAccessDeniedAce = 71, RtlAddAccessDeniedAceEx = 72, RtlAddAce = 73, RtlAddAuditAccessAce = 74, RtlAddAuditAccessAceEx = 75, RtlCreateAcl = 76, RtlCreateSecurityDescriptor = 77, RtlCreateUnicodeStringFromAsciiz = 78, RtlDosPathNameToNtPathNameU = 79, RtlFreeUnicodeString = 80, RtlGetAce = 81, RtlGetControlSecurityDescriptor = 82, RtlIsTextUnicode = 83, RtlLengthSecurityDescriptor = 84, RtlMakeSelfRelativeSD = 85, RtlNtStatusToDosError = 86, RtlQueryInformationAcl = 87, RtlSelfRelativeToAbsoluteSD = 88, RtlUniform = 89, RtlDeleteCriticalSection = 90, RtlEnterCriticalSection = 91, RtlLeaveCriticalSection = 92, Vsnprintf = 93,
    RtlSizeHeap = 94,
    WineGetHostVersion = 199, RtlInterlockedFlushSList = 200, RtlInterlockedPushEntrySList = 201, RtlTryEnterCriticalSection = 202, RtlAreBitsClear = 203, RtlAreBitsSet = 204, RtlInitializeBitMap = 205, RtlLookupFunctionEntry = 206, RtlPcToFileHeader = 207, RtlSetBits = 208, RtlTimeToSecondsSince1970 = 209, RtlUnwindEx = 210, Setjmp = 211, Setjmpex = 212, Longjmp = 213, WineDbgGetChannelFlags = 214, LdrGetDllFullName = 215, LdrLoadDll = 216, LdrQueryImageFileExecutionOptions = 217, CallbackReturn = 218, OpenDirectoryObject = 219, RtlFindActivationContextSectionString = 220, RtlImageDirectoryEntryToData = 221, RtlImageRvaToVa = 222, RtlInitializeNtUserPfn = 223, RtlMultiByteToUnicodeN = 224, RtlMultiByteToUnicodeSize = 225, RtlRetrieveNtUserPfn = 226, RtlResetNtUserPfn = 227, ApiSetQueryApiSetPresenceEx = 228,
    RtlExitUserThread = 95,
    RtlQueryUnbiasedInterruptTime = 96,
    DbgUiGetThreadDebugObject = 97,
    DbgUiIssueRemoteBreakin = 98,
    LdrGetDllDirectory = 99,
    LdrGetProcedureAddress = 100,
    LdrSetDllDirectory = 101,
    AddAtom = 102,
    AssignProcessToJobObject = 103, CreateJobObject = 104, CreateMailslotFile = 105, DeleteAtom = 106, DeviceIoControlFile = 107, FindAtom = 108, FsControlFile = 109, OpenJobObject = 110, PowerInformation = 111, QueryInformationAtom = 112, QueryInformationJobObject = 113, QuerySection = 114, QuerySystemInformation = 115, QuerySystemTime = 116, SetInformationDebugObject = 117, SetInformationJobObject = 118, SetInformationProcess = 119, SetInformationThread = 120, SetThreadExecutionState = 121, TerminateJobObject = 122, RtlAcquirePebLock = 123, RtlReleasePebLock = 124, RtlAddAtomToAtomTable = 125, RtlAnsiStringToUnicodeString = 126,
    RtlCaptureContext = 127, RtlCharToInteger = 128, RtlCreateAtomTable = 129, RtlCreateHeap = 130, RtlCreateUnicodeString = 131, RtlDeleteAtomFromAtomTable = 132, RtlDeregisterWait = 133, RtlDestroyAtomTable = 134, RtlDestroyHeap = 135, RtlDetermineDosPathNameTypeU = 136, RtlDosPathNameToNtPathNameUWithStatus = 137, RtlExitUserProcess = 138, RtlGetProcessHeaps = 139, RtlGetUserInfoHeap = 140, RtlImageNtHeader = 141, RtlInitializeCriticalSection = 142, RtlInitializeCriticalSectionAndSpinCount = 143, RtlInitializeCriticalSectionEx = 144, RtlIsNameLegalDOS8Dot3 = 145, RtlLockHeap = 146, RtlUnlockHeap = 147, RtlLookupAtomInAtomTable = 148, RtlOemStringToUnicodeString = 149, RtlQueryAtomInAtomTable = 150, RtlRegisterWait = 151, RtlRestoreContext = 152, RtlSetIoCompletionCallback = 153, RtlGetLastWin32Error = 154, RtlRestoreLastWin32Error = 155, RtlSetLastWin32Error = 156, RtlSetSearchPathMode = 157, RtlSetUnhandledExceptionFilter = 158, RtlSetUserValueHeap = 159, RtlTimeFieldsToTime = 160, RtlTimeToTimeFields = 161, RtlUnicodeStringToAnsiSize = 162, RtlUnicodeStringToAnsiString = 163, RtlUnicodeStringToInteger = 164, RtlUnicodeStringToOemSize = 165, RtlUnicodeStringToOemString = 166, RtlUnicodeToMultiByteN = 167, RtlUnicodeToMultiByteSize = 168, RtlUnicodeToOemN = 169, RtlUpcaseUnicodeString = 170, RtlUpperChar = 171, Wcsicmp = 172, Wcsnicmp = 173, Isalpha = 174, Islower = 175, Memcpy = 176, Memmove = 177, Memset = 178, Strcat = 179, Strchr = 180, Strcpy = 181, Strlen = 182, Strpbrk = 183, Strrchr = 184, Tolower = 185, Wcscat = 186, Wcschr = 187, Wcscmp = 188, Wcscpy = 189, Wcslen = 190, Wcsncmp = 191, Wcsrchr = 192, Wcstoul = 193, WineDbgHeader = 194, WineDbgOutput = 195, WineDbgStrdup = 196, RtlGUIDFromString = 197, RtlRandom = 198, DbgUiConnectToDbg = 229, DbgUiContinue = 230, DbgUiRemoteBreakin = 231, DbgUiStopDebugging = 232, DbgUiWaitStateChange = 233, DbgUiConvertStateChangeStructure = 234, DbgUiDebugActiveProcess = 235,
}
impl NtService {
    /// Return the tagged entry selector emitted by an NTDLL syscall stub.
    /// # C: O(1)
    pub const fn entry(self) -> u64 { NT_SERVICE_NAMESPACE | self as u64 }
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtCall { pub service: NtService, pub args: SyscallArgs }
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NtMemoryCall {
    Allocate { process: u64, base: UserPtr<u64>, zero_bits: u64, size: UserPtr<u64>, allocation_type: u32, protect: u32 },
    Free { process: u64, base: UserPtr<u64>, size: UserPtr<u64>, free_type: u32 },
    Protect { process: u64, base: UserPtr<u64>, size: UserPtr<u64>, protect: u32, old_protect: UserPtr<u32> },
    Query { process: u64, address: u64, info_class: u32, info: UserPtr<u8>, info_size: u64, return_length: UserPtr<u64> },
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NtHeapCall {
    Allocate { heap: u64, flags: u64, size: u64 },
    Free { heap: u64, flags: u64, base: u64 },
    Reallocate { heap: u64, flags: u64, base: u64, size: u64 },
    Size { heap: u64, flags: u64, base: u64 },
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtSystemCall { pub class: u32, pub info: UserPtr<u8>, pub length: u32, pub return_length: Option<UserPtr<u32>> }
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtWindowMessage { pub hwnd: u64, pub message: u32, pub padding: u32, pub wparam: u64, pub lparam: i64 }
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NtWindowCall {
    Create { parent: u64, wndproc: u64 },
    Destroy { hwnd: u64 },
    Post { hwnd: u64, message: u32, wparam: u64, lparam: i64 },
    Peek { message: UserPtr<NtWindowMessage>, hwnd: u64, first: u32, last: u32, remove: u32 },
    Get { message: UserPtr<NtWindowMessage>, hwnd: u64, first: u32, last: u32 },
    DefaultProc { hwnd: u64, message: u32, wparam: u64, lparam: i64 },
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NtLoaderCall { ResolveDelayLoadedApi { args: [u64; 6] }, ExecuteWithCatalog { request: UserPtr<crate::nt_exec::NtExecRequest> } }
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NtObjectCall {
    CreateEvent { handle: UserPtr<u32>, desired_access: u32, event_type: u32, initial_state: u32 },
    CreateJob { handle: UserPtr<u32>, desired_access: u32, attributes: u64 },
    AssignProcessToJobObject { job: u64, process: u64 }, TerminateJobObject { job: u64, status: u64 },
    CreateSemaphore { handle: UserPtr<u32>, desired_access: u32, attributes: u64, initial: i64, maximum: i64 },
    ReleaseSemaphore { handle: u32, count: u32, previous: Option<UserPtr<i32>> },
    CreateMutant { handle: UserPtr<u32>, desired_access: u32, attributes: u64, initial_owner: u32 },
    ReleaseMutant { handle: u32, previous: Option<UserPtr<i32>> },
    QueryMutant { handle: u32, class: u32, info: UserPtr<u8>, length: u32, return_length: Option<UserPtr<u32>> },
    Close { handle: u32 },
    SetEvent { handle: u32, previous: Option<UserPtr<i32>> },
    ResetEvent { handle: u32, previous: Option<UserPtr<i32>> },
    WaitEvent { handle: u32, alertable: u32, timeout: Option<UserPtr<i64>> },
    WaitMultiple { count: u32, handles: UserPtr<u32>, wait_type: u32, alertable: u32, timeout: Option<UserPtr<i64>> },
    CreateSection { handle: UserPtr<u32>, desired_access: u32, size: u64, protect: u32, attributes: u32, file: u32 },
    MapViewOfSection { section: u32, process: u64, base: UserPtr<u64>, offset: u64, size: UserPtr<u64>, protect: u32 },
    UnmapViewOfSection { process: u64, base: u64 },
    QuerySection { section: u32, class: u32, info: UserPtr<u8>, length: u32, return_length: Option<UserPtr<u64>> },
    QueryProcess { process: u64, class: u32, info: UserPtr<u8>, length: u32, return_length: Option<UserPtr<u32>> },
    CreateThreadEx { handle: UserPtr<u32>, process: u64, start: u64, parameter: u64, stack_size: u64, flags: u32 },
    TerminateThread { thread: u64, status: u64 },
    QueryThread { thread: u64, class: u32, info: UserPtr<u8>, length: u32, return_length: Option<UserPtr<u32>> },
    DuplicateObject { request: UserPtr<NtDuplicateObjectRequest> },
    CreateTimer { handle: UserPtr<u32>, desired_access: u32, timer_type: u32 },
    SetTimer { handle: u32, due_time: i64, period_ms: u32 },
    CancelTimer { handle: u32, previous: Option<UserPtr<u32>> },
    CreateIoCompletion { handle: UserPtr<u32>, desired_access: u32, concurrency: u32 },
    SetIoCompletion { request: UserPtr<NtCompletionPacket> },
    RemoveIoCompletion { request: UserPtr<NtRemoveIoCompletionRequest> },
    SignalAndWait { signal: u32, wait: u32, alertable: u32, timeout: Option<UserPtr<i64>> },
    OpenProcessToken { process: u64, desired_access: u32, handle: UserPtr<u32> },
    OpenThreadToken { thread: u64, desired_access: u32, open_as_self: u32, handle: UserPtr<u32> },
    QueryToken { token: u32, class: u32, info: UserPtr<u8>, length: u32, return_length: Option<UserPtr<u32>> },
    QueryObject { handle: u32, class: u32, info: UserPtr<u8>, length: u32, return_length: Option<UserPtr<u32>> },
    QuerySecurity { handle: u32, security_information: u32, descriptor: UserPtr<u8>, length: u32, return_length: Option<UserPtr<u32>> },
    SetSecurity { handle: u32, security_information: u32, descriptor: UserPtr<u8> },
}
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtCompletionPacket {
    pub handle: u32,
    pub padding: u32,
    pub key: u64,
    pub overlapped: u64,
    pub status: u32,
    pub status_padding: u32,
    pub information: u64,
}
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtRemoveIoCompletionRequest {
    pub handle: u32,
    pub padding: u32,
    pub key: u64,
    pub overlapped: u64,
    pub status: u64,
    pub information: u64,
    pub timeout: i64,
}
/// x86-64 request records used by tagged NT file services; pointer words remain integers until adapter validation.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtCreateFileRequest {
    pub handle: u64,
    pub desired_access: u32,
    pub object_attributes: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    pub share_access: u32,
    pub disposition: u32,
    pub options: u32,
}
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtOpenFileRequest {
    pub handle: u64,
    pub desired_access: u32,
    pub object_attributes: u64,
    pub share_access: u32,
    pub options: u32,
}
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtFileIoRequest {
    pub handle: u32,
    pub event: u32,
    pub io_status: u64,
    pub buffer: u64,
    pub length: u32,
    pub offset: u64,
}
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtFileInformationRequest {
    pub handle: u32,
    pub io_status: u64,
    pub information: u64,
    pub length: u32,
    pub information_class: u32,
}
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtLockFileRequest {
    pub handle: u32,
    pub flags: u32,
    pub io_status: u64,
    pub offset: u64,
    pub length: u64,
}
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtUnlockFileRequest {
    pub handle: u32,
    pub padding: u32,
    pub io_status: u64,
    pub offset: u64,
    pub length: u64,
}
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtDuplicateObjectRequest {
    pub source_process: u64,
    pub source: u32,
    pub source_padding: u32,
    pub target_process: u64,
    pub target: u64,
    pub desired_access: u32,
    pub attributes: u32,
    pub options: u32,
    pub options_padding: u32,
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NtFileCall {
    Create { request: UserPtr<NtCreateFileRequest> },
    Open { request: UserPtr<NtOpenFileRequest> },
    Read { request: UserPtr<NtFileIoRequest> },
    Write { request: UserPtr<NtFileIoRequest> },
    QueryInformation { request: UserPtr<NtFileInformationRequest> },
    SetInformation { request: UserPtr<NtFileInformationRequest> },
    QueryDirectory { request: UserPtr<NtFileInformationRequest> },
    Lock { request: UserPtr<NtLockFileRequest> },
    Unlock { request: UserPtr<NtUnlockFileRequest> },
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NtTimeout {
    Relative100ns(u64),
    Absolute100ns(u64),
}
/// Decode signed NT timeout encoding without consulting a clock; negative values are relative and positive values absolute. # C: O(1)
pub fn decode_timeout(raw: i64) -> Result<NtTimeout, Errno> {
    if raw <= 0 {
        let ticks = raw.checked_neg().ok_or(Errno::Einval)? as u64;
        Ok(NtTimeout::Relative100ns(ticks))
    } else {
        Ok(NtTimeout::Absolute100ns(raw as u64))
    }
}
/// Decode an oxide NT service selector and preserve its six arguments. # C: O(1)
pub fn decode(service: u32, args: SyscallArgs) -> Option<NtCall> {
    if service == 196 { return Some(NtCall { service: NtService::WineDbgStrdup, args }); }
    if service == 198 { return Some(NtCall { service: NtService::RtlRandom, args }); }
    if service == 199 { return Some(NtCall { service: NtService::WineGetHostVersion, args }); }
    if service == 200 { return Some(NtCall { service: NtService::RtlInterlockedFlushSList, args }); }
    if service == 201 { return Some(NtCall { service: NtService::RtlInterlockedPushEntrySList, args }); }
    if service == 202 { return Some(NtCall { service: NtService::RtlTryEnterCriticalSection, args }); }
    if service == 203 { return Some(NtCall { service: NtService::RtlAreBitsClear, args }); }
    if service == 204 { return Some(NtCall { service: NtService::RtlAreBitsSet, args }); }
    if service == 205 { return Some(NtCall { service: NtService::RtlInitializeBitMap, args }); }
    if service == 206 { return Some(NtCall { service: NtService::RtlLookupFunctionEntry, args }); }
    if service == 207 { return Some(NtCall { service: NtService::RtlPcToFileHeader, args }); }
    if service == 208 { return Some(NtCall { service: NtService::RtlSetBits, args }); }
    if service == 209 { return Some(NtCall { service: NtService::RtlTimeToSecondsSince1970, args }); }
    if service == 210 { return Some(NtCall { service: NtService::RtlUnwindEx, args }); }
    if service == 211 { return Some(NtCall { service: NtService::Setjmp, args }); }
    if service == 212 { return Some(NtCall { service: NtService::Setjmpex, args }); }
    if service == 213 { return Some(NtCall { service: NtService::Longjmp, args }); }
    if service == 214 { return Some(NtCall { service: NtService::WineDbgGetChannelFlags, args }); }
    if service == 215 { return Some(NtCall { service: NtService::LdrGetDllFullName, args }); }
    if service == 216 { return Some(NtCall { service: NtService::LdrLoadDll, args }); }
    if service == 217 { return Some(NtCall { service: NtService::LdrQueryImageFileExecutionOptions, args }); }
    if service == 218 { return Some(NtCall { service: NtService::CallbackReturn, args }); }
    if service == 219 { return Some(NtCall { service: NtService::OpenDirectoryObject, args }); }
    if service == 220 { return Some(NtCall { service: NtService::RtlFindActivationContextSectionString, args }); }
    if service == 221 { return Some(NtCall { service: NtService::RtlImageDirectoryEntryToData, args }); }
    if service == 222 { return Some(NtCall { service: NtService::RtlImageRvaToVa, args }); }
    if service == 223 { return Some(NtCall { service: NtService::RtlInitializeNtUserPfn, args }); }
    if service == 224 { return Some(NtCall { service: NtService::RtlMultiByteToUnicodeN, args }); }
    if service == 225 { return Some(NtCall { service: NtService::RtlMultiByteToUnicodeSize, args }); }
    if service == 226 { return Some(NtCall { service: NtService::RtlRetrieveNtUserPfn, args }); }
    if service == 227 { return Some(NtCall { service: NtService::RtlResetNtUserPfn, args }); }
    if service == 228 { return Some(NtCall { service: NtService::ApiSetQueryApiSetPresenceEx, args }); }
    if service == 229 { return Some(NtCall { service: NtService::DbgUiConnectToDbg, args }); }
    if service == 230 { return Some(NtCall { service: NtService::DbgUiContinue, args }); }
    if service == 231 { return Some(NtCall { service: NtService::DbgUiRemoteBreakin, args }); }
    if service == 232 { return Some(NtCall { service: NtService::DbgUiStopDebugging, args }); }
    if service == 233 { return Some(NtCall { service: NtService::DbgUiWaitStateChange, args }); }
    if service == 234 { return Some(NtCall { service: NtService::DbgUiConvertStateChangeStructure, args }); }
    if service == 235 { return Some(NtCall { service: NtService::DbgUiDebugActiveProcess, args }); }
    if service == 197 { return Some(NtCall { service: NtService::RtlGUIDFromString, args }); }
    if service == 195 { return Some(NtCall { service: NtService::WineDbgOutput, args }); }
    if service == 194 { return Some(NtCall { service: NtService::WineDbgHeader, args }); }
    if service == 193 { return Some(NtCall { service: NtService::Wcstoul, args }); }
    if service == 192 { return Some(NtCall { service: NtService::Wcsrchr, args }); }
    if service == 191 { return Some(NtCall { service: NtService::Wcsncmp, args }); }
    if service == 190 { return Some(NtCall { service: NtService::Wcslen, args }); }
    if service == 189 { return Some(NtCall { service: NtService::Wcscpy, args }); }
    let service = match service {
        0 => NtService::AllocateVirtualMemory,
        1 => NtService::FreeVirtualMemory,
        2 => NtService::ProtectVirtualMemory,
        3 => NtService::QueryVirtualMemory,
        4 => NtService::TerminateProcess,
        5 => NtService::CreateEvent,
        6 => NtService::Close,
        7 => NtService::SetEvent,
        8 => NtService::ResetEvent,
        9 => NtService::WaitForSingleObject,
        10 => NtService::CreateFile,
        11 => NtService::OpenFile,
        12 => NtService::ReadFile,
        13 => NtService::WriteFile,
        14 => NtService::QueryInformationFile,
        15 => NtService::SetInformationFile,
        16 => NtService::QueryDirectoryFile,
        17 => NtService::WaitForMultipleObjects,
        18 => NtService::CreateSection,
        19 => NtService::MapViewOfSection,
        20 => NtService::UnmapViewOfSection,
        21 => NtService::QueryInformationProcess,
        22 => NtService::CreateThreadEx,
        23 => NtService::TerminateThread,
        24 => NtService::QueryInformationThread,
        25 => NtService::AllocateHeap,
        26 => NtService::FreeHeap,
        27 => NtService::CreateWindow,
        28 => NtService::DestroyWindow,
        29 => NtService::PostMessage,
        30 => NtService::PeekMessage,
        31 => NtService::GetMessage, 32 => NtService::DefaultWindowProc, 33 => NtService::ReallocateHeap, 34 => NtService::ResolveDelayLoadedApi, 35 => NtService::RtlUnwind, 36 => NtService::CreateSemaphore, 37 => NtService::ReleaseSemaphore, 38 => NtService::ExecuteWithCatalog, 39 => NtService::CreateMutant, 40 => NtService::ReleaseMutant, 41 => NtService::QueryMutant, 42 => NtService::CreateKey, 43 => NtService::OpenKey, 44 => NtService::QueryValueKey, 45 => NtService::SetValueKey, 46 => NtService::LockFile, 47 => NtService::UnlockFile, 48 => NtService::DuplicateObject, 49 => NtService::CreateTimer, 50 => NtService::SetTimer, 51 => NtService::CancelTimer, 52 => NtService::CreateIoCompletion, 53 => NtService::SetIoCompletion, 54 => NtService::RemoveIoCompletion, 55 => NtService::SignalAndWait, 56 => NtService::OpenProcessToken, 57 => NtService::OpenThreadToken, 58 => NtService::QueryToken, 59 => NtService::RtlInitUnicodeString, 60 => NtService::RtlInitUnicodeStringEx, 61 => NtService::QueryObject, 62 => NtService::RtlInitAnsiString, 63 => NtService::RtlInitAnsiStringEx, 64 => NtService::QuerySecurityObject, 65 => NtService::RtlQueryPerformanceCounter, 66 => NtService::RtlQueryPerformanceFrequency, 67 => NtService::RenameKey, 68 => NtService::SetSecurityObject,
        69 => NtService::RtlAddAccessAllowedAce,
        70 => NtService::RtlAddAccessAllowedAceEx,
        71 => NtService::RtlAddAccessDeniedAce,
        72 => NtService::RtlAddAccessDeniedAceEx,
        73 => NtService::RtlAddAce,
        74 => NtService::RtlAddAuditAccessAce,
        75 => NtService::RtlAddAuditAccessAceEx,
        76 => NtService::RtlCreateAcl,
        77 => NtService::RtlCreateSecurityDescriptor,
        78 => NtService::RtlCreateUnicodeStringFromAsciiz,
        79 => NtService::RtlDosPathNameToNtPathNameU,
        80 => NtService::RtlFreeUnicodeString,
        81 => NtService::RtlGetAce,
        82 => NtService::RtlGetControlSecurityDescriptor,
        83 => NtService::RtlIsTextUnicode,
        84 => NtService::RtlLengthSecurityDescriptor,
        85 => NtService::RtlMakeSelfRelativeSD,
        86 => NtService::RtlNtStatusToDosError,
        87 => NtService::RtlQueryInformationAcl,
        88 => NtService::RtlSelfRelativeToAbsoluteSD,
        89 => NtService::RtlUniform,
        90 => NtService::RtlDeleteCriticalSection,
        91 => NtService::RtlEnterCriticalSection,
        92 => NtService::RtlLeaveCriticalSection,
        93 => NtService::Vsnprintf,
        94 => NtService::RtlSizeHeap,
        95 => NtService::RtlExitUserThread,
        96 => NtService::RtlQueryUnbiasedInterruptTime,
        97 => NtService::DbgUiGetThreadDebugObject,
        98 => NtService::DbgUiIssueRemoteBreakin,
        99 => NtService::LdrGetDllDirectory,
        100 => NtService::LdrGetProcedureAddress,
        101 => NtService::LdrSetDllDirectory,
        102 => NtService::AddAtom,
        103 => NtService::AssignProcessToJobObject,
        104 => NtService::CreateJobObject,
        105 => NtService::CreateMailslotFile,
        106 => NtService::DeleteAtom,
        107 => NtService::DeviceIoControlFile,
        108 => NtService::FindAtom,
        109 => NtService::FsControlFile,
        110 => NtService::OpenJobObject,
        111 => NtService::PowerInformation,
        112 => NtService::QueryInformationAtom,
        113 => NtService::QueryInformationJobObject,
        114 => NtService::QuerySection,
        115 => NtService::QuerySystemInformation,
        116 => NtService::QuerySystemTime,
        117 => NtService::SetInformationDebugObject,
        118 => NtService::SetInformationJobObject,
        119 => NtService::SetInformationProcess,
        120 => NtService::SetInformationThread,
        121 => NtService::SetThreadExecutionState, 122 => NtService::TerminateJobObject,
        123 => NtService::RtlAcquirePebLock, 124 => NtService::RtlReleasePebLock, 125 => NtService::RtlAddAtomToAtomTable, 126 => NtService::RtlAnsiStringToUnicodeString, 127 => NtService::RtlCaptureContext, 128 => NtService::RtlCharToInteger, 129 => NtService::RtlCreateAtomTable, 130 => NtService::RtlCreateHeap, 131 => NtService::RtlCreateUnicodeString, 132 => NtService::RtlDeleteAtomFromAtomTable, 133 => NtService::RtlDeregisterWait, 134 => NtService::RtlDestroyAtomTable, 135 => NtService::RtlDestroyHeap, 136 => NtService::RtlDetermineDosPathNameTypeU, 137 => NtService::RtlDosPathNameToNtPathNameUWithStatus, 138 => NtService::RtlExitUserProcess, 139 => NtService::RtlGetProcessHeaps, 140 => NtService::RtlGetUserInfoHeap, 141 => NtService::RtlImageNtHeader, 142 => NtService::RtlInitializeCriticalSection, 143 => NtService::RtlInitializeCriticalSectionAndSpinCount, 144 => NtService::RtlInitializeCriticalSectionEx, 145 => NtService::RtlIsNameLegalDOS8Dot3, 146 => NtService::RtlLockHeap, 147 => NtService::RtlUnlockHeap, 148 => NtService::RtlLookupAtomInAtomTable, 149 => NtService::RtlOemStringToUnicodeString, 150 => NtService::RtlQueryAtomInAtomTable, 151 => NtService::RtlRegisterWait, 152 => NtService::RtlRestoreContext, 153 => NtService::RtlSetIoCompletionCallback, 154 => NtService::RtlGetLastWin32Error, 155 => NtService::RtlRestoreLastWin32Error, 156 => NtService::RtlSetLastWin32Error, 157 => NtService::RtlSetSearchPathMode, 158 => NtService::RtlSetUnhandledExceptionFilter, 159 => NtService::RtlSetUserValueHeap, 160 => NtService::RtlTimeFieldsToTime, 161 => NtService::RtlTimeToTimeFields, 162 => NtService::RtlUnicodeStringToAnsiSize, 163 => NtService::RtlUnicodeStringToAnsiString, 164 => NtService::RtlUnicodeStringToInteger, 165 => NtService::RtlUnicodeStringToOemSize, 166 => NtService::RtlUnicodeStringToOemString, 167 => NtService::RtlUnicodeToMultiByteN, 168 => NtService::RtlUnicodeToMultiByteSize, 169 => NtService::RtlUnicodeToOemN, 170 => NtService::RtlUpcaseUnicodeString, 171 => NtService::RtlUpperChar, 172 => NtService::Wcsicmp, 173 => NtService::Wcsnicmp, 174 => NtService::Isalpha, 175 => NtService::Islower, 176 => NtService::Memcpy, 177 => NtService::Memmove, 178 => NtService::Memset, 179 => NtService::Strcat, 180 => NtService::Strchr, 181 => NtService::Strcpy, 182 => NtService::Strlen, 183 => NtService::Strpbrk, 184 => NtService::Strrchr, 185 => NtService::Tolower, 186 => NtService::Wcscat, 187 => NtService::Wcschr, 188 => NtService::Wcscmp,
        _ => return None,
    };
    Some(NtCall { service, args })
}
/// Decode the tagged NT entry word used by the personality boundary. # C: O(1)
pub fn decode_entry(entry: u64, args: SyscallArgs) -> Option<NtCall> {
    if entry >> 32 != NT_SERVICE_NAMESPACE >> 32 { return None; }
    decode(entry as u32, args)
}
/// Validate pointer-bearing argument shapes for the initial memory services. # C: O(1)
pub fn decode_memory(call: NtCall) -> Result<NtMemoryCall, Errno> {
    let a = call.args;
    match call.service {
        NtService::AllocateVirtualMemory => Ok(NtMemoryCall::Allocate {
            process: a.a0, base: UserPtr::new(a.a1)?, zero_bits: a.a2,
            size: UserPtr::new(a.a3)?, allocation_type: a.a4 as u32, protect: a.a5 as u32,
        }),
        NtService::FreeVirtualMemory => Ok(NtMemoryCall::Free {
            process: a.a0, base: UserPtr::new(a.a1)?, size: UserPtr::new(a.a2)?, free_type: a.a3 as u32,
        }),
        NtService::ProtectVirtualMemory => Ok(NtMemoryCall::Protect {
            process: a.a0, base: UserPtr::new(a.a1)?, size: UserPtr::new(a.a2)?,
            protect: a.a3 as u32, old_protect: UserPtr::new(a.a4)?,
        }),
        NtService::QueryVirtualMemory => Ok(NtMemoryCall::Query {
            process: a.a0, address: a.a1, info_class: a.a2 as u32, info: UserPtr::new(a.a3)?,
            info_size: a.a4, return_length: UserPtr::new(a.a5)?,
        }),
        NtService::TerminateProcess => Err(Errno::Enosys),
        NtService::Wcscat => Err(Errno::Enosys),
        NtService::Wcschr => Err(Errno::Enosys),
        NtService::Wcscmp => Err(Errno::Enosys),
        NtService::Wcscpy => Err(Errno::Enosys),
        NtService::Wcslen => Err(Errno::Enosys),
        NtService::Wcsncmp => Err(Errno::Enosys),
        NtService::Wcsrchr => Err(Errno::Enosys),
        NtService::Wcstoul | NtService::WineDbgHeader | NtService::WineDbgOutput | NtService::WineDbgStrdup | NtService::RtlGUIDFromString | NtService::RtlRandom | NtService::WineGetHostVersion | NtService::RtlInterlockedFlushSList | NtService::RtlInterlockedPushEntrySList | NtService::RtlTryEnterCriticalSection | NtService::RtlAreBitsClear | NtService::RtlAreBitsSet | NtService::RtlInitializeBitMap | NtService::RtlLookupFunctionEntry | NtService::RtlPcToFileHeader | NtService::RtlSetBits | NtService::RtlTimeToSecondsSince1970 | NtService::RtlUnwindEx | NtService::Setjmp | NtService::Setjmpex | NtService::Longjmp | NtService::WineDbgGetChannelFlags | NtService::LdrGetDllFullName | NtService::LdrLoadDll | NtService::LdrQueryImageFileExecutionOptions | NtService::CallbackReturn | NtService::OpenDirectoryObject | NtService::RtlFindActivationContextSectionString | NtService::RtlImageDirectoryEntryToData | NtService::RtlImageRvaToVa | NtService::RtlInitializeNtUserPfn | NtService::RtlMultiByteToUnicodeN | NtService::RtlMultiByteToUnicodeSize | NtService::RtlRetrieveNtUserPfn | NtService::RtlResetNtUserPfn | NtService::ApiSetQueryApiSetPresenceEx | NtService::DbgUiConnectToDbg | NtService::DbgUiContinue | NtService::DbgUiRemoteBreakin | NtService::DbgUiStopDebugging | NtService::DbgUiWaitStateChange | NtService::DbgUiConvertStateChangeStructure | NtService::DbgUiDebugActiveProcess => Err(Errno::Enosys),
        NtService::RtlAddAccessAllowedAce | NtService::RtlAddAccessAllowedAceEx | NtService::RtlAddAccessDeniedAce | NtService::RtlAddAccessDeniedAceEx | NtService::RtlAddAce | NtService::RtlAddAuditAccessAce | NtService::RtlAddAuditAccessAceEx | NtService::RtlCreateAcl | NtService::RtlCreateSecurityDescriptor | NtService::RtlCreateUnicodeStringFromAsciiz | NtService::RtlDosPathNameToNtPathNameU | NtService::RtlFreeUnicodeString | NtService::RtlGetAce | NtService::RtlGetControlSecurityDescriptor | NtService::RtlIsTextUnicode | NtService::RtlLengthSecurityDescriptor | NtService::RtlMakeSelfRelativeSD | NtService::RtlNtStatusToDosError | NtService::RtlQueryInformationAcl | NtService::RtlSelfRelativeToAbsoluteSD | NtService::RtlUniform | NtService::RtlDeleteCriticalSection | NtService::RtlEnterCriticalSection | NtService::RtlLeaveCriticalSection | NtService::Vsnprintf | NtService::RtlSizeHeap | NtService::RtlQueryUnbiasedInterruptTime | NtService::RtlExitUserThread | NtService::DbgUiGetThreadDebugObject | NtService::DbgUiIssueRemoteBreakin | NtService::LdrGetDllDirectory | NtService::LdrGetProcedureAddress | NtService::LdrSetDllDirectory | NtService::AddAtom | NtService::AssignProcessToJobObject | NtService::CreateJobObject | NtService::CreateMailslotFile | NtService::DeleteAtom | NtService::DeviceIoControlFile | NtService::FindAtom | NtService::FsControlFile | NtService::OpenJobObject | NtService::PowerInformation | NtService::QueryInformationAtom | NtService::QueryInformationJobObject | NtService::QuerySection | NtService::QuerySystemInformation | NtService::QuerySystemTime => Err(Errno::Enosys),
        NtService::SetInformationDebugObject | NtService::SetInformationJobObject | NtService::SetInformationProcess | NtService::SetInformationThread | NtService::SetThreadExecutionState | NtService::TerminateJobObject | NtService::RtlAcquirePebLock | NtService::RtlReleasePebLock | NtService::RtlAddAtomToAtomTable | NtService::RtlAnsiStringToUnicodeString | NtService::RtlCaptureContext | NtService::RtlCharToInteger | NtService::RtlCreateAtomTable | NtService::RtlCreateHeap | NtService::RtlCreateUnicodeString | NtService::RtlDeleteAtomFromAtomTable | NtService::RtlDeregisterWait | NtService::RtlDestroyAtomTable | NtService::RtlDestroyHeap | NtService::RtlDetermineDosPathNameTypeU | NtService::RtlDosPathNameToNtPathNameUWithStatus | NtService::RtlExitUserProcess | NtService::RtlGetProcessHeaps | NtService::RtlGetUserInfoHeap | NtService::RtlImageNtHeader | NtService::RtlInitializeCriticalSection | NtService::RtlInitializeCriticalSectionAndSpinCount | NtService::RtlInitializeCriticalSectionEx | NtService::RtlIsNameLegalDOS8Dot3 | NtService::RtlLockHeap | NtService::RtlUnlockHeap | NtService::RtlLookupAtomInAtomTable | NtService::RtlOemStringToUnicodeString | NtService::RtlQueryAtomInAtomTable | NtService::RtlRegisterWait | NtService::RtlRestoreContext | NtService::RtlSetIoCompletionCallback | NtService::RtlGetLastWin32Error | NtService::RtlRestoreLastWin32Error | NtService::RtlSetLastWin32Error | NtService::RtlSetSearchPathMode | NtService::RtlSetUnhandledExceptionFilter | NtService::RtlSetUserValueHeap | NtService::RtlTimeFieldsToTime | NtService::RtlTimeToTimeFields | NtService::RtlUnicodeStringToAnsiSize | NtService::RtlUnicodeStringToAnsiString | NtService::RtlUnicodeStringToInteger | NtService::RtlUnicodeStringToOemSize | NtService::RtlUnicodeStringToOemString | NtService::RtlUnicodeToMultiByteN | NtService::RtlUnicodeToMultiByteSize | NtService::RtlUnicodeToOemN | NtService::RtlUpcaseUnicodeString | NtService::RtlUpperChar | NtService::Wcsicmp | NtService::Wcsnicmp | NtService::Isalpha | NtService::Islower | NtService::Memcpy | NtService::Memmove | NtService::Memset | NtService::Strcat | NtService::Strchr | NtService::Strcpy | NtService::Strlen | NtService::Strpbrk | NtService::Strrchr | NtService::Tolower => Err(Errno::Enosys),
        NtService::CreateEvent | NtService::Close | NtService::SetEvent | NtService::ResetEvent
        | NtService::WaitForSingleObject | NtService::WaitForMultipleObjects | NtService::CreateFile | NtService::OpenFile
        | NtService::ReadFile | NtService::WriteFile | NtService::QueryInformationFile
        | NtService::SetInformationFile | NtService::QueryDirectoryFile
        | NtService::CreateSection | NtService::MapViewOfSection | NtService::UnmapViewOfSection
        | NtService::QueryInformationProcess | NtService::CreateThreadEx
        | NtService::TerminateThread | NtService::QueryInformationThread
        | NtService::AllocateHeap | NtService::FreeHeap | NtService::CreateWindow
        | NtService::DestroyWindow | NtService::PostMessage | NtService::PeekMessage
        | NtService::GetMessage | NtService::DefaultWindowProc | NtService::ReallocateHeap | NtService::ResolveDelayLoadedApi | NtService::RtlUnwind
        | NtService::CreateSemaphore | NtService::ReleaseSemaphore | NtService::ExecuteWithCatalog
        | NtService::CreateMutant | NtService::ReleaseMutant | NtService::QueryMutant
        | NtService::CreateKey | NtService::OpenKey | NtService::QueryValueKey | NtService::SetValueKey
        | NtService::LockFile | NtService::UnlockFile | NtService::DuplicateObject
        | NtService::CreateTimer | NtService::SetTimer | NtService::CancelTimer
        | NtService::CreateIoCompletion | NtService::SetIoCompletion | NtService::RemoveIoCompletion
        | NtService::SignalAndWait | NtService::OpenProcessToken | NtService::OpenThreadToken | NtService::QueryToken | NtService::RtlInitUnicodeString | NtService::RtlInitUnicodeStringEx | NtService::QueryObject | NtService::RtlInitAnsiString | NtService::RtlInitAnsiStringEx | NtService::QuerySecurityObject | NtService::RtlQueryPerformanceCounter | NtService::RtlQueryPerformanceFrequency | NtService::RenameKey | NtService::SetSecurityObject => Err(Errno::Enosys),
    }
}
pub fn decode_system(call: NtCall) -> Result<NtSystemCall, Errno> {
    if call.service != NtService::QuerySystemInformation { return Err(Errno::Enosys); }
    Ok(NtSystemCall { class: call.args.a0 as u32, info: UserPtr::new(call.args.a1)?, length: call.args.a2 as u32, return_length: optional_ptr(call.args.a3)? })
}
pub fn decode_heap(call: NtCall) -> Result<NtHeapCall, Errno> {
    match call.service {
        NtService::AllocateHeap => Ok(NtHeapCall::Allocate { heap: call.args.a0, flags: call.args.a1, size: call.args.a2 }),
        NtService::FreeHeap => Ok(NtHeapCall::Free { heap: call.args.a0, flags: call.args.a1, base: call.args.a2 }),
        NtService::ReallocateHeap => Ok(NtHeapCall::Reallocate { heap: call.args.a0, flags: call.args.a1, base: call.args.a2, size: call.args.a3 }),
        NtService::RtlSizeHeap => Ok(NtHeapCall::Size { heap: call.args.a0, flags: call.args.a1, base: call.args.a2 }),
        _ => Err(Errno::Enosys),
    }
}
pub fn decode_loader(call: NtCall) -> Result<NtLoaderCall, Errno> {
    match call.service {
        NtService::ResolveDelayLoadedApi => Ok(NtLoaderCall::ResolveDelayLoadedApi { args: [call.args.a0, call.args.a1, call.args.a2, call.args.a3, call.args.a4, call.args.a5] }),
        NtService::ExecuteWithCatalog => Ok(NtLoaderCall::ExecuteWithCatalog { request: UserPtr::new(call.args.a0)? }),
        _ => Err(Errno::Enosys),
    }
}
pub fn decode_window(call: NtCall) -> Result<NtWindowCall, Errno> {
    let a = call.args;
    match call.service {
        NtService::CreateWindow => Ok(NtWindowCall::Create { parent: a.a0, wndproc: a.a1 }),
        NtService::DestroyWindow => Ok(NtWindowCall::Destroy { hwnd: a.a0 }),
        NtService::PostMessage => Ok(NtWindowCall::Post { hwnd: a.a0, message: a.a1 as u32, wparam: a.a2, lparam: a.a3 as i64 }),
        NtService::PeekMessage => Ok(NtWindowCall::Peek { message: UserPtr::new(a.a0)?, hwnd: a.a1, first: a.a2 as u32, last: a.a3 as u32, remove: a.a4 as u32 }),
        NtService::GetMessage => Ok(NtWindowCall::Get { message: UserPtr::new(a.a0)?, hwnd: a.a1, first: a.a2 as u32, last: a.a3 as u32 }),
        NtService::DefaultWindowProc => Ok(NtWindowCall::DefaultProc { hwnd: a.a0, message: a.a1 as u32, wparam: a.a2, lparam: a.a3 as i64 }),
        _ => Err(Errno::Enosys),
    }
}

/// Validate the outer pointer for an NT file request record. Nested pointers are validated after the record is copied. # C: O(1)
pub fn decode_file(call: NtCall) -> Result<NtFileCall, Errno> {
    let a = call.args;
    match call.service {
        NtService::CreateFile => Ok(NtFileCall::Create { request: UserPtr::new(a.a0)? }),
        NtService::OpenFile => Ok(NtFileCall::Open { request: UserPtr::new(a.a0)? }),
        NtService::ReadFile => Ok(NtFileCall::Read { request: UserPtr::new(a.a0)? }),
        NtService::WriteFile => Ok(NtFileCall::Write { request: UserPtr::new(a.a0)? }),
        NtService::QueryInformationFile => Ok(NtFileCall::QueryInformation { request: UserPtr::new(a.a0)? }),
        NtService::SetInformationFile => Ok(NtFileCall::SetInformation { request: UserPtr::new(a.a0)? }),
        NtService::QueryDirectoryFile => Ok(NtFileCall::QueryDirectory { request: UserPtr::new(a.a0)? }),
        NtService::LockFile => Ok(NtFileCall::Lock { request: UserPtr::new(a.a0)? }),
        NtService::UnlockFile => Ok(NtFileCall::Unlock { request: UserPtr::new(a.a0)? }),
        _ => Err(Errno::Enosys),
    }
}

/// Validate the register shape for an event-object service. # C: O(1)
pub fn decode_object(call: NtCall) -> Result<NtObjectCall, Errno> {
    let a = call.args;
    match call.service {
        NtService::CreateEvent => Ok(NtObjectCall::CreateEvent {
            handle: UserPtr::new(a.a0)?, desired_access: a.a1 as u32,
            event_type: a.a3 as u32, initial_state: a.a4 as u32,
        }),
        NtService::CreateJobObject => Ok(NtObjectCall::CreateJob { handle: UserPtr::new(a.a0)?, desired_access: a.a1 as u32, attributes: a.a2 }),
        NtService::AssignProcessToJobObject => Ok(NtObjectCall::AssignProcessToJobObject { job: a.a0, process: a.a1 }),
        NtService::TerminateJobObject => Ok(NtObjectCall::TerminateJobObject { job: a.a0, status: a.a1 }),
        NtService::CreateSemaphore => Ok(NtObjectCall::CreateSemaphore {
            handle: UserPtr::new(a.a0)?, desired_access: a.a1 as u32, attributes: a.a2,
            initial: a.a3 as i64, maximum: a.a4 as i64,
        }),
        NtService::ReleaseSemaphore => Ok(NtObjectCall::ReleaseSemaphore {
            handle: a.a0 as u32, count: a.a1 as u32, previous: optional_ptr(a.a2)?,
        }),
        NtService::CreateMutant => Ok(NtObjectCall::CreateMutant {
            handle: UserPtr::new(a.a0)?, desired_access: a.a1 as u32, attributes: a.a2, initial_owner: a.a3 as u32,
        }),
        NtService::ReleaseMutant => Ok(NtObjectCall::ReleaseMutant { handle: a.a0 as u32, previous: optional_ptr(a.a1)? }),
        NtService::QueryMutant => Ok(NtObjectCall::QueryMutant { handle: a.a0 as u32, class: a.a1 as u32, info: UserPtr::new(a.a2)?, length: a.a3 as u32, return_length: optional_ptr(a.a4)? }),
        NtService::Close => Ok(NtObjectCall::Close { handle: a.a0 as u32 }),
        NtService::SetEvent => Ok(NtObjectCall::SetEvent { handle: a.a0 as u32, previous: optional_ptr(a.a1)? }),
        NtService::ResetEvent => Ok(NtObjectCall::ResetEvent { handle: a.a0 as u32, previous: optional_ptr(a.a1)? }),
        NtService::WaitForSingleObject => Ok(NtObjectCall::WaitEvent {
            handle: a.a0 as u32, alertable: a.a1 as u32, timeout: optional_ptr(a.a2)?,
        }),
        NtService::WaitForMultipleObjects => Ok(NtObjectCall::WaitMultiple {
            count: a.a0 as u32, handles: UserPtr::new(a.a1)?, wait_type: a.a2 as u32,
            alertable: a.a3 as u32, timeout: optional_ptr(a.a4)?,
        }),
        NtService::CreateSection => Ok(NtObjectCall::CreateSection {
            handle: UserPtr::new(a.a0)?, desired_access: a.a1 as u32, size: a.a2,
            protect: a.a3 as u32, attributes: a.a4 as u32, file: a.a5 as u32,
        }),
        NtService::MapViewOfSection => Ok(NtObjectCall::MapViewOfSection {
            section: a.a0 as u32, process: a.a1, base: UserPtr::new(a.a2)?, offset: a.a3,
            size: UserPtr::new(a.a4)?, protect: a.a5 as u32,
        }),
        NtService::UnmapViewOfSection => Ok(NtObjectCall::UnmapViewOfSection {
            process: a.a0, base: a.a1,
        }),
        NtService::QuerySection => Ok(NtObjectCall::QuerySection {
            section: a.a0 as u32, class: a.a1 as u32, info: UserPtr::new(a.a2)?,
            length: a.a3 as u32, return_length: optional_ptr(a.a4)?,
        }),
        NtService::QueryInformationProcess => Ok(NtObjectCall::QueryProcess {
            process: a.a0, class: a.a1 as u32, info: UserPtr::new(a.a2)?, length: a.a3 as u32,
            return_length: optional_ptr(a.a4)?,
        }),
        NtService::CreateThreadEx => Ok(NtObjectCall::CreateThreadEx {
            handle: UserPtr::new(a.a0)?, process: a.a1, start: a.a2, parameter: a.a3,
            stack_size: a.a4, flags: a.a5 as u32,
        }),
        NtService::TerminateThread => Ok(NtObjectCall::TerminateThread { thread: a.a0, status: a.a1 }),
        NtService::QueryInformationThread => Ok(NtObjectCall::QueryThread {
            thread: a.a0, class: a.a1 as u32, info: UserPtr::new(a.a2)?, length: a.a3 as u32,
            return_length: optional_ptr(a.a4)?,
        }),
        NtService::DuplicateObject => Ok(NtObjectCall::DuplicateObject { request: UserPtr::new(a.a0)? }),
        NtService::CreateTimer => Ok(NtObjectCall::CreateTimer { handle: UserPtr::new(a.a0)?, desired_access: a.a1 as u32, timer_type: a.a2 as u32 }),
        NtService::SetTimer => Ok(NtObjectCall::SetTimer { handle: a.a0 as u32, due_time: a.a1 as i64, period_ms: a.a2 as u32 }),
        NtService::CancelTimer => Ok(NtObjectCall::CancelTimer { handle: a.a0 as u32, previous: optional_ptr(a.a1)? }),
        NtService::CreateIoCompletion => Ok(NtObjectCall::CreateIoCompletion { handle: UserPtr::new(a.a0)?, desired_access: a.a1 as u32, concurrency: a.a2 as u32 }),
        NtService::SetIoCompletion => Ok(NtObjectCall::SetIoCompletion { request: UserPtr::new(a.a0)? }),
        NtService::RemoveIoCompletion => Ok(NtObjectCall::RemoveIoCompletion { request: UserPtr::new(a.a0)? }),
        NtService::SignalAndWait => Ok(NtObjectCall::SignalAndWait { signal: a.a0 as u32, wait: a.a1 as u32, alertable: a.a2 as u32, timeout: optional_ptr(a.a3)? }),
        NtService::OpenProcessToken => Ok(NtObjectCall::OpenProcessToken { process: a.a0, desired_access: a.a1 as u32, handle: UserPtr::new(a.a2)? }),
        NtService::OpenThreadToken => Ok(NtObjectCall::OpenThreadToken { thread: a.a0, desired_access: a.a1 as u32, open_as_self: a.a2 as u32, handle: UserPtr::new(a.a3)? }),
        NtService::QueryToken => Ok(NtObjectCall::QueryToken { token: a.a0 as u32, class: a.a1 as u32, info: UserPtr::new(a.a2)?, length: a.a3 as u32, return_length: optional_ptr(a.a4)? }),
        NtService::QueryObject => Ok(NtObjectCall::QueryObject { handle: a.a0 as u32, class: a.a1 as u32, info: UserPtr::new(a.a2)?, length: a.a3 as u32, return_length: optional_ptr(a.a4)? }),
        NtService::QuerySecurityObject => Ok(NtObjectCall::QuerySecurity { handle: a.a0 as u32, security_information: a.a1 as u32, descriptor: UserPtr::new(a.a2)?, length: a.a3 as u32, return_length: optional_ptr(a.a4)? }),
        NtService::SetSecurityObject => Ok(NtObjectCall::SetSecurity { handle: a.a0 as u32, security_information: a.a1 as u32, descriptor: UserPtr::new(a.a2)? }),
        _ => Err(Errno::Enosys),
    }
}
fn optional_ptr<T>(raw: u64) -> Result<Option<UserPtr<T>>, Errno> {
    if raw == 0 { Ok(None) } else { UserPtr::new(raw).map(Some) }
}
/// Decode the scalar termination shape; task teardown remains owned by the scheduler adapter. # C: O(1)
pub fn decode_terminate(call: NtCall) -> Result<(u64, u32), Errno> {
    if call.service != NtService::TerminateProcess { return Err(Errno::Enosys); }
    Ok((call.args.a0, call.args.a1 as u32))
}
#[cfg(test)] #[path = "nt/tests.rs"] mod tests;
