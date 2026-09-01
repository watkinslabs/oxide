//! NT personality entry boundary; Linux remains separate.
use syscall::{nt, SyscallArgs}; use syscall::nt::NtCall;
#[cfg(target_os = "oxide-kernel")] use syscall::nt::NtObjectCall;
#[cfg(target_os = "oxide-kernel")]
use syscall::nt::NtMemoryCall;
/// Decode one NT personality entry without making it visible to Linux routes.
/// # C: O(1)
pub fn decode_entry(entry: u64, args: SyscallArgs) -> Option<NtCall> {
    nt::decode_entry(entry, args)
}
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn stack_argument(index: usize) -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        let frame = hal_x86_64::current_pt_regs();
        if frame.is_null() { return None; }
        // SAFETY: this is the active task's syscall frame and rsp names its readable user stack.
        let rsp = unsafe { (*frame).rsp };
        let offset = 0x28u64.checked_add((index.checked_sub(4)? as u64).checked_mul(8)?)?;
        uaccess::get_user_u64(rsp.checked_add(offset)?).ok()
    }
    #[cfg(not(target_arch = "x86_64"))]
    { let _ = index; None }
}
#[cfg(target_os = "oxide-kernel")]
const CURRENT_PROCESS: u64 = u64::MAX;
#[cfg(target_os = "oxide-kernel")]
const CURRENT_THREAD: u64 = u64::MAX - 1;
#[cfg(target_os = "oxide-kernel")]
const MEM_RESERVE: u32 = 0x2000;
#[cfg(target_os = "oxide-kernel")]
const MEM_COMMIT: u32 = 0x1000;
#[cfg(target_os = "oxide-kernel")]
const MEM_RELEASE: u32 = 0x8000;
#[cfg(target_os = "oxide-kernel")]
const MEMORY_BASIC_INFORMATION_CLASS: u32 = 0;
#[cfg(target_os = "oxide-kernel")]
const MEMORY_BASIC_INFORMATION_BYTES: usize = 48;
#[cfg(target_os = "oxide-kernel")]
const STATUS_SUCCESS: u64 = 0;
#[cfg(target_os = "oxide-kernel")]
pub(crate) const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
#[cfg(target_os = "oxide-kernel")]
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
#[cfg(target_os = "oxide-kernel")]
const STATUS_MEMORY_NOT_ALLOCATED: u64 = 0xc000_00a0;
#[cfg(target_os = "oxide-kernel")]
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
#[cfg(target_os = "oxide-kernel")]
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
#[cfg(target_os = "oxide-kernel")]
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
#[cfg(target_os = "oxide-kernel")]
const STATUS_NOT_SAME_OBJECT: u64 = 0xc000_01ac;
const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xc000_0004;
const STATUS_INVALID_INFO_CLASS: u64 = 0xc000_0003;
const STATUS_NO_CALLBACK_ACTIVE: u64 = 0xc000_0258;
#[cfg(target_os = "oxide-kernel")]
const EVENT_ALL_ACCESS: u32 = 0x001f_0003;
#[cfg(target_os = "oxide-kernel")]
const EVENT_MODIFY_STATE: u32 = 0x0002;
#[cfg(target_os = "oxide-kernel")]
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
#[cfg(target_os = "oxide-kernel")]
const STATUS_TIMEOUT: u64 = 0x0000_0102;
#[cfg(target_os = "oxide-kernel")]
const STATUS_ALERTED: u64 = 0x0000_0101;
#[cfg(target_os = "oxide-kernel")]
const STATUS_USER_APC: u64 = 0x0000_00c0;
#[cfg(target_os = "oxide-kernel")]
const STATUS_NOT_MAPPED_DATA: u64 = 0xc000_001d;
#[cfg(target_os = "oxide-kernel")]
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
#[cfg(target_os = "oxide-kernel")]
const NT_CONTEXT_AMD64: u32 = 0x0010_0000;
#[cfg(target_os = "oxide-kernel")]
const NT_CONTEXT_CONTROL: u32 = 0x0000_0001;
#[cfg(target_os = "oxide-kernel")]
const NT_CONTEXT_INTEGER: u32 = 0x0000_0002;
const JOB_OBJECT_ALL_ACCESS: u32 = 0x001f_001f;
const JOB_OBJECT_ASSIGN_PROCESS: u32 = 0x0001;
#[cfg(target_os = "oxide-kernel")]
const JOB_OBJECT_TERMINATE: u32 = 0x0008;
const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
const PROCESS_BASIC_INFORMATION_BYTES: usize = 48;
const THREAD_BASIC_INFORMATION_CLASS: u32 = 0;
const THREAD_BASIC_INFORMATION_BYTES: usize = 48;
const STATUS_WAIT_0: u64 = 0x0000_0100;
const WAIT_MULTIPLE_LIMIT: u32 = 64;
const SECTION_MAX_BYTES: u64 = 1 << 30;
const SECTION_QUERY: u32 = 0x0001;
const SECTION_MAP_READ: u32 = 0x0004;
const SECTION_MAP_WRITE: u32 = 0x0002;
const FILE_READ_DATA: u32 = 0x0001;
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_GENERIC_READ: u32 = 0x0012_0089;
const THREAD_ALL_ACCESS: u32 = 0x001f_03ff;
const THREAD_TERMINATE: u32 = 0x0001;
const THREAD_SUSPEND_RESUME: u32 = 0x0002;
const THREAD_QUERY_INFORMATION: u32 = 0x0040;
const NT_THREAD_DEFAULT_STACK: u64 = 1 << 20;
const NT_THREAD_MAX_STACK: u64 = 64 << 20;
#[cfg(target_os = "oxide-kernel")]
const NT_EPOCH_OFFSET_NS: u64 = 11_644_473_600_000_000_000;
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn wait_deadline(timeout: Option<syscall::UserPtr<i64>>) -> Result<u64, u64> {
    let Some(timeout) = timeout else { return Ok(0); };
    let raw = uaccess::get_user_u64(timeout.as_u64()).map_err(|_| STATUS_INVALID_PARAMETER)? as i64;
    let monotonic = timekeeper::monotonic_ns();
    match nt::decode_timeout(raw).map_err(|_| STATUS_INVALID_PARAMETER)? {
      nt::NtTimeout::Relative100ns(ticks) => {
        let duration = ticks.checked_mul(100).ok_or(STATUS_INVALID_PARAMETER)?;
        return Ok(monotonic.saturating_add(duration));
      }
      nt::NtTimeout::Absolute100ns(ticks) => {
    let nt_ns = ticks.checked_mul(100).ok_or(STATUS_INVALID_PARAMETER)?;
    let realtime_target = match nt_ns.checked_sub(NT_EPOCH_OFFSET_NS) {
        Some(target) => target,
        None => return Ok(monotonic),
    };
    let realtime = timekeeper::realtime_ns();
    Ok(if realtime_target <= realtime { monotonic } else {
        monotonic.saturating_add(realtime_target - realtime)
    })
      }
    }
}
#[cfg(target_os = "oxide-kernel")]
fn resolve_thread_target(cur: &sched::Task, raw: u64,
    table: &sched::nt_object::NtHandleTable, access: u32) -> Result<alloc::sync::Arc<sched::Task>, u64> {
    if raw == CURRENT_THREAD {
        return sched::registry::lookup(cur.tid).ok_or(STATUS_INVALID_HANDLE);
    }
    if raw > u32::MAX as u64 { return Err(STATUS_INVALID_HANDLE); }
    let handle = sched::nt_object::NtHandle::from_raw(raw as u32);
    let Some(object) = table.get(handle, access) else {
        return Err(if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE });
    };
    if object.kind() != sched::nt_object::NtObjectType::Thread { return Err(STATUS_INVALID_HANDLE); }
    object.task().ok_or(STATUS_INVALID_HANDLE)
}
#[cfg(target_os = "oxide-kernel")]
fn compare_objects(cur: &sched::Task, first: u64, second: u64) -> u64 {
    let pseudo_kind = |raw| {
        if raw == CURRENT_PROCESS { Some(sched::nt_object::NtObjectType::Process) }
        else if raw == CURRENT_THREAD { Some(sched::nt_object::NtObjectType::Thread) }
        else { None }
    };
    if let (Some(first_kind), Some(second_kind)) = (pseudo_kind(first), pseudo_kind(second)) {
        return if first_kind == second_kind { STATUS_SUCCESS } else { STATUS_NOT_SAME_OBJECT };
    }
    let table = cur.thread_group.nt_handles();
    let resolve = |raw| {
        if let Some(kind) = pseudo_kind(raw) { return Ok((kind, None)); }
        if raw > u32::MAX as u64 { return Err(STATUS_INVALID_HANDLE); }
        let handle = sched::nt_object::NtHandle::from_raw(raw as u32);
        table.get(handle, 0).map(|object| (object.kind(), Some(object)))
            .ok_or(STATUS_INVALID_HANDLE)
    };
    let (first_kind, first_object) = match resolve(first) { Ok(value) => value, Err(status) => return status };
    let (second_kind, second_object) = match resolve(second) { Ok(value) => value, Err(status) => return status };
    let first_is_pseudo = first_object.is_none();
    match (first_object, second_object) {
        (Some(first), Some(second)) => if alloc::sync::Arc::ptr_eq(&first, &second) { STATUS_SUCCESS } else { STATUS_NOT_SAME_OBJECT },
        (None, Some(object)) | (Some(object), None) => {
            let pseudo = if first_is_pseudo { first_kind } else { second_kind };
            let Some(task) = object.task() else { return STATUS_NOT_SAME_OBJECT; };
            let same = match pseudo {
                sched::nt_object::NtObjectType::Process => object.kind() == pseudo && task.tgid.load(core::sync::atomic::Ordering::Acquire) == cur.tgid.load(core::sync::atomic::Ordering::Acquire),
                sched::nt_object::NtObjectType::Thread => object.kind() == pseudo && task.tid == cur.tid,
                _ => false,
            };
            if same { STATUS_SUCCESS } else { STATUS_NOT_SAME_OBJECT }
        }
        (None, None) => STATUS_NOT_SAME_OBJECT,
    }
}
/// Enter the native NT memory adapter from the tagged personality path.
/// Pointer values are copied only after the ABI shape has been validated;
/// subsystem code receives typed values and never sees Windows registers.
/// # C: O(log N_vmas) plus usercopy
#[cfg(target_os = "oxide-kernel")]
pub fn dispatch(call: NtCall) -> u64 {
    if call.service == syscall::nt::NtService::RtlGetNativeSystemInformation {
        let mut query = call;
        query.service = syscall::nt::NtService::QuerySystemInformation;
        return dispatch(query);
    }
    if let Some(result) = crate::nt_apiset::dispatch(call) { return result; }
    if let Some(result) = crate::nt_actctx::dispatch(call) { return result; }
    if let Some(result) = crate::nt_env::dispatch(call) { return result; }
    if let Some(result) = crate::nt_threadpool::dispatch(call) { return result; }
    if let Some(result) = crate::nt_user_stack::dispatch(call) { return result; }
    if let Some(result) = crate::nt_capability::dispatch(call) { return result; }
    if let Some(result) = crate::nt_exists::dispatch(call) { return result; }
    if let Some(result) = crate::nt_search_path::dispatch(call) { return result; }
    if let Some(result) = crate::nt_acl::dispatch(call) { return result; }
    if let Some(result) = crate::nt_directory::dispatch(call) { return result; }
    if let Some(result) = crate::nt_nls::dispatch(call) { return result; }
    if call.service == syscall::nt::NtService::CallbackReturn { return STATUS_NO_CALLBACK_ACTIVE; }
    if call.service == syscall::nt::NtService::NtFlushInstructionCache {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() || call.args.a0 != CURRENT_PROCESS { return STATUS_INVALID_PARAMETER; }
        // x86 instruction and data caches are coherent; Wine likewise treats
        // this operation as a successful no-op on x86/x86_64.
        return STATUS_SUCCESS;
    }
    if call.service == syscall::nt::NtService::NtGetContextThread {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        let Ok(nt::NtThreadCall::GetContext { thread, context }) = nt::decode_thread(call) else {
            return STATUS_INVALID_PARAMETER;
        };
        let table = cur.thread_group.nt_handles();
        let target = match resolve_thread_target(&cur, thread, &table, THREAD_QUERY_INFORMATION) {
            Ok(target) => target, Err(status) => return status,
        };
        // The saved PtRegs is the canonical owner for the current task. A
        // remote task needs a scheduler-safe suspended-register snapshot,
        // which does not exist yet; do not report another task's state.
        if target.tid != cur.tid { return STATUS_NOT_IMPLEMENTED; }
        let flags_addr = match context.as_u64().checked_add(48) {
            Some(address) => address,
            None => return STATUS_INVALID_PARAMETER,
        };
        let flags = match uaccess::get_user_u32(flags_addr) {
            Ok(flags) => flags,
            Err(_) => return STATUS_INVALID_PARAMETER,
        };
        let supported = NT_CONTEXT_AMD64 | NT_CONTEXT_CONTROL | NT_CONTEXT_INTEGER;
        if flags & !(supported) != 0 { return STATUS_NOT_IMPLEMENTED; }
        #[cfg(target_arch = "x86_64")]
        {
            let frame = hal_x86_64::current_pt_regs();
            if frame.is_null() { return STATUS_ACCESS_DENIED; }
            let f = unsafe { &*frame };
            let put = |offset: u64, value: u64| {
                uaccess::put_user_u64(context.as_u64().checked_add(offset).ok_or(() )?, value).map_err(|_| ())
            };
            if flags & NT_CONTEXT_INTEGER != 0 {
                for (offset, value) in [(160, f.rax), (168, f.rcx), (176, f.rdx), (184, f.rbx),
                    (200, f.rbp), (208, f.rsi), (216, f.rdi), (224, f.r8), (232, f.r9),
                    (240, f.r10), (248, f.r11), (256, f.r12), (264, f.r13), (272, f.r14),
                    (280, f.r15)] {
                    if put(offset, value).is_err() { return STATUS_INVALID_PARAMETER; }
                }
            }
            if flags & NT_CONTEXT_CONTROL != 0 {
                for (offset, value) in [(192, f.rsp), (288, f.rip), (104, f.rflags),
                    (56, f.cs), (96, f.ss)] {
                    if put(offset, value).is_err() { return STATUS_INVALID_PARAMETER; }
                }
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        { return STATUS_NOT_IMPLEMENTED; }
        #[cfg(target_arch = "x86_64")]
        {
            if uaccess::put_user_u32(flags_addr, flags).is_err() {
                return STATUS_INVALID_PARAMETER;
            }
            return STATUS_SUCCESS;
        }
    }
    if call.service == syscall::nt::NtService::NtSetContextThread {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        let Ok(nt::NtThreadCall::SetContext { thread, context }) = nt::decode_thread(call) else {
            return STATUS_INVALID_PARAMETER;
        };
        let table = cur.thread_group.nt_handles();
        let target = match resolve_thread_target(&cur, thread, &table, THREAD_QUERY_INFORMATION) {
            Ok(target) => target, Err(status) => return status,
        };
        // A remote task needs its scheduler-owned stopped-register snapshot;
        // mutating a live task's frame from another CPU would race return.
        if target.tid != cur.tid { return STATUS_NOT_IMPLEMENTED; }
        let flags_addr = match context.as_u64().checked_add(48) {
            Some(address) => address,
            None => return STATUS_INVALID_PARAMETER,
        };
        let flags = match uaccess::get_user_u32(flags_addr) {
            Ok(flags) => flags,
            Err(_) => return STATUS_INVALID_PARAMETER,
        };
        let supported = NT_CONTEXT_AMD64 | NT_CONTEXT_CONTROL | NT_CONTEXT_INTEGER;
        if flags & !supported != 0 { return STATUS_NOT_IMPLEMENTED; }
        #[cfg(target_arch = "x86_64")]
        {
            let frame = hal_x86_64::current_pt_regs();
            if frame.is_null() { return STATUS_ACCESS_DENIED; }
            // SAFETY: this is the active task's live syscall frame; the NT
            // entry cannot schedule before these field updates complete.
            let f = unsafe { &mut *frame };
            let get = |offset: u64| -> Result<u64, ()> {
                uaccess::get_user_u64(context.as_u64().checked_add(offset).ok_or(())?).map_err(|_| ())
            };
            if flags & NT_CONTEXT_INTEGER != 0 {
                for (offset, slot) in [(160, &mut f.rax), (168, &mut f.rcx), (176, &mut f.rdx), (184, &mut f.rbx),
                    (200, &mut f.rbp), (208, &mut f.rsi), (216, &mut f.rdi), (224, &mut f.r8), (232, &mut f.r9),
                    (240, &mut f.r10), (248, &mut f.r11), (256, &mut f.r12), (264, &mut f.r13), (272, &mut f.r14),
                    (280, &mut f.r15)] {
                    *slot = match get(offset) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
                }
            }
            if flags & NT_CONTEXT_CONTROL != 0 {
                let rip = match get(288) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
                let rsp = match get(192) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
                let rflags = match get(104) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
                if hal::UserVirtAddr::new(rip).is_none() || hal::UserVirtAddr::new(rsp).is_none()
                    || rflags & 0x2 == 0 || rflags & 0x3000 != 0 { return STATUS_INVALID_PARAMETER; }
                f.rip = rip; f.rsp = rsp; f.rflags = rflags;
            }
            return STATUS_SUCCESS;
        }
        #[cfg(not(target_arch = "x86_64"))]
        { return STATUS_NOT_IMPLEMENTED; }
    }
    if call.service == syscall::nt::NtService::NtGetWriteWatch {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() || call.args.a0 != CURRENT_PROCESS { return STATUS_INVALID_PARAMETER; }
        // Oxide has no per-VMA write-watch owner yet. Keep the ABI visible,
        // but fail closed instead of claiming that every page is clean.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtWriteFileGather {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() || call.args.a0 == 0 || call.args.a4 == 0 || call.args.a5 == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        // The trailing length/offset/key arguments live on the x86_64 user
        // stack. Keep this native ABI separate from the ordinary NtWriteFile
        // request until a canonical segment-array/file owner exists.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtWriteVirtualMemory {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() || call.args.a0 == 0 || call.args.a1 == 0
            || call.args.a2 == 0 || call.args.a3 > usize::MAX as u64 {
            return STATUS_INVALID_PARAMETER;
        }
        // The target process/address-space owner is not yet available to the
        // NT personality, so do not copy into an unvalidated address space.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtYieldExecution {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        let _ = crate::s024_sched_yield::sys_sched_yield(&SyscallArgs { a0: 0, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 });
        return STATUS_SUCCESS;
    }
    if call.service == syscall::nt::NtService::NtSetInformationVirtualMemory {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() || call.args.a0 != CURRENT_PROCESS { return STATUS_INVALID_PARAMETER; }
        // VmPrefetchInformation is class zero. The range array and extended
        // information are user buffers; validate their presence before the
        // VMM acquires a real prefetch/write-watch owner.
        if call.args.a1 != 0 || call.args.a2 == 0 || call.args.a3 == 0 || call.args.a4 == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtSetSystemInformation {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() || call.args.a0 != 28 || call.args.a1 == 0 || call.args.a2 != 8 {
            return STATUS_INVALID_PARAMETER;
        }
        // Wine treats this as a compatibility no-op. The real clock/time
        // adjustment owner remains the kernel timekeeper and privilege layer.
        return STATUS_SUCCESS;
    }
    if call.service == syscall::nt::NtService::NtSetSystemTime {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() || call.args.a0 == 0 || call.args.a1 > u64::MAX - 8 {
            return STATUS_INVALID_PARAMETER;
        }
        // Wine only permits changes within half a second and reports larger
        // changes as STATUS_PRIVILEGE_NOT_HELD. The canonical timekeeper
        // owner is not yet exposed to the NT personality, so fail closed.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtSetValueKey {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() || call.args.a0 > u32::MAX as u64 || call.args.a1 == 0
            || call.args.a2 != 0 || call.args.a3 > u32::MAX as u64 || call.args.a5 > u32::MAX as u64 {
            return STATUS_INVALID_PARAMETER;
        }
        if call.args.a4 == 0 && call.args.a5 != 0 { return STATUS_ACCESS_VIOLATION; }
        // Keep the native six-argument ABI separate from the internal
        // registry request record. Canonical key/value storage and VFS
        // persistence are still required before mutation is safe.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtUnloadKey {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return STATUS_INVALID_PARAMETER; }
        // Unloading a registry hive requires the same canonical registry
        // namespace and persistence owner as NtLoadKey; it must not become a
        // synonym for Linux filesystem unmount.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtResetWriteWatch {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() || call.args.a0 != CURRENT_PROCESS || call.args.a1 == 0 || call.args.a2 == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let Some(end) = call.args.a1.checked_add(call.args.a2) else { return STATUS_INVALID_PARAMETER; };
        // SAFETY: this syscall runs on the current task; cloning its mm pins
        // the VMA tree for the duration of the read-only validation.
        let Some(mm) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return STATUS_INVALID_PARAMETER; };
        let Some(base) = hal::UserVirtAddr::new(call.args.a1) else { return STATUS_INVALID_PARAMETER; };
        let Some(vma) = mm.find_vma(base) else { return STATUS_MEMORY_NOT_ALLOCATED; };
        if end > vma.end.as_u64() { return STATUS_INVALID_PARAMETER; }
        // The VMM has not yet acquired a per-page write-watch owner. Do not
        // report success for an operation that would leave dirty state intact.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtImpersonateAnonymousToken {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtIsProcessInJob {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() || call.args.a0 != CURRENT_PROCESS || call.args.a1 > u32::MAX as u64 {
            return STATUS_INVALID_PARAMETER;
        }
        let table = cur.thread_group.nt_handles();
        let job = sched::nt_object::NtHandle::from_raw(call.args.a1 as u32);
        let Some(object) = table.get(job, 0) else {
            return if table.contains(job) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
        };
        if object.kind() != sched::nt_object::NtObjectType::Job { return STATUS_INVALID_HANDLE; }
        return if cur.nt_job_id() == object.id() { 0x0000_0124 } else { 0x0000_0123 };
    }
    if call.service == syscall::nt::NtService::NtLoadKey {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        // Registry hive loading needs a typed request in the userspace
        // registry owner; accepting the ABI without that transaction would
        // discard the hive, so fail closed until that owner is added.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtSaveKey {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() || call.args.a0 == 0 || call.args.a1 == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        // A successful save requires the canonical registry-key owner to
        // serialize its hive into the caller's writable VFS file. Neither
        // handle can be interpreted safely by the current NT object layer.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtSetInformationObject {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() || call.args.a0 > u32::MAX as u64 || call.args.a2 == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let table = cur.thread_group.nt_handles();
        let handle = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
        if table.get(handle, 0).is_none() { return STATUS_INVALID_HANDLE; }
        // Wine's implemented class is ObjectHandleFlagInformation (4), whose
        // two ULONG fields control inherit/protect-from-close. The handle
        // table currently has no owner for those flags, so reject other
        // classes and avoid reporting a mutation that is not retained.
        if call.args.a1 != 4 || call.args.a3 < 8 { return STATUS_INVALID_PARAMETER; }
        if uaccess::get_user_u32(call.args.a2).is_err() || uaccess::get_user_u32(call.args.a2 + 4).is_err() {
            return STATUS_INVALID_PARAMETER;
        }
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtMakeTemporaryObject {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        // The NT handle table has no named-object permanence owner yet. Do
        // not report success while silently leaving a permanent object alive.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtMapViewOfSectionEx {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        // Extended parameters and cross-process APC mapping need an NT-owned
        // request decoder; the ordinary section mapper cannot safely stand in.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtNotifyChangeDirectoryFile {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        // Directory change delivery needs an NT async/event registration
        // owner over the VFS notification stream; do not fake completion.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtNotifyChangeKey {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        // Registry change delivery needs an NT async/event registration owner
        // over the userspace registry service; do not fake completion.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtOpenEvent {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        // The NT object table has no named-object namespace yet, so an event
        // cannot be resolved safely from OBJECT_ATTRIBUTES.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::OpenKey {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        // Registry key handles need a typed NT object and namespace resolver;
        // do not confuse the Linux VFS namespace with the Windows registry.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtOpenKeyEx {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtOpenMutant {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        // Mutant objects exist, but the named-object namespace needed by
        // OBJECT_ATTRIBUTES is not owned by the current NT handle layer.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtOpenProcess {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        // Process-handle acquisition needs a typed CLIENT_ID/attributes
        // decoder and access check over the scheduler process owner.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtOpenSection {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        // Section handles are implemented, but named-section lookup still
        // requires the NT object namespace owner.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtOpenSemaphore {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        // Named semaphore lookup requires the shared NT object namespace.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtOpenSymbolicLinkObject {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        // Symbolic-link objects are distinct from VFS path symlinks and need
        // an NT namespace/object owner before they can be opened safely.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtOpenThread {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        // Thread identities exist in the scheduler, but NT CLIENT_ID handle
        // acquisition and access checks are not owned by the current bridge.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtOpenTimer {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        // Named timer lookup requires the shared NT object namespace.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtQueryDirectoryObject {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        // NT object-directory enumeration requires the NT namespace owner;
        // Linux VFS directory enumeration is deliberately not substituted.
        return STATUS_NOT_IMPLEMENTED;
    }
    if call.service == syscall::nt::NtService::NtPulseEvent {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        // Pulse semantics require an event-owner wake snapshot, not a SetEvent
        // followed by ResetEvent race.
        return STATUS_NOT_IMPLEMENTED;
    }
    if matches!(call.service, syscall::nt::NtService::NtCreateNamedPipeFile | syscall::nt::NtService::NtCreateSectionEx | syscall::nt::NtService::NtCreateSymbolicLinkObject | syscall::nt::NtService::NtCreateUserProcess | syscall::nt::NtService::NtDeleteKey | syscall::nt::NtService::NtDeleteValueKey | syscall::nt::NtService::NtEnumerateKey | syscall::nt::NtService::NtEnumerateValueKey | syscall::nt::NtService::NtFilterToken | syscall::nt::NtService::NtFlushKey) { return 0xc000_0002; }
    if let Some(result) = crate::nt_power::dispatch(call) { return result; }
    if let Some(result) = crate::nt_fls::dispatch(call) { return result; }
    if let Some(result) = crate::nt_format::dispatch(call) { return result; }
    if let Some(result) = crate::nt_oem::dispatch(call) { return result; }
    if let Ok(system) = nt::decode_system_information_ex(call) {
        const SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES: u32 = 181;
        const ARCHITECTURE_RECORD_BYTES: u32 = 4;
        const ARCHITECTURE_RECORDS: u32 = 2;
        const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() || system.class != SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES || system.query == 0 || system.query_len < 8 { return STATUS_INVALID_PARAMETER; }
        if uaccess::get_user_u64(system.query).is_err() { return STATUS_INVALID_PARAMETER; }
        let required = ARCHITECTURE_RECORD_BYTES * ARCHITECTURE_RECORDS;
        if let Some(return_length) = system.return_length {
            if uaccess::put_user_u32(return_length.as_u64(), required).is_err() { return STATUS_INVALID_PARAMETER; }
        }
        if system.length < required { return STATUS_BUFFER_TOO_SMALL; }
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&0x0007_8664u32.to_ne_bytes());
        if uaccess::copy_to_user(system.info.as_u64(), &out).is_err() { return STATUS_INVALID_PARAMETER; }
        return STATUS_SUCCESS;
    }
    if let Ok(system) = nt::decode_system(call) {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        const SYSTEM_BASIC_INFORMATION_CLASS: u32 = 0;
        const SYSTEM_BASIC_INFORMATION_BYTES: u32 = 64;
        if system.class != SYSTEM_BASIC_INFORMATION_CLASS { return STATUS_INVALID_INFO_CLASS; }
        if system.length != SYSTEM_BASIC_INFORMATION_BYTES {
            if let Some(return_length) = system.return_length {
                if uaccess::put_user_u32(return_length.as_u64(), SYSTEM_BASIC_INFORMATION_BYTES).is_err() { return STATUS_INVALID_PARAMETER; }
            }
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        let processors = cpu::count().max(1);
        let affinity = if processors >= 64 { u64::MAX } else { (1u64 << processors) - 1 };
        let mut out = [0u8; SYSTEM_BASIC_INFORMATION_BYTES as usize];
        out[8..12].copy_from_slice(&(hal::PAGE_SIZE_BYTES as u32).to_le_bytes());
        out[24..32].copy_from_slice(&0x1_0000u64.to_le_bytes());
        out[32..40].copy_from_slice(&0x1_0000u64.to_le_bytes());
        out[40..48].copy_from_slice(&hal::USER_VA_END.saturating_sub(1).to_le_bytes());
        out[48..56].copy_from_slice(&affinity.to_le_bytes());
        out[56] = processors.min(u8::MAX as u32) as u8;
        if uaccess::copy_to_user(system.info.as_u64(), &out).is_err() { return STATUS_INVALID_PARAMETER; }
        if let Some(return_length) = system.return_length {
            if uaccess::put_user_u32(return_length.as_u64(), SYSTEM_BASIC_INFORMATION_BYTES).is_err() { return STATUS_INVALID_PARAMETER; }
        }
        return STATUS_SUCCESS;
    }
    if matches!(call.service, nt::NtService::DeviceIoControlFile | nt::NtService::FsControlFile | nt::NtService::OpenJobObject | nt::NtService::QueryInformationJobObject | nt::NtService::SetInformationDebugObject | nt::NtService::SetInformationJobObject | nt::NtService::SetInformationProcess | nt::NtService::SetInformationThread) {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        return 0xc000_0002;
    }
    if let Some(result) = crate::nt_atom::dispatch(call) { return result; }
    if let Some(result) = crate::nt_loader_dir::dispatch(call) { return result; }
    if let Some(result) = crate::nt_loader_proc::dispatch(call) { return result; }
    if let Some(result) = crate::nt_exec::dispatch(call) { return result; }
    if let Some(result) = crate::nt_duplicate::dispatch(call) { return result; }
    if let Some(result) = crate::nt_timer::dispatch(call) { return result; }
    if let Some(result) = crate::nt_completion::dispatch(call) { return result; }
    if let Some(result) = crate::nt_signal_wait::dispatch(call) { return result; }
    if let Some(result) = crate::nt_token::dispatch(call) { return result; }
    if let Some(result) = crate::nt_unwind::dispatch(call) { return result; }
    if let Some(result) = crate::nt_exception::dispatch(call) { return result; }
    if let Some(result) = crate::nt_time::dispatch(call) { return result; }
    if let Some(result) = crate::nt_rtl::dispatch(call) { return result; }
    if let Some(result) = crate::nt_bitmap::dispatch(call) { return result; }
    if let Some(result) = crate::nt_unicode::dispatch(call) { return result; }
    if let Some(result) = crate::nt_context::dispatch(call) { return result; }
    if let Some(result) = crate::nt_sid::dispatch(call) { return result; }
    if let Some(result) = crate::nt_printf::dispatch(call) { return result; }
    if let Some(result) = crate::nt_security::dispatch(call) { return result; }
    if let Some(result) = crate::nt_time::dispatch(call) { return result; }
    if let Some(result) = crate::nt_threadpool::dispatch(call) { return result; }
    if let Some(result) = crate::nt_path_type::dispatch(call) { return result; }
    if let Some(result) = crate::nt_image::dispatch(call) { return result; }
    if let Some(result) = crate::nt_dos83::dispatch(call) { return result; }
    if let Some(result) = crate::nt_heap_lock::dispatch(call) { return result; }
    if let Some(result) = crate::nt_object_query::dispatch(call) { return result; }
    if let Some(result) = crate::nt_sync::dispatch(call) { return result; }
    if let Some(result) = crate::nt_mutant::dispatch(call) { return result; }
    if let Ok(file_call) = nt::decode_file(call) {
        return crate::nt_file::dispatch(file_call);
    }
    if let Some(result) = crate::nt_heap::dispatch(call) { return result; }
    if let Some(result) = crate::nt_window::dispatch(call) { return result; }
    if call.service == nt::NtService::TerminateProcess {
        let (process, status) = match nt::decode_terminate(call) {
            Ok(values) => values,
            Err(_) => return STATUS_INVALID_PARAMETER,
        };
        if process != CURRENT_PROCESS { return STATUS_INVALID_PARAMETER; }
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        return crate::s060_exit::sys_exit_group(&SyscallArgs { a0: status as u64, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }) as u64;
    }
    if call.service == nt::NtService::RtlExitUserProcess {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        return crate::s060_exit::sys_exit_group(&SyscallArgs { a0: call.args.a0, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }) as u64;
    }
    if call.service == nt::NtService::TerminateThread {
        let Ok(NtObjectCall::TerminateThread { thread, status }) = nt::decode_object(call) else { return STATUS_INVALID_PARAMETER; };
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        let table = cur.thread_group.nt_handles();
        let target = match resolve_thread_target(&cur, thread, &table, THREAD_TERMINATE) {
            Ok(target) => target, Err(error) => return error,
        };
        if target.tgid.load(core::sync::atomic::Ordering::Acquire) != cur.tgid.load(core::sync::atomic::Ordering::Acquire) {
            return STATUS_INVALID_HANDLE;
        }
        if thread == CURRENT_THREAD {
            return crate::s060_exit::sys_exit(&SyscallArgs { a0: status, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }) as u64;
        }
        // Cross-thread termination uses Linux's canonical forced-fatal signal
        // path; it wakes a sleeping target and preserves scheduler teardown ownership.
        let info = sched::sigsend::fault_info(sched::signum::Signum::Sigkill as u32, 0, 0, 0);
        sched::live::force_sig_info_to_task(&target, info, sched::sigsend::ForceMode::Exit);
        return STATUS_SUCCESS;
    }
    if call.service == nt::NtService::NtSuspendThread {
        let Ok(NtObjectCall::SuspendThread { thread, count }) = nt::decode_object(call) else { return STATUS_INVALID_PARAMETER; };
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        let table = cur.thread_group.nt_handles();
        let target = match resolve_thread_target(&cur, thread, &table, THREAD_SUSPEND_RESUME) {
            Ok(target) => target, Err(error) => return error,
        };
        let previous = target.nt_suspend();
        if let Some(count) = count {
            if uaccess::put_user_u32(count.as_u64(), previous).is_err() { return STATUS_INVALID_PARAMETER; }
        }
        return STATUS_SUCCESS;
    }
    if call.service == nt::NtService::NtResumeThread {
        let Ok(NtObjectCall::ResumeThread { thread, count }) = nt::decode_object(call) else { return STATUS_INVALID_PARAMETER; };
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        let table = cur.thread_group.nt_handles();
        let target = match resolve_thread_target(&cur, thread, &table, THREAD_SUSPEND_RESUME) {
            Ok(target) => target, Err(error) => return error,
        };
        let previous = target.nt_resume();
        if let Some(count) = count {
            if uaccess::put_user_u32(count.as_u64(), previous).is_err() { return STATUS_INVALID_PARAMETER; }
        }
        return STATUS_SUCCESS;
    }
    if call.service == nt::NtService::RtlExitUserThread {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        return crate::s060_exit::sys_exit(&SyscallArgs { a0: call.args.a0, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }) as u64;
    }
    if let Ok(object_call) = nt::decode_object(call) {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        let table = cur.thread_group.nt_handles();
        return match object_call {
            NtObjectCall::CompareObjects { first, second } => compare_objects(&cur, first, second),
            NtObjectCall::CreateJob { handle, desired_access, attributes: _ } => {
                if desired_access & !JOB_OBJECT_ALL_ACCESS != 0 { return STATUS_INVALID_PARAMETER; }
                let object = table.new_object(sched::nt_object::NtObjectType::Job);
                let Some(native) = table.insert(object, desired_access) else { return STATUS_NO_MEMORY; };
                if uaccess::put_user_u32(handle.as_u64(), native.raw()).is_err() {
                    let _ = table.close(native);
                    STATUS_INVALID_PARAMETER
                } else { STATUS_SUCCESS }
            }
            NtObjectCall::AssignProcessToJobObject { job, process } => {
                if process != CURRENT_PROCESS || job > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
                let native = sched::nt_object::NtHandle::from_raw(job as u32);
                let Some(object) = table.get(native, JOB_OBJECT_ASSIGN_PROCESS) else { return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
                if object.kind() != sched::nt_object::NtObjectType::Job { return STATUS_INVALID_HANDLE; }
                cur.set_nt_job_id(object.id());
                STATUS_SUCCESS
            }
            NtObjectCall::TerminateJobObject { job, status } => {
                if job > u32::MAX as u64 { return STATUS_INVALID_HANDLE; }
                let native = sched::nt_object::NtHandle::from_raw(job as u32);
                let Some(object) = table.get(native, JOB_OBJECT_TERMINATE) else { return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
                if object.kind() != sched::nt_object::NtObjectType::Job { return STATUS_INVALID_HANDLE; }
                if cur.nt_job_id() != object.id() { return STATUS_SUCCESS; }
                cur.set_nt_job_id(0);
                return crate::s060_exit::sys_exit_group(&SyscallArgs { a0: status, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }) as u64;
            }
            NtObjectCall::CreateEvent { handle, desired_access, event_type, initial_state } => {
                if desired_access & !EVENT_ALL_ACCESS != 0 || event_type > 1 || initial_state > 1 { return STATUS_INVALID_PARAMETER; }
                // Native EVENT_TYPE 0 is NotificationEvent (manual reset),
                // while 1 is SynchronizationEvent (auto reset).
                let object = table.new_event(event_type == 0, initial_state != 0);
                let Some(native) = table.insert(object, desired_access) else { return STATUS_NO_MEMORY; };
                if uaccess::put_user_u32(handle.as_u64(), native.raw()).is_err() {
                    let _ = table.close(native);
                    STATUS_INVALID_PARAMETER
                } else { STATUS_SUCCESS }
            }
            NtObjectCall::Close { handle } => {
                if table.close(sched::nt_object::NtHandle::from_raw(handle)) { STATUS_SUCCESS } else { STATUS_INVALID_HANDLE }
            }
            NtObjectCall::SetEvent { handle, previous } => {
                let native = sched::nt_object::NtHandle::from_raw(handle);
                let Some(object) = table.get(native, EVENT_MODIFY_STATE) else { return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
                if object.kind() != sched::nt_object::NtObjectType::Event { return STATUS_INVALID_HANDLE; }
                let Some(event) = object.event() else { return STATUS_INVALID_HANDLE; };
                let old = event.is_signaled();
                event.set();
                table.wake_waiters();
                if let Some(previous) = previous { if uaccess::put_user_u32(previous.as_u64(), old as u32).is_err() { return STATUS_INVALID_PARAMETER; } }
                STATUS_SUCCESS
            }
            NtObjectCall::ResetEvent { handle, previous } => {
                let native = sched::nt_object::NtHandle::from_raw(handle);
                let Some(object) = table.get(native, EVENT_MODIFY_STATE) else { return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
                if object.kind() != sched::nt_object::NtObjectType::Event { return STATUS_INVALID_HANDLE; }
                let Some(event) = object.event() else { return STATUS_INVALID_HANDLE; };
                let old = event.is_signaled();
                event.reset();
                table.wake_waiters();
                if let Some(previous) = previous { if uaccess::put_user_u32(previous.as_u64(), old as u32).is_err() { return STATUS_INVALID_PARAMETER; } }
                STATUS_SUCCESS
            }
            NtObjectCall::WaitEvent { handle, alertable, timeout } => {
                if alertable > 1 { return STATUS_INVALID_PARAMETER; }
                let native = sched::nt_object::NtHandle::from_raw(handle);
                let Some(object) = table.get(native, SYNCHRONIZE_ACCESS) else { return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
                let deadline = match wait_deadline(timeout) { Ok(deadline) => deadline, Err(status) => return status };
                let outcome = if let Some(event) = object.event() {
                    // SAFETY: NT dispatch is process context; the object Arc keeps the predicate alive while the scheduler may sleep.
                    unsafe { event.wait(deadline, timekeeper::monotonic_ns) }
                } else if let Some(semaphore) = object.semaphore() {
                    // SAFETY: NT dispatch is process context; the object Arc keeps the predicate alive while the scheduler may sleep.
                    unsafe { semaphore.wait(deadline, timekeeper::monotonic_ns) }
                } else if let Some(mutant) = object.mutant() {
                    // SAFETY: NT dispatch is process context; the object Arc keeps the predicate alive while the scheduler may sleep.
                    unsafe { mutant.wait(cur.tid as u64, deadline, timekeeper::monotonic_ns) }
                } else if let Some(timer) = object.timer() {
                    // Timer deadlines participate in the same interruptible
                    // wait loop as explicit NT timeout deadlines.
                    unsafe { timer.wait(deadline, timekeeper::monotonic_ns) }
                } else { return STATUS_INVALID_HANDLE; };
                match outcome {
                    sched::WaitOutcome::Ready => STATUS_SUCCESS,
                    sched::WaitOutcome::TimedOut => STATUS_TIMEOUT,
                    sched::WaitOutcome::Interrupted => if alertable != 0 { STATUS_USER_APC } else { STATUS_ALERTED },
                }
            }
            NtObjectCall::WaitMultiple { count, handles, wait_type, alertable, timeout } => {
                if count == 0 || count > WAIT_MULTIPLE_LIMIT || wait_type > 1 || alertable > 1 { return STATUS_INVALID_PARAMETER; }
                let mut waitables = alloc::vec::Vec::with_capacity(count as usize);
                for index in 0..count as usize {
                    let Some(address) = handles.as_u64().checked_add((index * core::mem::size_of::<u32>()) as u64) else { return STATUS_INVALID_PARAMETER; };
                    let raw = match uaccess::get_user_u32(address) { Ok(raw) => raw, Err(_) => return STATUS_INVALID_PARAMETER };
                    let native = sched::nt_object::NtHandle::from_raw(raw);
                    let Some(object) = table.get(native, SYNCHRONIZE_ACCESS) else { return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
                    if !matches!(object.kind(), sched::nt_object::NtObjectType::Event | sched::nt_object::NtObjectType::Semaphore | sched::nt_object::NtObjectType::Mutant | sched::nt_object::NtObjectType::Timer) { return STATUS_INVALID_HANDLE; }
                    waitables.push(object);
                }
                let deadline = match wait_deadline(timeout) { Ok(deadline) => deadline, Err(status) => return status };
                // SAFETY: wait table and object Arcs remain alive for the complete wait.
                let timer_deadline = waitables.iter().filter_map(|object| object.timer_deadline()).min().unwrap_or(u64::MAX);
                let wait_deadline = deadline.min(timer_deadline);
                let all_ready = || {
                    if wait_type == 0 { waitables.iter().all(|object| object.is_signaled_at(cur.tid as u64, timekeeper::monotonic_ns())) }
                    else { waitables.iter().any(|object| object.is_signaled_at(cur.tid as u64, timekeeper::monotonic_ns())) }
                };
                let outcome = unsafe { sched::live::wait_event_interruptible_until(table.waiters(), wait_deadline, timekeeper::monotonic_ns, all_ready) };
                let outcome = if matches!(outcome, sched::WaitOutcome::TimedOut) && timer_deadline <= deadline
                    && waitables.iter().any(|object| object.is_signaled_at(cur.tid as u64, timekeeper::monotonic_ns())) {
                    sched::WaitOutcome::Ready
                } else { outcome };
                match outcome {
                    sched::WaitOutcome::Ready => {
                        if wait_type == 0 {
                            for object in &waitables { let _ = object.try_wait_at(cur.tid as u64, timekeeper::monotonic_ns()); }
                            STATUS_SUCCESS
                        } else {
                            for (index, object) in waitables.iter().enumerate() {
                                if object.try_wait_at(cur.tid as u64, timekeeper::monotonic_ns()) { return STATUS_WAIT_0 + index as u64; }
                            }
                            STATUS_ALERTED
                        }
                    }
                    sched::WaitOutcome::TimedOut => STATUS_TIMEOUT,
                    sched::WaitOutcome::Interrupted => if alertable != 0 { STATUS_USER_APC } else { STATUS_ALERTED },
                }
            }
            NtObjectCall::CreateSection { handle, desired_access, size, protect, attributes, file } => {
                if desired_access & !(SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_WRITE | SYNCHRONIZE_ACCESS) != 0
                    || size == 0 || size > SECTION_MAX_BYTES || attributes != 0 { return STATUS_INVALID_PARAMETER; }
                let page = hal::PAGE_SIZE_BYTES as u64;
                let Some(size) = size.checked_add(page - 1).map(|v| v & !(page - 1)) else { return STATUS_INVALID_PARAMETER; };
                let Ok(protection) = elf_load::nt_memory::windows_protection(protect) else { return STATUS_INVALID_PARAMETER; };
                if protection.contains(vmm::VmaProt::EXEC) { return STATUS_INVALID_PARAMETER; }
                let object = if file == 0 {
                    let Some(object) = table.new_section(size as usize) else { return STATUS_NO_MEMORY; };
                    object
                } else {
                    let native = sched::nt_object::NtHandle::from_raw(file);
                    let Some(file_object) = table.get(native, 0) else { return STATUS_INVALID_HANDLE; };
                    if file_object.kind() != sched::nt_object::NtObjectType::File { return STATUS_INVALID_HANDLE; }
                    let granted = table.access(native).unwrap_or(0);
                    if granted & (FILE_READ_DATA | GENERIC_READ | FILE_GENERIC_READ) == 0 { return STATUS_ACCESS_DENIED; }
                    let Some(file) = file_object.file() else { return STATUS_INVALID_HANDLE; };
                    let stat = vfs::generic_fillattr(file.inode(), &vfs::IDENTITY);
                    let file_size = (stat.size as u64).checked_add(hal::PAGE_SIZE_BYTES - 1)
                        .map(|value| value & !(hal::PAGE_SIZE_BYTES - 1)).unwrap_or(0);
                    if file_size == 0 || size < file_size { return STATUS_INVALID_PARAMETER; }
                    table.new_file_section(file, size as usize)
                };
                let Some(native) = table.insert(object, desired_access) else { return STATUS_NO_MEMORY; };
                if uaccess::put_user_u32(handle.as_u64(), native.raw()).is_err() {
                    let _ = table.close(native);
                    STATUS_INVALID_PARAMETER
                } else { STATUS_SUCCESS }
            }
            NtObjectCall::MapViewOfSection { section, process, base, offset, size, protect } => {
                if process != CURRENT_PROCESS || offset % hal::PAGE_SIZE_BYTES != 0 { return STATUS_INVALID_PARAMETER; }
                // SAFETY: the running NT task owns its current address-space
                // slot for this syscall; the clone keeps the VMM state alive.
                let Some(mm) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return STATUS_INVALID_PARAMETER; };
                let Ok(protection) = elf_load::nt_memory::windows_protection(protect) else { return STATUS_INVALID_PARAMETER; };
                if protection.contains(vmm::VmaProt::EXEC) { return STATUS_INVALID_PARAMETER; }
                let native = sched::nt_object::NtHandle::from_raw(section);
                let required_access = if protection.contains(vmm::VmaProt::WRITE) { SECTION_MAP_WRITE } else { SECTION_MAP_READ };
                let Some(object) = table.get(native, required_access) else { return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
                if object.kind() != sched::nt_object::NtObjectType::Section { return STATUS_INVALID_HANDLE; }
                let Some(section) = object.section() else { return STATUS_INVALID_HANDLE; };
                if offset >= section.size() as u64 { return STATUS_INVALID_PARAMETER; }
                let requested = match uaccess::get_user_u64(base.as_u64()) { Ok(0) => None, Ok(raw) => hal::UserVirtAddr::new(raw), Err(_) => return STATUS_INVALID_PARAMETER };
                let requested_size = match uaccess::get_user_u64(size.as_u64()) { Ok(0) => section.size() as u64 - offset, Ok(raw) => raw, Err(_) => return STATUS_INVALID_PARAMETER };
                let page = hal::PAGE_SIZE_BYTES as u64;
                if requested_size == 0 || requested_size % page != 0 || requested_size > section.size() as u64 - offset { return STATUS_INVALID_PARAMETER; }
                let placement = vmm::MmapPlacement::Advisory(requested);
                let backing = if let Some(file) = section.file() {
                    vmm::VmaBacking::File {
                        backing: crate::mmap_file::InodeFileBacking::new(file.inode().clone()), off: offset,
                    }
                } else {
                    vmm::VmaBacking::KernelBytes { data: section.bytes(), off: offset as usize }
                };
                let mapped = match mm.mmap_with_may_at(placement, requested_size as usize, protection, protection,
                    vmm::VmaFlags::PRIVATE, backing) {
                    Ok(mapped) => mapped,
                    Err(_) => return STATUS_NO_MEMORY,
                };
                if uaccess::put_user_u64(base.as_u64(), mapped.as_u64()).is_err()
                    || uaccess::put_user_u64(size.as_u64(), requested_size).is_err() {
                    let _ = mm.munmap(mapped, requested_size as usize);
                    return STATUS_INVALID_PARAMETER;
                }
                STATUS_SUCCESS
            }
            NtObjectCall::UnmapViewOfSection { process, base } => {
                if process != CURRENT_PROCESS { return STATUS_INVALID_PARAMETER; }
                // SAFETY: the running NT task owns its current address-space
                // slot for this syscall; the clone keeps the VMM state alive.
                let Some(mm) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return STATUS_INVALID_PARAMETER; };
                let Some(base) = hal::UserVirtAddr::new(base) else { return STATUS_INVALID_PARAMETER; };
                let Some(vma) = mm.find_vma(base) else { return STATUS_MEMORY_NOT_ALLOCATED; };
                if vma.start != base { return STATUS_INVALID_PARAMETER; }
                if mm.munmap(vma.start, (vma.end.as_u64() - vma.start.as_u64()) as usize).is_ok() { STATUS_SUCCESS } else { STATUS_MEMORY_NOT_ALLOCATED }
            }
            NtObjectCall::UnmapViewOfSectionEx { process, base, flags } => {
                if process != CURRENT_PROCESS || flags != 0 { return STATUS_INVALID_PARAMETER; }
                let Some(mm) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return STATUS_INVALID_PARAMETER; };
                let Some(base) = hal::UserVirtAddr::new(base) else { return STATUS_INVALID_PARAMETER; };
                let Some(vma) = mm.find_vma(base) else { return STATUS_MEMORY_NOT_ALLOCATED; };
                if vma.start != base { return STATUS_INVALID_PARAMETER; }
                if mm.munmap(vma.start, (vma.end.as_u64() - vma.start.as_u64()) as usize).is_ok() { STATUS_SUCCESS } else { STATUS_MEMORY_NOT_ALLOCATED }
            }
            NtObjectCall::QuerySection { section, class, info, length, return_length } => {
                const SECTION_BASIC_INFORMATION_BYTES: u32 = 24;
                if class != 0 { return STATUS_INVALID_INFO_CLASS; }
                if length < SECTION_BASIC_INFORMATION_BYTES { return STATUS_INFO_LENGTH_MISMATCH; }
                let native = sched::nt_object::NtHandle::from_raw(section);
                let Some(object) = table.get(native, SECTION_QUERY) else {
                    return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
                };
                if object.kind() != sched::nt_object::NtObjectType::Section { return STATUS_INVALID_HANDLE; }
                let Some(section) = object.section() else { return STATUS_INVALID_HANDLE; };
                if uaccess::put_user_u64(info.as_u64(), 0).is_err()
                    || uaccess::put_user_u32(info.as_u64() + 8, 0).is_err()
                    || uaccess::put_user_u64(info.as_u64() + 16, section.size() as u64).is_err() {
                    return STATUS_INVALID_PARAMETER;
                }
                if let Some(return_length) = return_length {
                    if uaccess::put_user_u64(return_length.as_u64(), SECTION_BASIC_INFORMATION_BYTES as u64).is_err() {
                        return STATUS_INVALID_PARAMETER;
                    }
                }
                STATUS_SUCCESS
            }
            NtObjectCall::QueryProcess { process, class, info, length, return_length } => {
                if process != CURRENT_PROCESS || class != PROCESS_BASIC_INFORMATION_CLASS { return STATUS_INVALID_PARAMETER; }
                if (length as usize) < PROCESS_BASIC_INFORMATION_BYTES { return STATUS_INVALID_PARAMETER; }
                let mut out = [0u8; PROCESS_BASIC_INFORMATION_BYTES];
                out[8..16].copy_from_slice(&cur.nt_peb().to_ne_bytes());
                out[32..40].copy_from_slice(&(cur.tgid.load(core::sync::atomic::Ordering::Acquire) as u64).to_ne_bytes());
                out[40..48].copy_from_slice(&(cur.parent_tid.load(core::sync::atomic::Ordering::Acquire) as u64).to_ne_bytes());
                if uaccess::copy_to_user(info.as_u64(), &out).is_err() { return STATUS_INVALID_PARAMETER; }
                if let Some(return_length) = return_length {
                    if uaccess::put_user_u32(return_length.as_u64(), PROCESS_BASIC_INFORMATION_BYTES as u32).is_err() { return STATUS_INVALID_PARAMETER; }
                }
                STATUS_SUCCESS
            }
            NtObjectCall::QueryThread { thread, class, info, length, return_length } => {
                if class != THREAD_BASIC_INFORMATION_CLASS || (length as usize) < THREAD_BASIC_INFORMATION_BYTES { return STATUS_INVALID_PARAMETER; }
                let target = match resolve_thread_target(&cur, thread, &table, THREAD_QUERY_INFORMATION) {
                    Ok(target) => target, Err(error) => return error,
                };
                if !target.is_nt_personality() { return STATUS_INVALID_HANDLE; }
                let mut out = [0u8; THREAD_BASIC_INFORMATION_BYTES];
                out[8..16].copy_from_slice(&target.nt_teb().to_ne_bytes());
                out[16..24].copy_from_slice(&(target.tgid.load(core::sync::atomic::Ordering::Acquire) as u64).to_ne_bytes());
                out[24..32].copy_from_slice(&(target.tid as u64).to_ne_bytes());
                if uaccess::copy_to_user(info.as_u64(), &out).is_err() { return STATUS_INVALID_PARAMETER; }
                if let Some(return_length) = return_length {
                    if uaccess::put_user_u32(return_length.as_u64(), THREAD_BASIC_INFORMATION_BYTES as u32).is_err() { return STATUS_INVALID_PARAMETER; }
                }
                STATUS_SUCCESS
            }
            NtObjectCall::TerminateThread { .. } => STATUS_INVALID_PARAMETER,
            NtObjectCall::DuplicateObject { .. } | NtObjectCall::DuplicateToken { .. } => STATUS_INVALID_PARAMETER,
            NtObjectCall::CreateTimer { .. } | NtObjectCall::SetTimer { .. } | NtObjectCall::CancelTimer { .. } => STATUS_INVALID_PARAMETER,
            NtObjectCall::CreateIoCompletion { .. } | NtObjectCall::SetIoCompletion { .. } | NtObjectCall::RemoveIoCompletion { .. } | NtObjectCall::SignalAndWait { .. } => STATUS_INVALID_PARAMETER,
            NtObjectCall::OpenProcessToken { .. } | NtObjectCall::OpenThreadToken { .. } | NtObjectCall::QueryToken { .. } => STATUS_INVALID_PARAMETER,
            NtObjectCall::CreateThreadEx { handle, process, start, parameter, stack_size, flags } => {
                if process != CURRENT_PROCESS || flags != 0 || start == 0 { return STATUS_INVALID_PARAMETER; }
                let Some(entry) = hal::UserVirtAddr::new(start) else { return STATUS_INVALID_PARAMETER; };
                let stack_size = if stack_size == 0 { NT_THREAD_DEFAULT_STACK } else { stack_size };
                let page = hal::PAGE_SIZE_BYTES as u64;
                let Some(stack_size) = stack_size.checked_add(page - 1).map(|v| v & !(page - 1)) else { return STATUS_INVALID_PARAMETER; };
                if stack_size == 0 || stack_size > NT_THREAD_MAX_STACK { return STATUS_INVALID_PARAMETER; }
                // SAFETY: the running NT task owns this address-space slot;
                // the clone pins it while the unpublished child is prepared.
                let Some(mm) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return STATUS_INVALID_PARAMETER; };
                let stack = match mm.mmap(None, stack_size as usize, vmm::VmaProt::READ | vmm::VmaProt::WRITE,
                    vmm::VmaFlags::PRIVATE, vmm::VmaBacking::Anonymous, false) {
                    Ok(stack) => stack, Err(_) => return STATUS_NO_MEMORY,
                };
                let stack_top = stack.as_u64().checked_add(stack_size).unwrap_or(0) & !0xf;
                let tid = sched::live::next_tid();
                let teb = match elf_load::process_env::build_thread_teb(
                    cur.tgid.load(core::sync::atomic::Ordering::Acquire), tid,
                    cur.nt_peb(), &mm) {
                    Ok(teb) => teb.as_u64(),
                    Err(_) => { let _ = mm.munmap(stack, stack_size as usize); return STATUS_NO_MEMORY; }
                };
                // SAFETY: entry and stack are mapped in the pinned current mm;
                // the returned task is unpublished and not yet runnable.
                let child = match unsafe { sched::live::new_nt_thread_unpublished(
                    tid, entry.as_u64(), stack_top, parameter, teb, mm.clone(), cur.thread_group.clone()) } {
                    Ok(child) => child,
                    Err(_) => { let _ = mm.munmap(stack, stack_size as usize); return STATUS_NO_MEMORY; }
                };
                let native = match table.insert(table.new_thread(child.clone()), THREAD_ALL_ACCESS | SYNCHRONIZE_ACCESS) {
                    Some(handle) => handle,
                    None => { let _ = mm.munmap(stack, stack_size as usize); return STATUS_NO_MEMORY; }
                };
                if uaccess::put_user_u32(handle.as_u64(), native.raw()).is_err() {
                    let _ = table.close(native);
                    let _ = mm.munmap(stack, stack_size as usize);
                    return STATUS_INVALID_PARAMETER;
                }
                sched::live::publish_new_task(&child);
                sched::live::wake_new_task(&child);
                STATUS_SUCCESS
            }
            NtObjectCall::CreateSemaphore { .. } | NtObjectCall::ReleaseSemaphore { .. }
            | NtObjectCall::CreateMutant { .. } | NtObjectCall::ReleaseMutant { .. }
            | NtObjectCall::QueryMutant { .. } | NtObjectCall::QueryObject { .. }
            | NtObjectCall::QuerySecurity { .. } | NtObjectCall::SetSecurity { .. }
            | NtObjectCall::ResumeThread { .. } | NtObjectCall::SuspendThread { .. } => STATUS_INVALID_PARAMETER,
        };
    }
    if call.service == nt::NtService::NtAllocateVirtualMemoryEx {
        let Some(parameter_count) = stack_argument(6) else { return STATUS_INVALID_PARAMETER; };
        if call.args.a5 != 0 || parameter_count != 0 { return STATUS_INVALID_PARAMETER; }
    }
    let call = match nt::decode_memory(call) {
        Ok(call) => call,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };
    let process = match &call {
        NtMemoryCall::Allocate { process, .. } | NtMemoryCall::Free { process, .. }
        | NtMemoryCall::Protect { process, .. } | NtMemoryCall::Query { process, .. }
        | NtMemoryCall::Flush { process, .. } | NtMemoryCall::Lock { process, .. }
        | NtMemoryCall::Unlock { process, .. } => *process,
    };
    if process != CURRENT_PROCESS { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    // SAFETY: the running task is the sole mm mutator during its syscall;
    // clone_mm pins the address space for the complete adapter operation.
    let Some(mm) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return STATUS_INVALID_PARAMETER; };
    match call {
        NtMemoryCall::Allocate { base, size, allocation_type, protect, .. } => {
            if allocation_type != MEM_RESERVE | MEM_COMMIT { return STATUS_INVALID_PARAMETER; }
            let size_ptr = size.as_u64();
            let requested_base = match uaccess::get_user_u64(base.as_u64()) {
                Ok(0) => None,
                Ok(raw) => match hal::UserVirtAddr::new(raw) { Some(raw) => Some(raw), None => return STATUS_INVALID_PARAMETER },
                Err(_) => return STATUS_INVALID_PARAMETER,
            };
            let size = match uaccess::get_user_u64(size_ptr) { Ok(size) => size as usize, Err(_) => return STATUS_INVALID_PARAMETER };
            let protection = match elf_load::nt_memory::windows_protection(protect) { Ok(protection) => protection, Err(_) => return STATUS_INVALID_PARAMETER };
            let allocation = match elf_load::nt_memory::allocate(&mm, requested_base, size, protection) {
                Ok(allocation) => allocation,
                Err(elf_load::nt_memory::NtStatus::NoMemory) => return STATUS_NO_MEMORY,
                Err(_) => return STATUS_INVALID_PARAMETER,
            };
            if uaccess::put_user_u64(base.as_u64(), allocation.base.as_u64()).is_err()
                || uaccess::put_user_u64(size_ptr, allocation.size as u64).is_err() {
                let _ = elf_load::nt_memory::free(&mm, allocation);
                return STATUS_INVALID_PARAMETER;
            }
            STATUS_SUCCESS
        }
        NtMemoryCall::Free { base, size, free_type, .. } => {
            if free_type != MEM_RELEASE { return STATUS_INVALID_PARAMETER; }
            let base = match uaccess::get_user_u64(base.as_u64()).ok().and_then(hal::UserVirtAddr::new) { Some(base) => base, None => return STATUS_INVALID_PARAMETER };
            let size = match uaccess::get_user_u64(size.as_u64()) { Ok(size) if size <= usize::MAX as u64 => size as usize, _ => return STATUS_INVALID_PARAMETER };
            let Some(info) = elf_load::nt_memory::query(&mm, base).ok() else { return STATUS_MEMORY_NOT_ALLOCATED; };
            match elf_load::nt_memory::free(&mm, elf_load::nt_memory::NtAllocation { base, size, protection: info.protection }) {
                elf_load::nt_memory::NtStatus::Success => STATUS_SUCCESS,
                _ => STATUS_INVALID_PARAMETER,
            }
        }
        NtMemoryCall::Protect { base, size, protect, old_protect, .. } => {
            let base = match uaccess::get_user_u64(base.as_u64()).ok().and_then(hal::UserVirtAddr::new) { Some(base) => base, None => return STATUS_INVALID_PARAMETER };
            let size = match uaccess::get_user_u64(size.as_u64()) { Ok(size) if size <= usize::MAX as u64 => size as usize, _ => return STATUS_INVALID_PARAMETER };
            let protection = match elf_load::nt_memory::windows_protection(protect) { Ok(protection) => protection, Err(_) => return STATUS_INVALID_PARAMETER };
            let old = match elf_load::nt_memory::protect(&mm, base, size, protection) { Ok(old) => old, Err(_) => return STATUS_INVALID_PARAMETER };
            if uaccess::put_user_u32(old_protect.as_u64(), windows_protection_word(old)).is_err() { return STATUS_INVALID_PARAMETER; }
            STATUS_SUCCESS
        }
        NtMemoryCall::Query { address, info_class, info, info_size, return_length, .. } => {
            if info_class != MEMORY_BASIC_INFORMATION_CLASS || info_size < MEMORY_BASIC_INFORMATION_BYTES as u64 { return STATUS_INVALID_PARAMETER; }
            let address = match hal::UserVirtAddr::new(address) { Some(address) => address, None => return STATUS_INVALID_PARAMETER };
            let memory = match elf_load::nt_memory::query(&mm, address) { Ok(memory) => memory, Err(_) => return STATUS_MEMORY_NOT_ALLOCATED };
            let mut bytes = [0u8; MEMORY_BASIC_INFORMATION_BYTES];
            bytes[0..8].copy_from_slice(&memory.base.as_u64().to_ne_bytes());
            bytes[8..16].copy_from_slice(&memory.allocation_base.as_u64().to_ne_bytes());
            bytes[16..20].copy_from_slice(&windows_protection_word(memory.protection).to_ne_bytes());
            bytes[24..32].copy_from_slice(&(memory.size as u64).to_ne_bytes());
            bytes[32..36].copy_from_slice(&MEM_COMMIT.to_ne_bytes());
            bytes[36..40].copy_from_slice(&windows_protection_word(memory.protection).to_ne_bytes());
            bytes[40..44].copy_from_slice(&0x20000u32.to_ne_bytes());
            if uaccess::copy_to_user(info.as_u64(), &bytes).is_err() || uaccess::put_user_u64(return_length.as_u64(), MEMORY_BASIC_INFORMATION_BYTES as u64).is_err() { return STATUS_INVALID_PARAMETER; }
            STATUS_SUCCESS
        }
        NtMemoryCall::Flush { address, size, io, .. } => {
            let address_value = match uaccess::get_user_u64(address.as_u64()) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
            let size_value = match uaccess::get_user_u64(size.as_u64()) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
            let (flushed_address, flushed_size) = match mm.flush_virtual_range(address_value, size_value) {
                Ok(range) => range,
                Err(vmm::Error::Io) => return STATUS_NOT_MAPPED_DATA,
                Err(_) => return STATUS_INVALID_PARAMETER,
            };
            if uaccess::put_user_u64(address.as_u64(), flushed_address).is_err()
                || uaccess::put_user_u64(size.as_u64(), flushed_size).is_err() { return STATUS_INVALID_PARAMETER; }
            let _ = io;
            STATUS_SUCCESS
        }
        NtMemoryCall::Lock { address, size, unknown: _, .. } => crate::nt_memory_lock::dispatch(&mm, address, size),
        NtMemoryCall::Unlock { address, size, unknown: _, .. } => crate::nt_memory_lock::unlock(&mm, address, size),
    }
}
#[cfg(target_os = "oxide-kernel")]
fn windows_protection_word(protection: vmm::VmaProt) -> u32 {
    match (protection.contains(vmm::VmaProt::READ), protection.contains(vmm::VmaProt::WRITE), protection.contains(vmm::VmaProt::EXEC)) {
        (false, false, false) => 0x01,
        (true, false, false) => 0x02,
        (true, true, false) => 0x04,
        (false, false, true) => 0x10,
        (true, false, true) => 0x20,
        (true, true, true) => 0x40,
        _ => 0x01,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn untagged_linux_entry_is_not_an_nt_call() {
        let args = SyscallArgs { a0: 1, a1: 2, a2: 3, a3: 4, a4: 5, a5: 6 };
        assert_eq!(decode_entry(0, args), None);
        assert_eq!(decode_entry(9, args), None);
    }
    #[test]
    fn tagged_entry_preserves_the_abi_register_block() {
        let args = SyscallArgs { a0: 1, a1: 2, a2: 3, a3: 4, a4: 5, a5: 6 };
        let call = decode_entry(nt::NT_SERVICE_NAMESPACE | 0, args).unwrap();
        assert_eq!(call.service, nt::NtService::AllocateVirtualMemory);
        assert_eq!(call.args, args);
    }
}
