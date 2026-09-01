//! Process-heap primitives used by the initial Wine-derived runtime.

use syscall::nt::{self, NtCall, NtHeapCall};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const HEAP_ADD_USER_INFO: u64 = 0x0000_0100;

/// Dispatch the heap subset, returning `None` for every other NT service.
/// # C: O(log N_vmas)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == nt::NtService::RtlFreeUserStack {
        if call.args.a0 == 0 { return Some(0); }
        let heap_call = NtCall { service: nt::NtService::FreeHeap, args: syscall::SyscallArgs { a0: 0, a1: 0, a2: call.args.a0, a3: 0, a4: 0, a5: 0 } };
        let _ = dispatch(heap_call);
        return Some(0);
    }
    if call.service == nt::NtService::RtlCompactHeap { return Some(0); }
    if call.service == nt::NtService::RtlCreateHeap { return Some(create_heap(call)); }
    if call.service == nt::NtService::RtlDestroyHeap { return Some(destroy_heap(call)); }
    if call.service == nt::NtService::RtlGetProcessHeaps { return Some(get_process_heaps(call)); }
    if call.service == nt::NtService::RtlGetUserInfoHeap { return Some(get_user_info(call)); }
    if call.service == nt::NtService::RtlSetUserValueHeap { return Some(set_user_value(call)); }
    let heap_call = nt::decode_heap(call).ok()?;
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    // The initial process heap is one VMM-backed extent namespace. Heap
    // handles and flags remain in the ABI for the later multi-heap policy.
    let mm = (unsafe { cur.mm_ref() }).map(|mm| mm.clone())?;
    Some(match heap_call {
        NtHeapCall::Allocate { heap: _, flags, size } => {
            let page = hal::PAGE_SIZE_BYTES as u64;
            let size = match size.checked_add(page - 1).map(|size| size & !(page - 1)) {
                Some(size) if size != 0 && size <= usize::MAX as u64 => size as usize,
                _ => return Some(STATUS_NO_MEMORY),
            };
            match elf_load::nt_memory::allocate(&mm, None, size, vmm::VmaProt::READ | vmm::VmaProt::WRITE) {
                Ok(allocation) => {
                    let base = allocation.base.as_u64();
                    if flags & HEAP_ADD_USER_INFO != 0 { cur.thread_group.nt_heap_user_info.lock().push((base, flags as u32, 0)); }
                    base
                }
                Err(elf_load::nt_memory::NtStatus::NoMemory) => STATUS_NO_MEMORY,
                Err(_) => STATUS_INVALID_PARAMETER,
            }
        }
        NtHeapCall::Free { heap: _, flags: _, base } => {
            let Some(base) = hal::UserVirtAddr::new(base) else { return Some(0); };
            let Some(info) = elf_load::nt_memory::query(&mm, base).ok() else { return Some(0); };
            match elf_load::nt_memory::free(&mm, elf_load::nt_memory::NtAllocation { base, size: info.size, protection: info.protection }) {
                elf_load::nt_memory::NtStatus::Success => { cur.thread_group.nt_heap_user_info.lock().retain(|entry| entry.0 != base.as_u64()); 1 }
                _ => 0,
            }
        }
        NtHeapCall::Reallocate { heap: _, flags, base, size } => {
            let page = hal::PAGE_SIZE_BYTES as u64;
            let Some(size) = size.checked_add(page - 1).map(|size| size & !(page - 1)).filter(|size| *size != 0 && *size <= usize::MAX as u64) else { return Some(0); };
            let Some(old_base) = hal::UserVirtAddr::new(base) else { return Some(0); };
            let Ok(old_info) = elf_load::nt_memory::query(&mm, old_base) else { return Some(0); };
            let Ok(new) = elf_load::nt_memory::allocate(&mm, None, size as usize, vmm::VmaProt::READ | vmm::VmaProt::WRITE) else { return Some(0); };
            let copy_len = core::cmp::min(old_info.size, size as usize);
            let mut bytes = alloc::vec![0u8; copy_len];
            if uaccess::copy_from_user(&mut bytes, old_base.as_u64()).is_err() || uaccess::copy_to_user(new.base.as_u64(), &bytes).is_err() {
                let _ = elf_load::nt_memory::free(&mm, new);
                return Some(0);
            }
            let _ = elf_load::nt_memory::free(&mm, elf_load::nt_memory::NtAllocation { base: old_base, size: old_info.size, protection: old_info.protection });
            let mut user_info = cur.thread_group.nt_heap_user_info.lock();
            if let Some(entry) = user_info.iter_mut().find(|entry| entry.0 == old_base.as_u64()) { entry.0 = new.base.as_u64(); } else if flags & HEAP_ADD_USER_INFO != 0 { user_info.push((new.base.as_u64(), flags as u32, 0)); }
            new.base.as_u64()
        }
        NtHeapCall::Size { heap: _, flags: _, base } => {
            let Some(base) = hal::UserVirtAddr::new(base) else { return Some(u64::MAX); };
            match elf_load::nt_memory::query(&mm, base) { Ok(info) => info.size as u64, Err(_) => u64::MAX }
        }
    })
}

fn create_heap(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let _ = (call.args.a0, call.args.a1, call.args.a2, call.args.a3, call.args.a4, call.args.a5);
    1
}

fn destroy_heap(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return call.args.a0; };
    if !cur.is_nt_personality() { return call.args.a0; }
    if call.args.a0 == 1 { return 1; }
    call.args.a0
}

fn get_process_heaps(call: NtCall) -> u64 {
    if call.args.a0 == 0 { return 1; }
    if call.args.a1 == 0 { return 0; }
    if uaccess::put_user_u64(call.args.a1, 1).is_err() { return 0; }
    1
}

fn get_user_info(call: NtCall) -> u64 {
    if call.args.a0 != 1 || call.args.a2 == 0 || call.args.a3 == 0 || call.args.a4 == 0 { return 0; }
    let Some(cur) = sched::live::current() else { return 0; };
    if !cur.is_nt_personality() { return 0; }
    let Some(base) = hal::UserVirtAddr::new(call.args.a2) else { return 0; };
    let Some((_, flags, value)) = cur.thread_group.nt_heap_user_info.lock().iter().find(|entry| entry.0 == base.as_u64()).copied() else { return 0; };
    if uaccess::put_user_u64(call.args.a3, value).is_err() || uaccess::put_user_u32(call.args.a4, flags & !(HEAP_ADD_USER_INFO as u32)).is_err() { return 0; }
    1
}

fn set_user_value(call: NtCall) -> u64 {
    if call.args.a0 != 1 || call.args.a2 == 0 { return 0; }
    let Some(cur) = sched::live::current() else { return 0; };
    if !cur.is_nt_personality() { return 0; }
    let mut user_info = cur.thread_group.nt_heap_user_info.lock();
    let Some(entry) = user_info.iter_mut().find(|entry| entry.0 == call.args.a2) else { return 0; };
    entry.2 = call.args.a3;
    1
}
