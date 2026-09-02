//! Native user-stack creation boundary for the Windows personality.
#![cfg(target_os = "oxide-kernel")]
use syscall::nt::{NtCall, NtService};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const STATUS_MEMORY_NOT_ALLOCATED: u64 = 0xc000_00a0;
const STATUS_SUCCESS: u64 = 0;
const DEFAULT_COMMIT: u64 = 64 * 1024;
const DEFAULT_RESERVE: u64 = 1 * 1024 * 1024;
const MIN_RESERVE: u64 = 1 * 1024 * 1024;
const RESERVE_GRANULARITY: u64 = 64 * 1024;
const INITIAL_TEB_BYTES: usize = 5 * 8;

/// Validate the INITIAL_TEB output and stack sizing contract.
/// # C: O(1)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlFreeUserStack {
        return Some(free_user_stack(call.args.a0));
    }
    if call.service != NtService::RtlCreateUserStack { return None; }
    Some(create_user_stack(call.args.a0, call.args.a1, call.args.a2 as u32,
        call.args.a3, call.args.a4, call.args.a5))
}

fn free_user_stack(base: u64) -> u64 {
    let Some(base) = hal::UserVirtAddr::new(base) else { return STATUS_INVALID_PARAMETER; };
    let Some(task) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !task.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    // SAFETY: the running NT task owns its address-space reference for this
    // syscall; only the exact VMA returned by stack creation is released.
    let Some(mm) = (unsafe { task.mm_ref() }).map(|mm| mm.clone()) else { return STATUS_INVALID_PARAMETER; };
    let Some(vma) = mm.find_vma(base) else { return STATUS_MEMORY_NOT_ALLOCATED; };
    if vma.start != base { return STATUS_INVALID_PARAMETER; }
    let size = vma.end.as_u64().checked_sub(vma.start.as_u64()).unwrap_or(0);
    if size == 0 || mm.munmap(vma.start, size as usize).is_err() { return STATUS_MEMORY_NOT_ALLOCATED; }
    STATUS_SUCCESS
}

fn create_user_stack(commit: u64, reserve: u64, zero_bits: u32,
    commit_align: u64, reserve_align: u64, output: u64) -> u64 {
    if output == 0 || commit_align == 0 || reserve_align == 0
        || !commit_align.is_power_of_two() || !reserve_align.is_power_of_two()
        || zero_bits >= 64 {
        return STATUS_INVALID_PARAMETER;
    }
    let commit = round_or_default(commit, commit_align, DEFAULT_COMMIT);
    let mut reserve = round_or_default(reserve, reserve_align, DEFAULT_RESERVE);
    let Some(minimum) = round_up(MIN_RESERVE, reserve_align) else { return STATUS_INVALID_PARAMETER; };
    if reserve < commit { reserve = commit; }
    if reserve < minimum { reserve = minimum; }
    let Some(reserve) = round_up(reserve, RESERVE_GRANULARITY) else { return STATUS_INVALID_PARAMETER; };
    let Some(task) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !task.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    // SAFETY: the running NT task owns its address-space reference for this
    // syscall; the mapping remains owned by that address space after return.
    let Some(mm) = (unsafe { task.mm_ref() }).map(|mm| mm.clone()) else { return STATUS_INVALID_PARAMETER; };
    let Ok(stack) = mm.mmap(None, reserve as usize, vmm::VmaProt::READ | vmm::VmaProt::WRITE,
        vmm::VmaFlags::PRIVATE, vmm::VmaBacking::Anonymous, false) else { return STATUS_NO_MEMORY; };
    let base = stack.as_u64();
    let stack_base = match base.checked_add(reserve) { Some(value) => value, None => { let _ = mm.munmap(stack, reserve as usize); return STATUS_INVALID_PARAMETER; } };
    let page = hal::PAGE_SIZE_BYTES as u64;
    let Some(stack_limit) = base.checked_add(page.saturating_mul(2)) else { let _ = mm.munmap(stack, reserve as usize); return STATUS_INVALID_PARAMETER; };
    let mut initial = [0u8; INITIAL_TEB_BYTES];
    initial[16..24].copy_from_slice(&stack_base.to_ne_bytes());
    initial[24..32].copy_from_slice(&stack_limit.to_ne_bytes());
    initial[32..40].copy_from_slice(&base.to_ne_bytes());
    if uaccess::copy_to_user(output, &initial).is_err() {
        let _ = mm.munmap(stack, reserve as usize);
        return STATUS_INVALID_PARAMETER;
    }
    let _ = commit;
    STATUS_SUCCESS
}

fn round_or_default(value: u64, align: u64, default: u64) -> u64 {
    round_up(if value == 0 { default } else { value }, align).unwrap_or(u64::MAX)
}

fn round_up(value: u64, align: u64) -> Option<u64> {
    value.checked_add(align - 1).map(|value| value & !(align - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_sizes_follow_native_alignment_and_floor_rules() {
        assert_eq!(round_or_default(0, 0x1000, DEFAULT_COMMIT), DEFAULT_COMMIT);
        assert_eq!(round_or_default(0x11000, 0x4000, DEFAULT_COMMIT), 0x14000);
        assert_eq!(round_up(0x20000, RESERVE_GRANULARITY), Some(0x20000));
        assert_eq!(round_up(0x20001, RESERVE_GRANULARITY), Some(0x30000));
    }
}
