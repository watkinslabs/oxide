use syscall::errno::Errno;

const PAGE_MASK: u64 = !(hal::PAGE_SIZE_BYTES - 1);

/// Validate `[ptr, ptr + len)` as a readable user buffer. # C: O(1)
pub(crate) fn validate_user_buf(ptr: u64, len: u64, align: u64) -> Result<(), i64> {
    if ptr == 0 {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    if align > 1 && (ptr & (align - 1)) != 0 {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    let end = ptr.checked_add(len).ok_or(-(Errno::Efault.as_i32() as i64))?;
    if end > hal::USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    Ok(())
}

/// Validate `[ptr, ptr + len)` as a writable user buffer. # C: O(N_pages * log N_vmas)
pub(crate) fn validate_user_buf_writable(ptr: u64, len: u64, align: u64) -> Result<(), i64> {
    validate_user_buf(ptr, len, align)?;
    #[cfg(target_os = "oxide-kernel")]
    {
        use hal::UserVirtAddr;
        use vmm::VmaProt;
        if len == 0 { return Ok(()); }
        let cur = sched::live::current().ok_or(-(Errno::Efault.as_i32() as i64))?;
        // SAFETY: current task mm is stable for this syscall while preemption is disabled.
        let mm = unsafe { cur.mm_ref() }.ok_or(-(Errno::Efault.as_i32() as i64))?.clone();
        let mut va = ptr & PAGE_MASK;
        let end_inclusive = ptr + len - 1;
        while va <= (end_inclusive & PAGE_MASK) {
            let uva = UserVirtAddr::new(va).ok_or(-(Errno::Efault.as_i32() as i64))?;
            match mm.find_vma(uva) {
                Some(v) if v.prot.contains(VmaProt::WRITE) => {}
                _ => return Err(-(Errno::Efault.as_i32() as i64)),
            }
            va = va.checked_add(hal::PAGE_SIZE_BYTES).ok_or(-(Errno::Efault.as_i32() as i64))?;
        }
    }
    Ok(())
}

/// Validate `[ptr, ptr + len)` as a readable user buffer. # C: O(N_pages * log N_vmas)
pub(crate) fn validate_user_buf_readable(ptr: u64, len: u64, align: u64) -> Result<(), i64> {
    validate_user_buf(ptr, len, align)?;
    #[cfg(target_os = "oxide-kernel")]
    {
        use hal::UserVirtAddr;
        use vmm::VmaProt;
        if len == 0 { return Ok(()); }
        let cur = sched::live::current().ok_or(-(Errno::Efault.as_i32() as i64))?;
        // SAFETY: current task mm is stable for this syscall while preemption is disabled.
        let mm = unsafe { cur.mm_ref() }.ok_or(-(Errno::Efault.as_i32() as i64))?.clone();
        let mut va = ptr & PAGE_MASK;
        let end_inclusive = ptr + len - 1;
        while va <= (end_inclusive & PAGE_MASK) {
            let uva = UserVirtAddr::new(va).ok_or(-(Errno::Efault.as_i32() as i64))?;
            match mm.find_vma(uva) {
                Some(v) if v.prot.contains(VmaProt::READ) => {}
                _ => return Err(-(Errno::Efault.as_i32() as i64)),
            }
            va = va.checked_add(hal::PAGE_SIZE_BYTES).ok_or(-(Errno::Efault.as_i32() as i64))?;
        }
    }
    Ok(())
}
