use alloc::vec::Vec;
use sched::{Task, nt_callback::Completion, nt_native_thread::Phase};
use syscall::nt_native_gdi as abi;

/// Redirect this PE text syscall only after all bounded usercopies succeed. # C: O(text units)
pub(crate) fn begin(mut request: abi::TextRequest) -> u64 {
    let Some(bytes) = request.payload_bytes() else { return 0; };
    let mut copy = Vec::new();
    if copy.try_reserve_exact(bytes).is_err() { return 0; }
    copy.resize(bytes, 0);
    let head = core::mem::size_of::<abi::TextRequest>();
    let end = head + request.count as usize * 2;
    if request.count != 0 && uaccess::copy_from_user(&mut copy[head..end], request.text).is_err() { return 0; }
    if request.advances != 0 {
        let start = (end + 3) & !3;
        if request.count != 0 && uaccess::copy_from_user(&mut copy[start..], request.advances).is_err() { return 0; }
    }
    launch(&mut copy, |payload, copy| {
        request.text = payload + head as u64;
        if request.advances != 0 { request.advances = payload + ((end + 3) & !3) as u64; }
        // SAFETY: repr(C) header contains initialized integer fields without padding.
        copy[..head].copy_from_slice(unsafe { core::slice::from_raw_parts((&request as *const abi::TextRequest).cast(), head) });
    })
}

pub(super) fn launch(copy: &mut [u8], patch: impl FnOnce(u64, &mut [u8])) -> u64 {
    launch_or(copy, 0, patch)
}

pub(super) fn launch_or(copy: &mut [u8], failure: u64, patch: impl FnOnce(u64, &mut [u8])) -> u64 {
    let Some(task) = sched::live::current() else { return failure; };
    if !task.is_nt_personality() || task.nt_teb() == 0 { return failure; }
    let native_ready = match task.nt_native_thread.lock().child {
        Some(child) => child.phase == Phase::Running,
        None => task.tid == task.tgid.load(core::sync::atomic::Ordering::Acquire),
    };
    if !native_ready || crate::nt_native_thread::factory(task).is_none() { return failure; }
    let Some((entry, ret)) = super::service::registration(task) else { return failure; };
    let regs = crate::arch_frame::current_user_regs();
    if regs.is_null() { return failure; }
    // SAFETY: active syscall frame belongs exclusively to this current Task.
    let frame = unsafe { &mut *regs };
    #[cfg(target_arch = "x86_64")]
    let (sp, link) = (frame.rsp, 0);
    #[cfg(target_arch = "aarch64")]
    let (sp, link) = (frame.sp_el0, frame.x30);
    #[cfg(target_arch = "x86_64")]
    let arch = abi::CallbackArch::X86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = abi::CallbackArch::Aarch64;
    let Some((payload, call_sp)) = abi::callback_storage_layout(sp, copy.len(), arch) else { return failure; };
    patch(payload, copy);
    if uaccess::copy_to_user(payload, copy).is_err() { return failure; }
    #[cfg(target_arch = "x86_64")]
    if uaccess::put_user_u64(call_sp, ret).is_err() { return failure; }
    let saved = crate::nt_callback_frame::capture(frame, task, Completion { kind: abi::TOKEN, argument: link });
    if !task.nt_callback_stack.lock().push(saved) { return failure; }
    #[cfg(target_arch = "x86_64")]
    { frame.rip = entry; frame.rsp = call_sp; frame.rcx = payload; }
    #[cfg(target_arch = "aarch64")]
    { frame.elr_el1 = entry; frame.sp_el0 = call_sp; frame.gp[0] = payload; frame.retval = payload; frame.x30 = ret; }
    #[cfg(target_arch = "x86_64")] { 0 }
    #[cfg(target_arch = "aarch64")] { payload }
}

pub(super) fn complete(task: &Task, result: u64) -> u64 {
    let regs = crate::arch_frame::current_user_regs();
    if regs.is_null() { return abi::INVALID; }
    let mut stack = task.nt_callback_stack.lock();
    let Some(saved) = stack.pop() else { return abi::INVALID; };
    if saved.completion.kind != abi::TOKEN { let _ = stack.push(saved); return abi::INVALID; }
    drop(stack);
    let result = result as u32 as u64;
    // SAFETY: completion owns this live syscall frame and its tagged LIFO continuation.
    unsafe {
        crate::nt_callback_frame::restore(&mut *regs, task, &saved);
        #[cfg(target_arch = "x86_64")]
        { (*regs).rax = result; }
        #[cfg(target_arch = "aarch64")]
        { (*regs).x30 = saved.completion.argument; (*regs).gp[0] = result; (*regs).retval = result; }
    }
    result
}
