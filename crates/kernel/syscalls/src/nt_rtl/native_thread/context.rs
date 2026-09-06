use sched::{Task, nt_callback::Completion, nt_native_thread::Phase};
use syscall::nt_native_thread as abi;

#[cfg(target_arch = "x86_64")]
type Registers = hal_x86_64::PtRegs;
#[cfg(target_arch = "aarch64")]
type Registers = hal_aarch64::SvcFrame;

fn registers() -> *mut Registers {
    #[cfg(target_arch = "x86_64")] { hal_x86_64::current_pt_regs() }
    #[cfg(target_arch = "aarch64")] { hal_aarch64::current_svc_frame() }
}

pub(super) fn factory(task: &Task, entry: u64, ret: u64, request: abi::FactoryRequest) -> Result<u64, u64> {
    let frame = registers();
    if frame.is_null() { return Err(abi::INVALID); }
    // SAFETY: active syscall frame is exclusively owned by this dispatch.
    let frame = unsafe { &mut *frame };
    #[cfg(target_arch = "x86_64")]
    let (sp, link) = (frame.rsp, 0);
    #[cfg(target_arch = "aarch64")]
    let (sp, link) = (frame.sp_el0, frame.x30);
    let payload = sp.checked_sub(32).ok_or(abi::INVALID)? & !15;
    let call_sp = payload.checked_sub(40).ok_or(abi::INVALID)?;
    for (offset, value) in [(0, request.creator), (8, request.generation)] {
        uaccess::put_user_u64(payload + offset, value).map_err(|_| abi::INVALID)?;
    }
    #[cfg(target_arch = "x86_64")]
    uaccess::put_user_u64(call_sp, ret).map_err(|_| abi::INVALID)?;
    let saved = crate::nt_callback_frame::capture(frame, task, Completion { kind: abi::CALLBACK_KIND, argument: link });
    if !task.nt_callback_stack.lock().push(saved) { return Err(abi::NO_MEMORY); }
    #[cfg(target_arch = "x86_64")]
    { frame.rip = entry; frame.rsp = call_sp; frame.rcx = payload; }
    #[cfg(target_arch = "aarch64")]
    { frame.elr_el1 = entry; frame.sp_el0 = call_sp & !15; frame.gp[0] = payload; frame.x30 = ret; }
    #[cfg(target_arch = "x86_64")] { Ok(0) }
    #[cfg(target_arch = "aarch64")] { Ok(payload) }
}

pub(super) fn complete(task: &Task, status: u64) -> u64 {
    let frame = registers();
    if frame.is_null() { return abi::INVALID; }
    let mut callbacks = task.nt_callback_stack.lock();
    // Native completion owns only its tagged top continuation.
    let Some(saved) = callbacks.pop() else { return abi::INVALID; };
    if saved.completion.kind != abi::CALLBACK_KIND {
        let _ = callbacks.push(saved); return abi::INVALID;
    }
    drop(callbacks);
    task.nt_native_thread.lock().request = None;
    // SAFETY: active syscall frame remains private until return-to-user.
    unsafe {
        crate::nt_callback_frame::restore(&mut *frame, task, &saved);
        #[cfg(target_arch = "x86_64")]
        { (*frame).rax = status; }
        #[cfg(target_arch = "aarch64")]
        { (*frame).x30 = saved.completion.argument; (*frame).retval = status; }
    }
    status
}

pub(super) fn enter(task: &Task) -> u64 {
    let frame = registers();
    if frame.is_null() { return abi::INVALID; }
    let Some((_, _, pe_return)) = super::creation::factory(task) else { return abi::INVALID; };
    let child = match task.nt_native_thread.lock().child {
        Some(child) if child.phase == Phase::Published => child,
        _ => return abi::NOT_READY,
    };
    let top = (child.stack + child.size) & !15;
    #[cfg(target_arch = "x86_64")]
    if uaccess::put_user_u64(top - 40, pe_return).is_err() { return abi::INVALID; }
    let mut state = task.nt_native_thread.lock();
    if !state.advance(Phase::Published, Phase::Running) { return abi::INVALID; }
    let mut saved = [0u64; 40];
    const _: () = assert!(core::mem::size_of::<Registers>() <= 320);
    // SAFETY: complete active register frame fits the aligned task-owned buffer.
    unsafe { core::ptr::copy_nonoverlapping(frame.cast::<u8>(), saved.as_mut_ptr().cast::<u8>(), core::mem::size_of::<Registers>()); }
    state.resume = Some(saved);
    // SAFETY: only this child consumes its prepared entry/stack on syscall return.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        { (*frame).rip = child.start; (*frame).rsp = top - 40; (*frame).rcx = child.parameter; }
        #[cfg(target_arch = "aarch64")]
        { (*frame).elr_el1 = child.start; (*frame).sp_el0 = top; (*frame).gp[0] = child.parameter;
          (*frame).retval = child.parameter; (*frame).x18_x29[0] = task.nt_teb(); (*frame).x30 = pe_return; }
    }
    #[cfg(target_arch = "x86_64")] { 0 }
    #[cfg(target_arch = "aarch64")] { child.parameter }
}

pub(super) fn return_native(task: &Task, status: u32) -> u64 {
    let frame = registers();
    // SAFETY: current syscall frame belongs to this native child on this CPU.
    unsafe { return_native_at(task, status, frame) }
}

pub(super) unsafe fn return_native_at(task: &Task, status: u32, frame: *mut Registers) -> u64 {
    if frame.is_null() { return abi::INVALID; }
    let mut state = task.nt_native_thread.lock();
    let Some((saved, status)) = state.finish(status) else { return abi::INVALID; };
    // SAFETY: ENTER copied this exact architecture frame on the same canonical Task.
    unsafe { core::ptr::copy_nonoverlapping(saved.as_ptr().cast::<u8>(), frame.cast::<u8>(), core::mem::size_of::<Registers>()); }
    // SAFETY: syscall return consumes this restored native continuation and result.
    unsafe {
        #[cfg(target_arch = "x86_64")] { (*frame).rax = status as u64; }
        #[cfg(target_arch = "aarch64")] { (*frame).gp[0] = status as u64; (*frame).retval = status as u64; }
    }
    status as u64
}
