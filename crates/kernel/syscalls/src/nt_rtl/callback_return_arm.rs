//! ARM NtCallbackReturn restores the Task-owned PC/SP/LR continuation.
use syscall::nt::NtCall;

const NO_CALLBACK: u64 = 0xc000_0258;
const ACCESS_VIOLATION: u64 = 0xc000_0005;
const RESULT_BYTES: u64 = 8;

/// Read result before removing a continuation; faults cannot consume it.
/// Restore control before lifecycle completion, which may start another callback.
/// # C: O(1) plus lifecycle completion
pub(crate) fn callback_return(call: NtCall) -> u64 {
    if call.args.a1 != RESULT_BYTES { return NO_CALLBACK; }
    let regs = hal_aarch64::current_svc_frame();
    if regs.is_null() { return NO_CALLBACK; }
    let Some(task) = sched::live::current().filter(|task| task.is_nt_personality()) else { return NO_CALLBACK; };
    let Ok(result) = uaccess::get_user_u64(call.args.a0) else { return ACCESS_VIOLATION; };
    let mut callbacks = task.nt_callback_stack.lock();
    let Some(saved) = callbacks.pop() else { return NO_CALLBACK; };
    // Native ELF callbacks have their own completion service and must retain
    // their continuation if a PE callback-return is attempted while suspended.
    if matches!(saved.completion.kind, syscall::nt_native_gdi::TOKEN | syscall::nt_native_thread::CALLBACK_KIND) {
        let _ = callbacks.push(saved);
        return NO_CALLBACK;
    }
    drop(callbacks);
    // SAFETY: this dispatch owns the live SVC frame and popped Task continuation.
    let frame = unsafe { &mut *regs };
    crate::nt_callback_frame::restore(frame, task, &saved);
    frame.gp[0] = result;
    frame.retval = result;
    if saved.completion.kind != 0 { return crate::nt_window::complete_callback(saved.completion, result); }
    result
}
