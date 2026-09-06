//! Completion routing; each transaction owner retains its own pending command.
use super::{create, position, send, CALLBACK_INIT_BUILTIN_CLASSES};

pub(crate) fn complete_callback(completion: sched::nt_callback::Completion, result: u64) -> u64 {
    if completion.kind == CALLBACK_INIT_BUILTIN_CLASSES {
        // The client's builtin-class initialisation answers an NTSTATUS the
        // reference discards; the desktop window the caller asked for is the
        // result of the suspended syscall.
        klog::write_raw(b"[WINDOWS-INIT-BUILTIN-CLASSES] status=");
        klog::write_hex_u64(result);
        klog::write_raw(b" desktop=");
        klog::write_hex_u64(completion.argument);
        klog::write_raw(b"\n");
        return completion.argument;
    }
    if send::handles_callback(completion.kind) { send::complete_callback(completion, result) }
    else if position::handles_callback(completion.kind) { position::complete_position_callback(completion, result) }
    else { create::complete_callback(completion, result) }
}
