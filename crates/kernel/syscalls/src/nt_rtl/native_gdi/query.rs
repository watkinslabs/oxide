use alloc::vec::Vec;
use syscall::nt_native_gdi as abi;

/// Snapshot inputs and preserve the query's DWORD failure domain. # C: O(count)
pub(crate) fn begin_query(mut request: abi::QueryRequest) -> u64 {
    let failure = request.failure();
    if !request.valid() { return failure; }
    let head = core::mem::size_of::<abi::QueryRequest>();
    let input = if request.input == 0 { 0 } else { request.count as usize * 2 };
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(head + input).is_err() { return failure; }
    bytes.resize(head + input, 0);
    if input != 0 && uaccess::copy_from_user(&mut bytes[head..], request.input).is_err() { return failure; }
    super::context::launch_or(&mut bytes, failure, |payload, bytes| {
        if request.input != 0 { request.input = payload + head as u64; }
        // SAFETY: QueryRequest is a fully initialized integer-only repr(C) record without padding.
        bytes[..head].copy_from_slice(unsafe { core::slice::from_raw_parts((&request as *const abi::QueryRequest).cast(), head) });
    })
}

pub(super) fn copy_result(task: &sched::Task, request: u64, output: u64) -> u64 {
    let mut stack = task.nt_callback_stack.lock();
    let Some(frame) = stack.pop() else { return abi::INVALID; };
    let active = frame.completion.kind == abi::TOKEN;
    let _ = stack.push(frame);
    drop(stack);
    if !active { return abi::INVALID; }
    let mut req = [0u8; core::mem::size_of::<abi::QueryRequest>()];
    let mut out = [0u8; core::mem::size_of::<abi::QueryOutput>()];
    if uaccess::copy_from_user(&mut req, request).is_err() || uaccess::copy_from_user(&mut out, output).is_err() { return abi::INVALID; }
    // SAFETY: full initialized byte copies cover integer-only query records, with unaligned loads.
    let req = unsafe { req.as_ptr().cast::<abi::QueryRequest>().read_unaligned() };
    // SAFETY: full initialized byte copy covers the integer-only query result record.
    let out = unsafe { out.as_ptr().cast::<abi::QueryOutput>().read_unaligned() };
    if !req.accepts(&out) { return abi::INVALID; }
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(out.length as usize).is_err() { return abi::INVALID; }
    bytes.resize(out.length as usize, 0);
    if out.length != 0 && (uaccess::copy_from_user(&mut bytes, out.data).is_err()
        || uaccess::copy_to_user(req.output, &bytes).is_err()) { return abi::INVALID; }
    0
}
