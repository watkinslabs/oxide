use alloc::vec::Vec;
use syscall::nt_native_gdi as abi;

/// Snapshot bounded UTF-16 and redirect through the registered same-task callback. # C: O(count)
pub(crate) fn begin_measure(mut request: abi::MeasureRequest) -> u64 {
    let Some(bytes) = request.payload_bytes() else { return 0; };
    let head = core::mem::size_of::<abi::MeasureRequest>();
    let mut copy = Vec::new();
    if copy.try_reserve_exact(bytes).is_err() { return 0; }
    copy.resize(bytes, 0);
    if request.count != 0 && uaccess::copy_from_user(&mut copy[head..], request.text).is_err() { return 0; }
    super::context::launch(&mut copy, |payload, copy| {
        request.text = payload + head as u64;
        // SAFETY: repr(C) measurement header is entirely initialized integer fields without padding.
        copy[..head].copy_from_slice(unsafe { core::slice::from_raw_parts((&request as *const abi::MeasureRequest).cast(), head) });
    })
}

pub(super) fn copy_result(task: &sched::Task, request: u64, output: u64) -> u64 {
    let mut stack = task.nt_callback_stack.lock();
    let Some(frame) = stack.pop() else { return abi::INVALID; };
    let active = frame.completion.kind == abi::TOKEN;
    let _ = stack.push(frame);
    drop(stack);
    if !active { return abi::INVALID; }
    let mut request_bytes = [0u8; core::mem::size_of::<abi::MeasureRequest>()];
    let mut output_bytes = [0u8; core::mem::size_of::<abi::MeasureOutput>()];
    if uaccess::copy_from_user(&mut request_bytes, request).is_err()
        || uaccess::copy_from_user(&mut output_bytes, output).is_err() { return abi::INVALID; }
    // SAFETY: complete initialized byte copies cover repr(C) integer-only records; unaligned reads allowed.
    let request = unsafe { request_bytes.as_ptr().cast::<abi::MeasureRequest>().read_unaligned() };
    // SAFETY: complete initialized bytes cover the integer-only output record; no references escape.
    let output = unsafe { output_bytes.as_ptr().cast::<abi::MeasureOutput>().read_unaligned() };
    if !request.valid() || output.reserved != 0 || output.count != request.count || output.fit > request.count
        || output.width < 0 || output.height < 0 { return abi::INVALID; }
    if request.kind == abi::MEASURE_METRICS {
        return if uaccess::copy_to_user(request.metrics, &output.metrics).is_ok() { 0 } else { abi::INVALID };
    }
    let count = request.count as usize;
    if output.cumulative.checked_add(count as u64 * 4).is_none() { return abi::INVALID; }
    let mut advances = Vec::new();
    if advances.try_reserve_exact(count * 4).is_err() { return abi::INVALID; }
    advances.resize(count * 4, 0);
    if count != 0 && uaccess::copy_from_user(&mut advances, output.cumulative).is_err() { return abi::INVALID; }
    let Some(copied) = output.extent_copy_count(&request, &advances) else { return abi::INVALID; };
    if request.cumulative != 0 && copied != 0 && uaccess::copy_to_user(request.cumulative, &advances[..copied * 4]).is_err() { return abi::INVALID; }
    if request.fit != 0 && uaccess::put_user_u32(request.fit, output.fit).is_err() { return abi::INVALID; }
    let mut extent = [0u8; 8];
    extent[..4].copy_from_slice(&output.width.to_le_bytes()); extent[4..].copy_from_slice(&output.height.to_le_bytes());
    if uaccess::copy_to_user(request.extent, &extent).is_ok() { 0 } else { abi::INVALID }
}
