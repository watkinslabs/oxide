use alloc::vec::Vec;
use syscall::nt_native_gdi as abi;

/// Build canonical settings before launching the existing native font-normalization callback.
/// # C: O(1), fixed 584-byte callback payload
pub(crate) fn begin_nonclient(output: u64, size: u32) -> u64 {
    begin(output, size, None)
}

/// Normalize font-dependent system metrics on the same native callback Task.
/// # C: O(1), fixed 584-byte callback payload
pub(crate) fn begin_system_metric(index: u32) -> u64 {
    if !abi::system_metric_needs_font(index) { return 0; }
    begin(0, abi::NONCLIENT_BYTES, Some(index))
}

fn begin(output: u64, size: u32, metric: Option<u32>) -> u64 {
    let Ok(profile) = ipc::win32_gdi::nonclient_defaults(size) else { return 0; };
    let head = core::mem::size_of::<abi::QueryRequest>();
    let mut request = abi::QueryRequest { version: abi::VERSION, size: head as u32, dc: 0,
        kind: abi::QUERY_NONCLIENT, flags: 0, height: 0, width: 0, weight: 0, italic: 0,
        first: 0, count: abi::NONCLIENT_BYTES / 2, input: 0, output, table: 0, offset: 0, capacity: size, reserved: 0 };
    if let Some(index) = metric { request.kind = abi::QUERY_SYSTEM_METRIC; request.first = index; request.capacity = 0; }
    if !request.valid() { return 0; }
    let mut copy = Vec::new();
    if copy.try_reserve_exact(head + profile.len()).is_err() { return 0; }
    copy.resize(head, 0); copy.extend_from_slice(&profile);
    super::context::launch(&mut copy, |payload, copy| {
        request.input = payload + head as u64;
        // SAFETY: fixed repr(C) request is fully initialized integer fields without padding.
        copy[..head].copy_from_slice(unsafe { core::slice::from_raw_parts((&request as *const abi::QueryRequest).cast(), head) });
    })
}
