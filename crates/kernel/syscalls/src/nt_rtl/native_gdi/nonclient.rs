use alloc::vec::Vec;
use syscall::nt_native_gdi as abi;

/// Dots per inch the profile is quoted at before any per-monitor scaling.
pub(crate) const DEFAULT_DPI: u32 = 96;

/// Build canonical settings at the resolution a caller named, then launch the
/// native font-normalization callback.
/// # C: O(1), fixed 584-byte callback payload
pub(crate) fn begin_nonclient_at(output: u64, size: u32, dpi: u32) -> u64 {
    begin(output, size, None, dpi)
}

/// Normalize font-dependent system metrics on the same native callback Task.
/// # C: O(1), fixed 584-byte callback payload
pub(crate) fn begin_system_metric(index: u32) -> u64 {
    if !abi::system_metric_needs_font(index) { return 0; }
    begin(0, abi::NONCLIENT_BYTES, Some(index), DEFAULT_DPI)
}

fn begin(output: u64, size: u32, metric: Option<u32>, dpi: u32) -> u64 {
    // The live settings record, not the default one: a client that wrote the
    // nonclient metrics must read back what it wrote.
    let Some(profile) = crate::nt_nonclient_raw::kernel::live_profile(size, dpi) else { return 0; };
    let head = core::mem::size_of::<abi::QueryRequest>();
    let mut request = abi::QueryRequest { version: abi::VERSION, size: head as u32, dc: 0,
        kind: abi::QUERY_NONCLIENT, flags: 0, height: 0, width: 0, weight: 0, italic: 0,
        first: 0, count: abi::NONCLIENT_BYTES / 2, input: 0, output, table: 0, offset: 0, capacity: size, reserved: 0,
        aux: 0, value: 0, aux_bytes: 0, reserved2: 0 };
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
