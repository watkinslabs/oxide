//! Transfer an admitted canonical object snapshot; no object lookup or retained state.
const LOWEST_USER_BUFFER: u64 = 0x10000;

pub(super) fn complete_query(query: Result<ipc::win32_gdi::FontQuery, ipc::win32_gdi::GdiError>, output: u64,
    write: impl FnOnce(u64, &[u8]) -> bool, no_access: impl FnOnce()) -> u64 {
    let Ok(query) = query else { return 0; };
    copy_query(&query.bytes[..query.count], output, write, no_access)
}

pub(super) fn copy_query(bytes: &[u8], output: u64,
    write: impl FnOnce(u64, &[u8]) -> bool, no_access: impl FnOnce()) -> u64 {
    if output == 0 { return bytes.len() as u64; }
    if output < LOWEST_USER_BUFFER { no_access(); return 0; }
    if !bytes.is_empty() && !write(output, bytes) { return 0; }
    bytes.len() as u64
}

#[cfg(test)]
#[path = "tests/transfer.rs"]
mod tests;
