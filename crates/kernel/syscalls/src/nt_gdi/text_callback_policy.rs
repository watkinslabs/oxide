//! Raw text-state copyout ordering and canonical-to-Windows result encoding; 31ge§1.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OldValueEncoding { Xrgb, RawDword }

/// Owner result is obtained before this helper; failed copyout never rolls back mutation.
/// # C: O(1) plus bounded four-byte copyout
pub(crate) fn set_dword_result(previous: u64, result: Result<u32, u64>, encoding: OldValueEncoding,
    write: impl FnOnce(u64, u32) -> bool) -> u64 {
    let Ok(old) = result else { return 0; };
    if previous == 0 { return 0; }
    let old = match encoding {
        OldValueEncoding::Xrgb => ((old & 0xff) << 16) | (old & 0xff00) | ((old >> 16) & 0xff),
        OldValueEncoding::RawDword => old,
    };
    u64::from(write(previous, old))
}

/// Snapshot canonical position first; optional old-POINT copy must precede mutation.
/// # C: O(1) plus bounded eight-byte copyout and owner mutation
pub(crate) fn move_to_result(previous: u64, snapshot: Result<(i32, i32), u64>,
    copy: impl FnOnce(u64, &[u8; 8]) -> bool, update: impl FnOnce() -> bool) -> u64 {
    let Ok((x, y)) = snapshot else { return 0; };
    if previous != 0 {
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&x.to_le_bytes()); bytes[4..].copy_from_slice(&y.to_le_bytes());
        if !copy(previous, &bytes) { return 0; }
    }
    u64::from(update())
}

#[cfg(test)]
#[path = "tests/text_callback_policy.rs"]
mod tests;
