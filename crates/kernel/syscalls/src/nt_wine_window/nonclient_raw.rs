//! Bounded SPI nonclient-metrics ingress; other system-parameter actions remain unclaimed.
pub(crate) const SYSTEM_PARAMETERS_INFO: u64 = 0x15cb;
pub(crate) const GET_NONCLIENT_METRICS: u32 = 0x29;
pub(crate) const LEGACY_BYTES: u32 = 500;
pub(crate) const MODERN_BYTES: u32 = 504;

/// Decode before usercopy; caller record cbSize, not uiParam, controls output length.
/// # C: O(1) plus four-byte read and one native owner call
pub(crate) fn route(ordinal: u64, args: &[u64], read_size: impl FnOnce(u64) -> Option<u32>,
    begin: impl FnOnce(u64, u32) -> u64) -> Option<u64> {
    if ordinal != SYSTEM_PARAMETERS_INFO { return None; }
    let action = *args.first()? as u32;
    if action != GET_NONCLIENT_METRICS { return None; }
    if args.len() < 4 || args[2] == 0 || args[2].checked_add(4).is_none() { return Some(0); }
    let Some(size) = read_size(args[2]) else { return Some(0); };
    if !matches!(size, LEGACY_BYTES | MODERN_BYTES) || args[2].checked_add(size as u64).is_none() { return Some(0); }
    Some(begin(args[2], size))
}

#[cfg(test)]
#[path = "tests/nonclient_raw.rs"]
mod tests;
