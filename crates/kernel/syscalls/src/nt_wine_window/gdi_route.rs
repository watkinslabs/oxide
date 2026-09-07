//! Both ordinal entries reach GDI decoding through one normalized array.
#[cfg(target_os = "oxide-kernel")]
use super::gdi_raw;

/// # C: O(1) decode plus the operation's own cost
#[cfg(target_os = "oxide-kernel")]
pub(super) fn descriptor(ordinal: u64, args: &[u64; 17]) -> Option<u64> {
    let mut packed = [0; 9];
    packed.copy_from_slice(&args[..9]);
    gdi_raw::decode(ordinal, &packed).map(gdi_raw::kernel::dispatch)
}
