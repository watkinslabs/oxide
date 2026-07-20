#![cfg(target_os = "oxide-kernel")]

/// Linux `SWAP_FLAG_PRIO_MASK`: low fifteen bits encode an explicit priority.
pub(super) const SWAP_FLAG_PRIO_MASK: u64 = 0x7fff;
/// Linux `SWAP_FLAG_PREFER`: select the priority encoded by `SWAP_FLAG_PRIO_MASK`.
pub(super) const SWAP_FLAG_PREFER: u64 = 0x8000;
/// Linux `SWAP_FLAG_DISCARD`: enable queue-backed discard policy.
pub(super) const SWAP_FLAG_DISCARD: u64 = 0x1_0000;
/// Linux `SWAP_FLAG_DISCARD_ONCE`: discard the area at activation time.
pub(super) const SWAP_FLAG_DISCARD_ONCE: u64 = 0x2_0000;
/// Linux `SWAP_FLAG_DISCARD_PAGES`: discard page clusters after release.
pub(super) const SWAP_FLAG_DISCARD_PAGES: u64 = 0x4_0000;

/// Flags implemented by the canonical PMM swap-area owner.
pub(super) const SUPPORTED_SWAPON_FLAGS: u64 = SWAP_FLAG_PRIO_MASK
    | SWAP_FLAG_PREFER
    | SWAP_FLAG_DISCARD
    | SWAP_FLAG_DISCARD_ONCE
    | SWAP_FLAG_DISCARD_PAGES;
