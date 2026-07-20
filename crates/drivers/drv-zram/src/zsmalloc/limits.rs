//! Linux zsmalloc layout limits.

/// Linux zsmalloc uses eight class-index bits.
pub(super) const ZS_CLASS_BITS: usize = 8;
/// `CONFIG_ZSMALLOC_CHAIN_SIZE`: largest page chain comprising one zspage.
pub(super) const ZS_MAX_PAGES_PER_ZSPAGE: usize = 8;
/// Linux zsmalloc's minimum object size, before its handle-index constraint.
pub(super) const ZS_MIN_OBJECT_BYTES: usize = 32;
/// One class interval, equal to Linux `ZS_SIZE_CLASS_DELTA`.
pub(super) const ZS_CLASS_DELTA_BYTES: usize = (hal::PAGE_SIZE_BYTES as usize) >> ZS_CLASS_BITS;
/// Linux `ZS_FULLNESS_THRESHOLD_FRAC`: boundary for compactable zspages.
pub(super) const ZS_FULLNESS_THRESHOLD_FRAC: usize = 4;
/// Number of Linux zsmalloc fullness states.
pub(super) const ZS_FULLNESS_GROUP_COUNT: usize = 5;
