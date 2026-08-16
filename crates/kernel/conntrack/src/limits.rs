//! Sizing constants. Every one of these is a ceiling on memory an attacker
//! can make the kernel allocate, so none is a soft hint.

/// Conntrack hash buckets.
pub const CT_HASH_BUCKETS: usize = 4096;

/// Default entry ceiling. The reference derives it from RAM; a fixed value
/// here is the same contract with a fixed budget.
pub const CT_MAX_DEFAULT: u64 = CT_HASH_BUCKETS as u64 * 8;

/// Expectation hash buckets — the reference's `htable_size / 256`.
pub const EXPECT_HASH_BUCKETS: usize = CT_HASH_BUCKETS / 256;

/// Global expectation ceiling.
pub const EXPECT_MAX: usize = EXPECT_HASH_BUCKETS * 4;

/// Per-master, per-class expectation ceiling when a helper states none.
pub const EXPECT_MAX_CNT: u32 = 255;

/// Default expectation class.
pub const EXPECT_CLASS_DEFAULT: u8 = 0;

/// Largest expectation class index a helper may declare.
pub const EXPECT_CLASS_MAX: u8 = 3;

/// Attempts NAT makes to find a free port before halving its window.
pub const NAT_MAX_ATTEMPTS: u32 = 128;

/// Attempts remaining below which NAT may evict a closing TCP entry to free
/// the port it holds.
pub const NAT_HARDER_THRESH: u32 = NAT_MAX_ATTEMPTS / 4;

/// Ephemeral port window NAT falls back to when no range is specified.
pub const NAT_PORT_LOW_MIN:  u16 = 1;
pub const NAT_PORT_LOW_MAX:  u16 = 511;
pub const NAT_PORT_MID_MIN:  u16 = 600;
pub const NAT_PORT_MID_MAX:  u16 = 1023;
pub const NAT_PORT_HIGH_MIN: u16 = 1024;
pub const NAT_PORT_HIGH_MAX: u16 = 65535;

/// Source port below which the low/mid privileged windows apply.
pub const NAT_PRIVILEGED_PORT: u16 = 1024;
/// Source port below which the low window rather than the mid one applies.
pub const NAT_LOW_WINDOW_PORT: u16 = 512;
