// Sizes, counts and timeout classes. Contract-owned magnitudes only.

use crate::uapi::SHA512_DIGEST_SIZE;

/// Largest command or response the character device accepts.
pub const TPM_BUFSIZE: usize = 4096;
/// Largest digest any supported bank produces.
pub const MAX_DIGEST_SIZE: usize = SHA512_DIGEST_SIZE;
/// Largest number of simultaneously allocated PCR banks.
pub const MAX_PCR_BANKS: usize = 8;
/// PCR indices defined by the platform profile: 0..PLATFORM_PCR.
pub const PLATFORM_PCR: usize = 24;
/// Bytes needed for a PCR selection bitmap covering PLATFORM_PCR indices.
pub const PCR_SELECT_MIN: usize = PLATFORM_PCR.div_ceil(8);
/// Random bytes obtainable from one GetRandom round trip.
pub const MAX_RNG_DATA: usize = 128;
/// Backing store a resource-manager space reserves for saved contexts.
pub const SPACE_BUFFER_SIZE: usize = 16384;
/// Saved object contexts a single space may hold.
pub const SPACE_CONTEXT_SLOTS: usize = 3;
/// Saved sessions a single space may hold.
pub const SPACE_SESSION_SLOTS: usize = 3;
/// Largest single saved object context.
pub const MAX_CONTEXT_SIZE: usize = 4096;
/// Name of an object: hash algorithm identifier plus its digest.
pub const NAME_SIZE: usize = 34;
/// Retries a transport performs on a recoverable transfer error.
pub const TPM_RETRY: u32 = 50;

/// Interface timeout classes, milliseconds.
pub const TIMEOUT_A_MS: u32 = 750;
pub const TIMEOUT_B_MS: u32 = 4000;
pub const TIMEOUT_C_MS: u32 = 200;
pub const TIMEOUT_D_MS: u32 = 30;

/// Command duration classes, milliseconds.
pub const DURATION_SHORT_MS: u32 = 20;
pub const DURATION_LONG_MS: u32 = 2000;
pub const DURATION_DEFAULT_MS: u32 = 120000;

/// Longest a userspace reader may leave an unconsumed response parked,
/// in seconds, before the device drops it.
pub const USER_READ_TIMEOUT_SECS: u32 = 120;
