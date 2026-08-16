//! Bounds the mount and the on-disk records are held to.

/// Most layers one mount may stack, counting data-only layers.
pub const MAX_STACK: usize = 500;

/// Longest absolute redirect value written. A rename that would need a longer
/// one is refused with `EXDEV` so the caller falls back to copying by hand.
pub const REDIRECT_MAX: usize = 256;

/// Bytes a temporary name in the work directory occupies, including the
/// terminating position.
pub const TEMPNAME_SIZE: usize = 20;

/// Bytes moved per pass when copying a file's data up.
pub const COPY_UP_CHUNK_SIZE: u64 = 1 << 20;

/// Widest digest a metacopy record can carry.
pub const MAX_DIGEST_SIZE: usize = 64;

/// Metacopy record with no digest: version, length, flags, algorithm.
pub const METACOPY_MIN_SIZE: usize = 4;
/// Metacopy record carrying the widest digest.
pub const METACOPY_MAX_SIZE: usize = METACOPY_MIN_SIZE + MAX_DIGEST_SIZE;

/// Bytes a protattr value may occupy.
pub const PROTATTR_MAX: usize = 32;

/// Longest name any layer accepts, until the layers report otherwise.
pub const NAME_MAX: u32 = 255;
