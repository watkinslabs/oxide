// Errors raised while reading or consulting a policy.
//
// A policy image arrives from userspace and is entirely untrusted: every
// failure here must be a refusal, never a panic and never a partial load that
// leaves a half-built policy consultable.

/// Why a policy image was refused, or a policy query could not be answered.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Leading magic word is not a policy image.
    BadMagic,
    /// Signature string is absent or does not match.
    BadSignature,
    /// Policy version is outside the range this engine reads.
    UnsupportedVersion(u32),
    /// Image ended before a field it declared.
    Truncated,
    /// A field held a value the format does not permit.
    Malformed,
    /// A declared count or length exceeds what the format permits.
    TooLarge,
    /// A symbol value referenced a table entry that does not exist.
    UnknownSymbol,
    /// Two records claimed the same key.
    Duplicate,
    /// A context does not satisfy the loaded policy.
    InvalidContext,
    /// A SID has no entry in the SID table.
    UnknownSid,
    /// The policy declares MLS but the version predates it.
    MlsMismatch,
    /// Allocation failed while building the policy.
    NoMemory,
    /// The policy changed under a lock-free reader; the caller must retry.
    Stale,
}

/// Result of a policy read or query.
pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    /// Stable short name for logging and test assertions. # C: O(1)
    pub const fn name(self) -> &'static str {
        match self {
            Self::BadMagic => "bad-magic",
            Self::BadSignature => "bad-signature",
            Self::UnsupportedVersion(_) => "unsupported-version",
            Self::Truncated => "truncated",
            Self::Malformed => "malformed",
            Self::TooLarge => "too-large",
            Self::UnknownSymbol => "unknown-symbol",
            Self::Duplicate => "duplicate",
            Self::InvalidContext => "invalid-context",
            Self::UnknownSid => "unknown-sid",
            Self::MlsMismatch => "mls-mismatch",
            Self::NoMemory => "no-memory",
            Self::Stale => "stale",
        }
    }
}
