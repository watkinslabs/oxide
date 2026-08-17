//! What `test_dummy_encryption=` and `inlinecrypt` ask for.
//!
//! The dummy policy exists so a test can mount a volume in which EVERY file is
//! encrypted, without a key ever being added by hand. It is a real policy with
//! a well-known key, not a bypass: a volume mounted under it stores ciphertext
//! and encrypted names, and a mount of the same volume without it sees exactly
//! what an unkeyed reader sees.
//!
//! Two things about the policy cannot be decided here, and are deliberately
//! left to the module that owns keys:
//!
//! - **The v1 key DESCRIPTOR is a fixed eight-byte constant**, so it is stated
//!   here; nothing has to be derived to know it.
//! - **The v2 key IDENTIFIER is derived from the well-known test key**, which
//!   takes the key-derivation the crypto module owns. Fabricating bytes for it
//!   here would produce a policy that names a key nothing can find, and every
//!   file created under it would be unreadable by a correct implementation.

use syscall::errno::Errno;

/// Whether this build can encrypt contents and names.
///
/// A mount that asks for a dummy policy on a build that cannot encrypt is
/// REFUSED, not accepted-and-dropped: the whole point of the option is that
/// the files it creates are ciphertext, so a mount that silently gave
/// plaintext would hand a test a false pass.
pub const ENCRYPTION: bool = false;

/// Whether the path to the device can encrypt in place of the filesystem.
///
/// Unlike the dummy policy this changes only WHERE the same encryption
/// happens, so a build without it honours the mount and encrypts in the
/// filesystem instead — which is why asking for it is not an error.
pub const INLINE_CRYPT: bool = false;

/// Which generation of policy a file carries.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PolicyVersion {
    /// Keys named by a caller-chosen descriptor, with no proof the key is the
    /// one the policy meant.
    V1,
    /// Keys named by an identifier derived from the key itself.
    V2,
}

/// The eight bytes a v1 dummy policy names its key by.
pub const DUMMY_V1_DESCRIPTOR: [u8; 8] = [0x42; 8];

/// Contents are encrypted with AES-256 in XTS.
pub const MODE_AES_256_XTS: u8 = 1;
/// Names are encrypted with AES-256 in CBC-CTS.
pub const MODE_AES_256_CTS: u8 = 4;

/// The policy `test_dummy_encryption` asks every new file to be created under.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct DummyPolicy {
    pub version: PolicyVersion,
    pub contents_mode: u8,
    pub filenames_mode: u8,
}

impl DummyPolicy {
    /// # C: O(1)
    fn of(version: PolicyVersion) -> Self {
        Self { version, contents_mode: MODE_AES_256_XTS, filenames_mode: MODE_AES_256_CTS }
    }
}

/// Parse `test_dummy_encryption[=v1|=v2]` on top of whatever a previous
/// occurrence in the same option string already set.
///
/// A bare occurrence means the current generation. A second occurrence naming
/// the SAME policy is accepted — an option string assembled from two places
/// that agree is not a conflict — and one naming a different policy is
/// refused, because only one of the two can be what the files get.
/// # C: O(len)
pub fn parse_dummy(existing: Option<DummyPolicy>, arg: Option<&str>)
    -> Result<DummyPolicy, Errno>
{
    if !ENCRYPTION { return Err(Errno::Einval); }
    parse_dummy_ungated(existing, arg)
}

/// Parse the same option WITHOUT consulting whether this build can encrypt.
///
/// Split out so the spelling rules — which arguments name a policy, which
/// second occurrence conflicts — are checkable on a build that has no crypto
/// at all. The gate belongs at the mount, not in the grammar.
/// # C: O(len)
pub fn parse_dummy_ungated(existing: Option<DummyPolicy>, arg: Option<&str>)
    -> Result<DummyPolicy, Errno>
{
    let want = match arg.unwrap_or("v2") {
        "v1" => DummyPolicy::of(PolicyVersion::V1),
        "v2" => DummyPolicy::of(PolicyVersion::V2),
        _ => return Err(Errno::Einval),
    };
    match existing {
        Some(had) if had != want => Err(Errno::Einval),
        _ => Ok(want),
    }
}

/// How the option is rendered back into a mount line. # C: O(1)
pub fn show_dummy(p: &DummyPolicy) -> &'static str {
    match p.version {
        PolicyVersion::V1 => ",test_dummy_encryption=v1",
        PolicyVersion::V2 => ",test_dummy_encryption=v2",
    }
}
