// Integrity ABI numbers and wire structures: the `security.ima` /
// `security.evm` xattr type tags, the version-2 signature header layout, the
// appraisal status ladder, and the hook identities the policy language names.
// Values here are consumed by userspace tooling and by stored xattrs; they are
// not ours to renumber.

use crate::hash::HashAlgo;

/// `security.ima` / `security.evm` value type tag (leading byte).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum XattrType {
    /// Bare digest, no algorithm byte (legacy sha1/md5 form).
    ImaDigest = 0x01,
    /// EVM HMAC over the protected xattr set.
    EvmHmac = 0x02,
    /// Version-2+ file signature in `security.ima`.
    EvmImaDigsig = 0x03,
    /// Digest preceded by an algorithm id byte.
    ImaDigestNg = 0x04,
    /// Portable, immutable EVM signature.
    EvmPortableDigsig = 0x05,
    /// fs-verity digest signature (signature version 3 only).
    ImaVerityDigsig = 0x06,
}

/// First unassigned xattr type tag. # C: O(1)
pub const XATTR_TYPE_LAST: u8 = 0x07;

impl XattrType {
    /// Type for a leading tag byte, `None` when unassigned. # C: O(1)
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x01 => Some(Self::ImaDigest),
            0x02 => Some(Self::EvmHmac),
            0x03 => Some(Self::EvmImaDigsig),
            0x04 => Some(Self::ImaDigestNg),
            0x05 => Some(Self::EvmPortableDigsig),
            0x06 => Some(Self::ImaVerityDigsig),
            _ => None,
        }
    }
    /// Tag byte. # C: O(1)
    pub fn tag(self) -> u8 { self as u8 }
}

/// Appraisal / metadata verification outcome. Ordering is the ABI's.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Status {
    Pass = 0,
    PassImmutable,
    Fail,
    FailImmutable,
    NoLabel,
    NoXattrs,
    Unknown,
}

impl Status {
    /// Audit spelling of the status. # C: O(1)
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass", Self::PassImmutable => "pass_immutable",
            Self::Fail => "fail", Self::FailImmutable => "fail_immutable",
            Self::NoLabel => "no_label", Self::NoXattrs => "no_xattrs",
            Self::Unknown => "unknown",
        }
    }
}

/// Fixed size of the version-2 signature header preceding the signature bytes:
/// type, version, hash algorithm, big-endian key id, big-endian signature size.
pub const SIG_V2_HDR_LEN: usize = 9;

/// Parsed version-2/3 signature header.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SigV2Hdr {
    pub xattr_type: XattrType,
    pub version: u8,
    pub hash_algo: u8,
    pub keyid: u32,
    pub sig_size: u16,
}

impl SigV2Hdr {
    /// Decode a header from the front of an xattr value. `None` when the value
    /// is shorter than the header or carries an unassigned type tag. # C: O(1)
    pub fn parse(v: &[u8]) -> Option<Self> {
        if v.len() < SIG_V2_HDR_LEN { return None; }
        Some(Self {
            xattr_type: XattrType::from_tag(v[0])?,
            version: v[1],
            hash_algo: v[2],
            keyid: u32::from_be_bytes([v[3], v[4], v[5], v[6]]),
            sig_size: u16::from_be_bytes([v[7], v[8]]),
        })
    }

    /// Serialise the header. # C: O(1)
    pub fn encode(&self) -> [u8; SIG_V2_HDR_LEN] {
        let k = self.keyid.to_be_bytes();
        let s = self.sig_size.to_be_bytes();
        [self.xattr_type.tag(), self.version, self.hash_algo, k[0], k[1], k[2], k[3], s[0], s[1]]
    }

    /// Digest algorithm named by the header, `None` when out of range. # C: O(1)
    pub fn algo(&self) -> Option<HashAlgo> { HashAlgo::from_id(self.hash_algo) }
}

/// Policy hook identity. Discriminant order is the ABI enumeration's.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Hook {
    None = 0,
    FileCheck,
    MmapCheck,
    MmapCheckReqprot,
    BprmCheck,
    CredsCheck,
    PostSetattr,
    ModuleCheck,
    FirmwareCheck,
    KexecKernelCheck,
    KexecInitramfsCheck,
    PolicyCheck,
    KexecCmdline,
    KeyCheck,
    CriticalData,
    SetxattrCheck,
    MaxCheck,
}

impl Hook {
    /// Hook named by a `func=` argument, `None` when unknown. Both historical
    /// spellings (`PATH_CHECK`, `FILE_MMAP`) resolve to their modern hook.
    /// # C: O(1)
    pub fn by_token(tok: &str) -> Option<Self> {
        match tok {
            "FILE_CHECK" | "PATH_CHECK" => Some(Self::FileCheck),
            "MODULE_CHECK" => Some(Self::ModuleCheck),
            "FIRMWARE_CHECK" => Some(Self::FirmwareCheck),
            "MMAP_CHECK" | "FILE_MMAP" => Some(Self::MmapCheck),
            "MMAP_CHECK_REQPROT" => Some(Self::MmapCheckReqprot),
            "BPRM_CHECK" => Some(Self::BprmCheck),
            "CREDS_CHECK" => Some(Self::CredsCheck),
            "KEXEC_KERNEL_CHECK" => Some(Self::KexecKernelCheck),
            "KEXEC_INITRAMFS_CHECK" => Some(Self::KexecInitramfsCheck),
            "POLICY_CHECK" => Some(Self::PolicyCheck),
            "KEXEC_CMDLINE" => Some(Self::KexecCmdline),
            "KEY_CHECK" => Some(Self::KeyCheck),
            "CRITICAL_DATA" => Some(Self::CriticalData),
            "SETXATTR_CHECK" => Some(Self::SetxattrCheck),
            _ => None,
        }
    }

    /// Token the policy file renders for this hook. # C: O(1)
    pub fn token(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::FileCheck => "FILE_CHECK",
            Self::MmapCheck => "MMAP_CHECK",
            Self::MmapCheckReqprot => "MMAP_CHECK_REQPROT",
            Self::BprmCheck => "BPRM_CHECK",
            Self::CredsCheck => "CREDS_CHECK",
            Self::PostSetattr => "POST_SETATTR",
            Self::ModuleCheck => "MODULE_CHECK",
            Self::FirmwareCheck => "FIRMWARE_CHECK",
            Self::KexecKernelCheck => "KEXEC_KERNEL_CHECK",
            Self::KexecInitramfsCheck => "KEXEC_INITRAMFS_CHECK",
            Self::PolicyCheck => "POLICY_CHECK",
            Self::KexecCmdline => "KEXEC_CMDLINE",
            Self::KeyCheck => "KEY_CHECK",
            Self::CriticalData => "CRITICAL_DATA",
            Self::SetxattrCheck => "SETXATTR_CHECK",
            Self::MaxCheck => "MAX_CHECK",
        }
    }
}

/// Extended attribute names the integrity subsystem reads and writes.
pub const XATTR_NAME_IMA: &str = "security.ima";
pub const XATTR_NAME_EVM: &str = "security.evm";
pub const XATTR_NAME_SELINUX: &str = "security.selinux";
pub const XATTR_NAME_SMACK: &str = "security.SMACK64";
pub const XATTR_NAME_SMACK_EXEC: &str = "security.SMACK64EXEC";
pub const XATTR_NAME_SMACK_TRANSMUTE: &str = "security.SMACK64TRANSMUTE";
pub const XATTR_NAME_SMACK_MMAP: &str = "security.SMACK64MMAP";
pub const XATTR_NAME_APPARMOR: &str = "security.apparmor";
pub const XATTR_NAME_CAPS: &str = "security.capability";

#[cfg(test)]
mod tests;
