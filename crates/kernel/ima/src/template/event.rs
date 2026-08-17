// What a template's fields are serialised from: the collected file digest, the
// event name, the integrity xattrs, an appended module signature, a measured
// buffer, and the inode metadata the EVM-oriented templates carry.

use crate::hash::HashAlgo;
use crate::uapi::XattrType;

/// Inode metadata the `iuid`/`igid`/`imode` fields report.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct InodeMeta {
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
}

/// The data a measurement event draws on.
#[derive(Copy, Clone, Debug)]
pub struct Event<'a> {
    /// Collected file (or buffer) digest. Absent for a violation record.
    pub digest: Option<&'a [u8]>,
    /// Algorithm of `digest`.
    pub algo: HashAlgo,
    /// SHA-1 digest for the original template, needed when `algo` is one the
    /// original template's fixed-size digest field cannot carry.
    pub legacy_sha1: Option<&'a [u8]>,
    /// Event name — the path, or the synthetic name of a buffer event.
    pub filename: &'a str,
    /// `security.ima` value.
    pub xattr: Option<&'a [u8]>,
    /// `security.evm` value.
    pub evm_xattr: Option<&'a [u8]>,
    /// Raw appended module signature.
    pub modsig: Option<&'a [u8]>,
    /// Digest the appended module signature covers.
    pub modsig_digest: Option<(HashAlgo, &'a [u8])>,
    /// Measured buffer contents.
    pub buf: Option<&'a [u8]>,
    /// This record reports an integrity violation: no digest, and the PCR is
    /// invalidated rather than extended with the record.
    pub violation: bool,
    /// The digest is an fs-verity digest, which the version-2 digest field
    /// names in its type prefix.
    pub verity: bool,
    /// Inode metadata, when the event has an inode.
    pub inode: Option<InodeMeta>,
    /// Serialised names of the EVM-protected xattrs present on the inode.
    pub xattr_names: Option<&'a [u8]>,
    /// Serialised lengths of those xattr values.
    pub xattr_lengths: Option<&'a [u8]>,
    /// Serialised values of those xattrs.
    pub xattr_values: Option<&'a [u8]>,
}

impl<'a> Event<'a> {
    /// An event with only a name and digest set. # C: O(1)
    pub fn new(filename: &'a str, algo: HashAlgo, digest: Option<&'a [u8]>) -> Self {
        Self {
            digest, algo, legacy_sha1: None, filename,
            xattr: None, evm_xattr: None, modsig: None, modsig_digest: None, buf: None,
            violation: false, verity: false, inode: None,
            xattr_names: None, xattr_lengths: None, xattr_values: None,
        }
    }

    /// Digest the original template's fixed-size field reports: the collected
    /// digest when its algorithm fits that field, otherwise the separately
    /// collected SHA-1. # C: O(1)
    pub fn original_template_digest(&self) -> Option<&'a [u8]> {
        match self.algo {
            HashAlgo::Sha1 | HashAlgo::Md5 => self.digest,
            _ => self.legacy_sha1,
        }
    }

    /// Type tag of the `security.ima` value. # C: O(1)
    pub fn ima_xattr_type(&self) -> Option<XattrType> {
        self.xattr.and_then(|v| v.first().copied()).and_then(XattrType::from_tag)
    }

    /// Type tag of the `security.evm` value. # C: O(1)
    pub fn evm_xattr_type(&self) -> Option<XattrType> {
        self.evm_xattr.and_then(|v| v.first().copied()).and_then(XattrType::from_tag)
    }
}
