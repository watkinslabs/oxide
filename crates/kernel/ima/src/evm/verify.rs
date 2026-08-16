// Verifying the EVM label, and deciding which attribute writes EVM mediates.
//
// The label binds an inode's security attributes to its metadata. If it does
// not verify, the attributes cannot be trusted — which is why appraisal
// consults this before believing a `security.ima` value at all.

use alloc::vec::Vec;

use crate::appraise::VerifyResult;
use crate::hash::HashAlgo;
use crate::uapi::{SigV2Hdr, Status, XattrType, SIG_V2_HDR_LEN, XATTR_NAME_EVM};

use super::xattrs::{posix_acl_xattr, protected_xattr};

/// Length of an HMAC label: the type tag plus a SHA-1 digest.
pub const EVM_HMAC_XATTR_LEN: usize = 1 + 20;

/// What the caller must be able to do for the label check.
pub trait LabelOps {
    /// Hash or keyed-hash the label input for a label of this type under this
    /// algorithm. `None` when the inode carries nothing to cover, or the key or
    /// algorithm is unavailable. # C: O(total)
    fn compute(&mut self, ty: XattrType, algo: HashAlgo) -> Option<Vec<u8>>;
    /// Verify a label signature against the computed digest. # C: O(sig)
    fn verify_sig(&mut self, sig: &[u8], digest: &[u8], algo: HashAlgo) -> VerifyResult;
}

/// Verify an inode's EVM label. `protected_count` is how many protected
/// attributes the inode carries, which distinguishes a file that lost its label
/// from one that never needed one. # C: O(total)
pub fn verify_label(
    evm_xattr: Option<&[u8]>,
    read_unsupported: bool,
    protected_count: usize,
    sigv3_required: bool,
    ops: &mut impl LabelOps,
) -> Status {
    let v = match evm_xattr {
        None => {
            if read_unsupported { return Status::Unknown; }
            // Attributes present but no label: the label was removed.
            return if protected_count > 0 { Status::NoLabel } else { Status::NoXattrs };
        }
        Some(v) if v.is_empty() => return Status::Fail,
        Some(v) => v,
    };
    let ty = match XattrType::from_tag(v[0]) { Some(t) => t, None => return Status::Fail };
    match ty {
        XattrType::EvmHmac => {
            if v.len() != EVM_HMAC_XATTR_LEN { return Status::Fail; }
            match ops.compute(ty, HashAlgo::Sha1) {
                None => Status::Fail,
                Some(d) => if d.len() >= 20 && d[..20] == v[1..] { Status::Pass } else { Status::Fail },
            }
        }
        XattrType::EvmImaDigsig | XattrType::EvmPortableDigsig => {
            let immutable = ty == XattrType::EvmPortableDigsig;
            // A header with no signature after it is not a signature.
            if v.len() <= SIG_V2_HDR_LEN { return Status::Fail; }
            let hdr = match SigV2Hdr::parse(v) { Some(h) => h, None => return Status::Fail };
            if sigv3_required && hdr.version != 3 { return Status::Fail; }
            let algo = match hdr.algo() { Some(a) => a, None => return fail(immutable) };
            let digest = match ops.compute(ty, algo) { Some(d) => d, None => return fail(immutable) };
            match ops.verify_sig(v, &digest, algo) {
                VerifyResult::Ok =>
                    if immutable { Status::PassImmutable } else { Status::Pass },
                _ => fail(immutable),
            }
        }
        _ => Status::Fail,
    }
}

fn fail(immutable: bool) -> Status {
    if immutable { Status::FailImmutable } else { Status::Fail }
}

/// Why an attribute write was refused, or that it is allowed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum XattrDecision {
    /// The write proceeds.
    Allow,
    /// The write is refused because the caller lacks the administrative
    /// capability the label demands.
    DenyNotPrivileged,
    /// The write is refused because the inode's current label does not verify;
    /// allowing it would let an attacker settle metadata under a broken label.
    DenyBadLabel,
}

/// The state `protect_xattr` decides against.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ProtectCtx {
    /// Caller holds the administrative capability.
    pub privileged: bool,
    /// The filesystem cannot carry an EVM label at all.
    pub unsupported_fs: bool,
    /// No key is loaded, so no label will be computed.
    pub hmac_disabled: bool,
    /// The inode was created by this open and has no label yet.
    pub new_file: bool,
    /// The inode lives on a filesystem whose contents do not persist, where a
    /// missing label is expected.
    pub pseudo_fs: bool,
    /// Verified status of the inode's current label.
    pub status: Status,
    /// The write changes the attribute's value rather than rewriting the same
    /// bytes; an immutable label tolerates only the latter.
    pub value_changes: bool,
}

/// Decide whether a write to `name` may proceed. # C: O(n)
pub fn protect_xattr(name: &str, c: &ProtectCtx) -> XattrDecision {
    if name == XATTR_NAME_EVM {
        // Only an administrator may set the label itself, and never on a
        // filesystem that cannot carry one.
        if !c.privileged { return XattrDecision::DenyNotPrivileged; }
        if c.unsupported_fs { return XattrDecision::DenyNotPrivileged; }
    } else if !protected_xattr(name) {
        // An unprotected attribute is unmediated, except that writing an
        // access-control list changes the mode, which the label covers.
        if !posix_acl_xattr(name) { return XattrDecision::Allow; }
        if c.unsupported_fs { return XattrDecision::Allow; }
        if matches!(c.status, Status::Pass | Status::NoXattrs) { return XattrDecision::Allow; }
        return out(c);
    } else if c.unsupported_fs {
        return XattrDecision::Allow;
    }

    if c.status == Status::NoXattrs {
        if c.hmac_disabled { return XattrDecision::Allow; }
        if c.new_file { return XattrDecision::Allow; }
        if c.pseudo_fs { return XattrDecision::Allow; }
    }
    out(c)
}

fn out(c: &ProtectCtx) -> XattrDecision {
    if c.hmac_disabled && matches!(c.status, Status::NoLabel | Status::Unknown) {
        return XattrDecision::Allow;
    }
    // A portable label can never be updated, so other attributes moving under
    // it cannot make it any less valid than it already is.
    if c.status == Status::FailImmutable { return XattrDecision::Allow; }
    if c.status == Status::PassImmutable && !c.value_changes { return XattrDecision::Allow; }
    if c.status == Status::Pass { XattrDecision::Allow } else { XattrDecision::DenyBadLabel }
}
