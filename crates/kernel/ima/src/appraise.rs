// Appraisal: deciding whether a file's stored integrity label matches the file.
//
// The rule that matters most: a file with no `security.ima` label, or with a
// label that does not match its contents, does NOT appraise as a pass. Enforce
// mode then denies the access. Only the explicitly selected fix mode rewrites a
// label, and it never rewrites a signature.

use crate::flags::*;
use crate::hash::HashAlgo;
use crate::uapi::{Hook, SigV2Hdr, Status, XattrType, SIG_V2_HDR_LEN};

/// Outcome of verifying a signature against a digest.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum VerifyResult {
    /// Signature is by a trusted key and covers this digest.
    Ok,
    /// Signature does not verify.
    Invalid,
    /// No trusted key can verify this signature.
    NoKey,
    /// Signature verification is not available in this configuration.
    Unsupported,
}

/// Keyring a signature is checked against.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Keyring { Ima, Platform, Evm }

/// Signature verification, owned by the keyring subsystem. Appraisal decides
/// what must be verified and how to read the answer; it does not implement the
/// cryptography.
pub trait Verifier {
    /// Verify `sig` (a complete xattr value, header included) as covering
    /// `digest` under `algo`. # C: O(sig)
    fn verify(&self, ring: Keyring, sig: &[u8], digest: &[u8], algo: HashAlgo) -> VerifyResult;
    /// Verify an appended module signature over the file. # C: O(sig)
    fn verify_modsig(&self, ring: Keyring, modsig: &[u8]) -> VerifyResult { let _ = (ring, modsig); VerifyResult::Unsupported }
}

/// What appraisal was given to work with.
#[derive(Copy, Clone, Debug)]
pub struct Appraisal<'a> {
    pub func: Hook,
    /// Per-inode requirement bits taken from the matching policy rule.
    pub flags: u32,
    /// Digest collected from the file's contents.
    pub file_digest: &'a [u8],
    /// Algorithm of `file_digest`.
    pub algo: HashAlgo,
    /// `security.ima` value, absent when the file carries no label.
    pub xattr: Option<&'a [u8]>,
    /// Reading the label failed for a reason other than its absence.
    pub xattr_read_error: bool,
    /// The inode's filesystem cannot store extended attributes.
    pub no_xattr_support: bool,
    /// Appended module signature, when the file carries one.
    pub modsig: Option<&'a [u8]>,
    /// Result of verifying the inode's EVM metadata label.
    pub evm_status: Status,
    /// This open created the file.
    pub created: bool,
    /// File length in bytes.
    pub size: u64,
    /// Appraisal mode bits.
    pub mode: u32,
    /// Signatures on this filesystem cannot be properly verified.
    pub unverifiable_sigs_fs: bool,
    /// The filesystem was mounted by an untrusted mounter.
    pub untrusted_mounter: bool,
}

impl<'a> Appraisal<'a> {
    /// An appraisal of a labelled file with nothing else set. # C: O(1)
    pub fn new(func: Hook, algo: HashAlgo, file_digest: &'a [u8]) -> Self {
        Self {
            func, flags: 0, file_digest, algo, xattr: None, xattr_read_error: false,
            no_xattr_support: false, modsig: None, evm_status: Status::Pass,
            created: false, size: 1, mode: IMA_APPRAISE_ENFORCE,
            unverifiable_sigs_fs: false, untrusted_mounter: false,
        }
    }
    fn requires_digsig(&self) -> bool { self.flags & IMA_DIGSIG_REQUIRED != 0 }
    fn requires_verity(&self) -> bool { self.flags & IMA_VERITY_REQUIRED != 0 }
    fn requires_sigv3(&self) -> bool { self.flags & IMA_SIGV3_REQUIRED != 0 }
    fn modsig_allowed(&self) -> bool { self.flags & IMA_MODSIG_ALLOWED != 0 }
    fn is_new_file(&self) -> bool { self.flags & IMA_NEW_FILE != 0 || self.created }
}

/// Appraisal outcome: the status, the audit cause, and whether the label
/// carried a signature.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Outcome {
    pub status: Status,
    pub cause: &'static str,
    /// The label is a signature, so it is not to be rewritten on close.
    pub digsig: bool,
    /// Fix mode would rewrite the label with the file's own digest.
    pub would_fix: bool,
}

/// Algorithm a label says its digest is in. An unreadable or unlabelled file
/// falls back to the measurement algorithm rather than to no algorithm.
/// # C: O(1)
pub fn xattr_hash_algo(xattr: Option<&[u8]>, default: HashAlgo) -> HashAlgo {
    let v = match xattr { Some(v) if v.len() >= 2 => v, _ => return default };
    match XattrType::from_tag(v[0]) {
        Some(XattrType::ImaVerityDigsig) => match SigV2Hdr::parse(v) {
            Some(h) if h.version == 3 && v.len() > SIG_V2_HDR_LEN =>
                h.algo().unwrap_or(default),
            _ => default,
        },
        Some(XattrType::EvmImaDigsig) => match SigV2Hdr::parse(v) {
            Some(h) if (h.version == 2 || h.version == 3) && v.len() > SIG_V2_HDR_LEN =>
                h.algo().unwrap_or(default),
            _ => default,
        },
        // The digest is preceded by its algorithm id.
        Some(XattrType::ImaDigestNg) => HashAlgo::from_id(v[1]).unwrap_or(default),
        // The legacy digest form is identified by its total length.
        Some(XattrType::ImaDigest) => match v.len() {
            21 => if v[17..21] == [0, 0, 0, 0] { HashAlgo::Md5 } else { HashAlgo::Sha1 },
            17 => HashAlgo::Md5,
            _ => default,
        },
        _ => default,
    }
}

/// Result of checking a label: status, audit cause, whether the label was a
/// signature, and — when one was checked — how the signature verified.
type XattrVerdict = (Status, &'static str, bool, Option<VerifyResult>);

/// Verify the label against the collected digest. # C: O(n)
fn xattr_verify(a: &Appraisal<'_>, v: &[u8], verifier: &dyn Verifier) -> XattrVerdict {
    let ty = match XattrType::from_tag(v[0]) {
        Some(t) => t,
        None => return (Status::Unknown, "unknown-ima-data", false, None),
    };
    match ty {
        XattrType::ImaDigest | XattrType::ImaDigestNg => {
            // A bare digest is not a signature: a rule that demands a
            // signature must not be satisfied by one.
            if a.requires_digsig() {
                let cause = if a.requires_verity() { "verity-signature-required" }
                            else { "IMA-signature-required" };
                return (Status::Fail, cause, false, None);
            }
            let start = 1 + if ty == XattrType::ImaDigestNg { 1 } else { 0 };
            let want = a.file_digest;
            if v.len() < start + want.len() { return (Status::Fail, "invalid-hash", false, None); }
            if &v[start..start + want.len()] != want {
                return (Status::Fail, "invalid-hash", false, None);
            }
            (Status::Pass, "", false, None)
        }
        XattrType::EvmImaDigsig => {
            if a.requires_digsig() && a.requires_verity() {
                return (Status::Fail, "verity-signature-required", true, None);
            }
            let hdr = match SigV2Hdr::parse(v) {
                Some(h) => h,
                None => return (Status::Fail, "invalid-signature-version", true, None),
            };
            if hdr.version > 3 { return (Status::Fail, "invalid-signature-version", true, None); }
            if a.requires_sigv3() && hdr.version != 3 {
                return (Status::Fail, "IMA-sigv3-required", true, None);
            }
            check_sig(a, v, verifier, "invalid-signature")
        }
        XattrType::ImaVerityDigsig => {
            if a.requires_digsig() && !a.requires_verity() {
                return (Status::Fail, "IMA-signature-required", true, None);
            }
            match SigV2Hdr::parse(v) {
                Some(h) if h.version == 3 => {}
                _ => return (Status::Fail, "invalid-signature-version", true, None),
            }
            check_sig(a, v, verifier, "invalid-verity-signature")
        }
        _ => (Status::Unknown, "unknown-ima-data", false, None),
    }
}

fn check_sig(a: &Appraisal<'_>, v: &[u8], verifier: &dyn Verifier, fail_cause: &'static str)
    -> XattrVerdict
{
    let mut r = verifier.verify(Keyring::Ima, v, a.file_digest, a.algo);
    if r != VerifyResult::Ok && a.func == Hook::KexecKernelCheck {
        r = verifier.verify(Keyring::Platform, v, a.file_digest, a.algo);
    }
    match r {
        VerifyResult::Ok => (Status::Pass, "", true, Some(r)),
        VerifyResult::Unsupported => (Status::Unknown, "", true, Some(r)),
        _ => (Status::Fail, fail_cause, true, Some(r)),
    }
}

/// Appraise a file. # C: O(n)
pub fn appraise(a: &Appraisal<'_>, verifier: &dyn Verifier) -> Outcome {
    let try_modsig = a.modsig_allowed() && a.modsig.is_some();

    // Without extended attributes and without an appended signature there is
    // nothing to appraise against.
    if a.no_xattr_support && !try_modsig {
        return Outcome { status: Status::Unknown, cause: "unknown", digsig: false, would_fix: false };
    }

    let mut digsig = false;
    let mut status;
    let mut cause: &'static str = "unknown";

    if a.xattr.is_none() && !try_modsig {
        if a.xattr_read_error {
            return finish(a, Status::Unknown, "unknown", false, try_modsig);
        }
        cause = if a.requires_digsig() {
            if a.requires_verity() { "verity-signature-required" } else { "IMA-signature-required" }
        } else {
            "missing-hash"
        };
        // An unlabelled file is NOT a pass. The single exception is a file this
        // open just created that has no contents yet, or has no signature
        // requirement to satisfy.
        status = Status::NoLabel;
        if a.is_new_file() && (!a.requires_digsig() || a.size == 0) { status = Status::Pass; }
        return finish(a, status, cause, false, try_modsig);
    }

    // The label is only trustworthy if the inode's EVM metadata is.
    match a.evm_status {
        Status::Pass | Status::PassImmutable | Status::Unknown => {}
        Status::NoXattrs if try_modsig => {}
        Status::NoXattrs | Status::NoLabel =>
            return finish(a, a.evm_status, "missing-HMAC", false, try_modsig),
        Status::FailImmutable =>
            return finish(a, a.evm_status, "invalid-fail-immutable", true, try_modsig),
        Status::Fail => return finish(a, a.evm_status, "invalid-HMAC", false, try_modsig),
    }

    status = Status::Unknown;
    let mut no_key = false;
    if let Some(v) = a.xattr {
        if v.is_empty() {
            status = Status::Unknown;
            cause = "unknown-ima-data";
        } else {
            let (s, c, d, vr) = xattr_verify(a, v, verifier);
            status = s;
            digsig = d;
            if !c.is_empty() { cause = c; }
            no_key = vr == Some(VerifyResult::NoKey);
        }
    }

    // An appended signature is tried when there is no label, when the label is
    // a bare digest, or when no key could verify the label's signature.
    let plain_digest = a.xattr.and_then(|v| v.first().copied())
        == Some(XattrType::ImaDigestNg.tag());
    if try_modsig && (a.xattr.is_none() || plain_digest || no_key) {
        let r = verifier.verify_modsig(Keyring::Ima, a.modsig.unwrap_or(&[]));
        let r = if r != VerifyResult::Ok && a.func == Hook::KexecKernelCheck {
            verifier.verify_modsig(Keyring::Platform, a.modsig.unwrap_or(&[]))
        } else { r };
        if r == VerifyResult::Ok { status = Status::Pass; cause = ""; }
        else { status = Status::Fail; cause = "invalid-signature"; }
    }

    finish(a, status, cause, digsig, try_modsig)
}

fn finish(a: &Appraisal<'_>, status: Status, cause: &'static str, digsig: bool, try_modsig: bool)
    -> Outcome
{
    // A signature that cannot be verified on this filesystem fails outright
    // when the mount is untrusted or the policy asked to fail securely.
    if a.unverifiable_sigs_fs
        && (a.untrusted_mounter || a.flags & IMA_FAIL_UNVERIFIABLE_SIGS != 0)
    {
        return Outcome { status: Status::Fail, cause: "unverifiable-signature", digsig, would_fix: false };
    }
    if status == Status::Pass {
        return Outcome { status, cause: "", digsig, would_fix: false };
    }

    let label_is_signature = a.xattr.and_then(|v| v.first().copied())
        == Some(XattrType::EvmImaDigsig.tag());
    let mut status = status;
    let mut would_fix = false;
    if a.mode & IMA_APPRAISE_FIX != 0 && !try_modsig && !label_is_signature {
        // Fix mode writes the file's own digest into the label and accepts it.
        would_fix = true;
        status = Status::Pass;
    }
    // An empty file created by this open, already carrying a signature, is
    // permitted so the signature can be written before any contents are.
    if a.size == 0 && a.is_new_file() && digsig { status = Status::Pass; }
    Outcome { status, cause, digsig, would_fix }
}

/// Does this outcome permit the access? Only a pass does. In modes other than
/// enforce the access proceeds regardless, and the outcome is only logged.
/// # C: O(1)
pub fn permits_access(mode: u32, o: &Outcome) -> bool {
    if mode & IMA_APPRAISE_ENFORCE == 0 { return true; }
    o.status == Status::Pass
}

/// A write to a file whose label is a signature is refused: the signature
/// could not survive the write, and silently invalidating it would turn a
/// signed file into an unsigned one. A file this open created is exempt.
/// # C: O(1)
pub fn permits_write(mask: u32, label_is_signature: bool, new_file: bool) -> bool {
    !(mask & MAY_WRITE != 0 && label_is_signature && !new_file)
}

/// Was the digest taken with an algorithm the rule's allowlist permits? An
/// empty allowlist means the rule named none, and any algorithm is allowed.
/// # C: O(1)
pub fn algo_allowed(allowed: Option<u32>, algo: HashAlgo) -> bool {
    match allowed {
        None | Some(0) => true,
        Some(bits) => bits & (1u32 << algo.id()) != 0,
    }
}

/// The label a fix-mode write stores: the type tag, the algorithm id for the
/// modern form, and the digest. The legacy form, used only for the algorithms
/// that predate the algorithm byte, carries the digest alone. # C: O(n)
pub fn build_xattr(algo: HashAlgo, digest: &[u8]) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::with_capacity(digest.len() + 2);
    if algo.id() <= HashAlgo::Sha1.id() {
        v.push(XattrType::ImaDigest.tag());
    } else {
        v.push(XattrType::ImaDigestNg.tag());
        v.push(algo.id());
    }
    v.extend_from_slice(digest);
    v
}

/// Which appraisal-mode bit a hook's rules contribute to. # C: O(1)
pub fn appraise_flag(func: Hook) -> u32 {
    match func {
        Hook::ModuleCheck => IMA_APPRAISE_MODULES,
        Hook::FirmwareCheck => IMA_APPRAISE_FIRMWARE,
        Hook::PolicyCheck => IMA_APPRAISE_POLICY,
        Hook::KexecKernelCheck => IMA_APPRAISE_KEXEC,
        _ => 0,
    }
}

#[cfg(test)]
mod tests;
