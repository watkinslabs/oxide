// Rule validation: a rule is only accepted when its action, its hook and its
// conditions can all be honoured together. A rule that stores a condition the
// hook's match path never consults would appear to restrict an action it does
// not restrict, so such rules are refused at parse time rather than stored.

use crate::flags::*;
use crate::policy::rule::Rule;
use crate::uapi::Hook;

/// Conditions the inode-oriented hooks accept.
const FILE_CONDS: u32 = C_FUNC | C_MASK | C_FSMAGIC | C_UID | C_FOWNER | C_FSUUID | C_INMASK
    | C_EUID | C_PCR | C_FSNAME | C_FS_SUBTYPE | C_GID | C_EGID | C_FGROUP
    | IMA_DIGSIG_REQUIRED | IMA_PERMIT_DIRECTIO | C_VALIDATE_ALGOS | IMA_CHECK_BLACKLIST
    | IMA_VERITY_REQUIRED | IMA_SIGV3_REQUIRED;

/// Conditions the kernel-read hooks accept: as above, plus an appended module
/// signature, and without the fs-verity digest requirement.
const READ_CONDS: u32 = C_FUNC | C_MASK | C_FSMAGIC | C_UID | C_FOWNER | C_FSUUID | C_INMASK
    | C_EUID | C_PCR | C_FSNAME | C_FS_SUBTYPE | C_GID | C_EGID | C_FGROUP
    | IMA_DIGSIG_REQUIRED | IMA_PERMIT_DIRECTIO | IMA_MODSIG_ALLOWED | IMA_CHECK_BLACKLIST
    | C_VALIDATE_ALGOS | IMA_SIGV3_REQUIRED;

/// Conditions the command-line hook accepts: no inode, so no ownership of the
/// measured data and no appraisal.
const CMDLINE_CONDS: u32 = C_FUNC | C_FSMAGIC | C_UID | C_FOWNER | C_FSUUID | C_EUID | C_PCR
    | C_FSNAME | C_FS_SUBTYPE | C_GID | C_EGID | C_FGROUP;

/// Conditions the key hook accepts.
const KEY_CONDS: u32 = C_FUNC | C_UID | C_GID | C_PCR | C_KEYRINGS;

/// Conditions the critical-data hook accepts.
const DATA_CONDS: u32 = C_FUNC | C_UID | C_GID | C_PCR | C_LABEL;

/// Conditions the setxattr hook accepts: only the algorithm allowlist, because
/// its match path deliberately does not run a full policy check.
const SETXATTR_CONDS: u32 = C_FUNC | C_VALIDATE_ALGOS;

/// True when a rule may be stored. # C: O(1)
pub fn validate_rule(e: &Rule) -> bool {
    if e.action == UNKNOWN { return false; }

    // A PCR selection only means something for a measurement.
    if e.action != MEASURE && e.flags & C_PCR != 0 { return false; }

    // Signature requirements only mean something for an appraisal.
    if e.action != APPRAISE
        && e.flags & (IMA_DIGSIG_REQUIRED | IMA_MODSIG_ALLOWED | IMA_CHECK_BLACKLIST | C_VALIDATE_ALGOS) != 0
    {
        return false;
    }

    // The hook condition bit and a named hook must agree.
    if (e.flags & C_FUNC != 0) != (e.func != Hook::None) { return false; }

    let ok = match e.func {
        Hook::None | Hook::FileCheck | Hook::MmapCheck | Hook::MmapCheckReqprot
        | Hook::BprmCheck | Hook::CredsCheck | Hook::PostSetattr | Hook::FirmwareCheck
        | Hook::PolicyCheck => e.flags & !FILE_CONDS == 0,

        Hook::ModuleCheck | Hook::KexecKernelCheck | Hook::KexecInitramfsCheck =>
            e.flags & !READ_CONDS == 0,

        Hook::KexecCmdline =>
            e.action & !(MEASURE | DONT_MEASURE) == 0 && e.flags & !CMDLINE_CONDS == 0,

        Hook::KeyCheck =>
            e.action & !(MEASURE | DONT_MEASURE) == 0 && e.flags & !KEY_CONDS == 0
            && !e.has_lsm_cond(),

        Hook::CriticalData =>
            e.action & !(MEASURE | DONT_MEASURE) == 0 && e.flags & !DATA_CONDS == 0
            && !e.has_lsm_cond(),

        Hook::SetxattrCheck =>
            e.action == APPRAISE && e.flags & C_VALIDATE_ALGOS != 0
            && e.flags & !SETXATTR_CONDS == 0,

        Hook::MaxCheck => false,
    };
    if !ok { return false; }

    // Blacklist checking is only defined for a rule that requires a signature.
    if e.flags & IMA_CHECK_BLACKLIST != 0 && e.flags & IMA_DIGSIG_REQUIRED == 0 { return false; }

    // An fs-verity digest is only ever carried by a signature, so an appraisal
    // of one must require a signature.
    if e.action == APPRAISE && e.flags & IMA_VERITY_REQUIRED != 0
        && e.flags & IMA_DIGSIG_REQUIRED == 0
    {
        return false;
    }

    true
}
