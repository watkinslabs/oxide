// Bit values: the action mask a policy walk returns, the per-rule condition
// bits that say which filters a rule actually carries, the access-mask bits a
// hook reports, and the appraisal mode bits.

/// Action bits. The measure/appraise/audit/hash bits double as the "do this"
/// bits of a policy-walk result, and each is paired with its `dont_` bit one
/// position higher so a walk can clear both with a single shift.
pub const UNKNOWN: u32 = 0;
pub const MEASURE: u32 = 0x0001;
pub const DONT_MEASURE: u32 = 0x0002;
pub const APPRAISE: u32 = 0x0004;
pub const DONT_APPRAISE: u32 = 0x0008;
pub const AUDIT: u32 = 0x0040;
pub const DONT_AUDIT: u32 = 0x0080;
pub const HASH: u32 = 0x0100;
pub const DONT_HASH: u32 = 0x0200;

/// Per-inode action bits, sharing the numbering of the action bits above.
pub const IMA_MEASURE: u32 = 0x0000_0001;
pub const IMA_MEASURED: u32 = 0x0000_0002;
pub const IMA_APPRAISE: u32 = 0x0000_0004;
pub const IMA_APPRAISED: u32 = 0x0000_0008;
pub const IMA_COLLECTED: u32 = 0x0000_0020;
pub const IMA_AUDIT: u32 = 0x0000_0040;
pub const IMA_AUDITED: u32 = 0x0000_0080;
pub const IMA_HASH: u32 = 0x0000_0100;
pub const IMA_HASHED: u32 = 0x0000_0200;

/// Per-hook appraisal subactions and their done-bits.
pub const IMA_FILE_APPRAISE: u32 = 0x0000_1000;
pub const IMA_FILE_APPRAISED: u32 = 0x0000_2000;
pub const IMA_MMAP_APPRAISE: u32 = 0x0000_4000;
pub const IMA_MMAP_APPRAISED: u32 = 0x0000_8000;
pub const IMA_BPRM_APPRAISE: u32 = 0x0001_0000;
pub const IMA_BPRM_APPRAISED: u32 = 0x0002_0000;
pub const IMA_READ_APPRAISE: u32 = 0x0004_0000;
pub const IMA_READ_APPRAISED: u32 = 0x0008_0000;
pub const IMA_CREDS_APPRAISE: u32 = 0x0010_0000;
pub const IMA_CREDS_APPRAISED: u32 = 0x0020_0000;
pub const IMA_APPRAISE_SUBMASK: u32 =
    IMA_FILE_APPRAISE | IMA_MMAP_APPRAISE | IMA_BPRM_APPRAISE | IMA_READ_APPRAISE | IMA_CREDS_APPRAISE;
pub const IMA_APPRAISED_SUBMASK: u32 =
    IMA_FILE_APPRAISED | IMA_MMAP_APPRAISED | IMA_BPRM_APPRAISED | IMA_READ_APPRAISED | IMA_CREDS_APPRAISED;

/// Non-action bits a matching rule contributes to the walk result.
pub const IMA_NONACTION_FLAGS: u32 = 0xff00_0000;
pub const IMA_DIGSIG_REQUIRED: u32 = 0x0100_0000;
pub const IMA_PERMIT_DIRECTIO: u32 = 0x0200_0000;
pub const IMA_NEW_FILE: u32 = 0x0400_0000;
pub const IMA_SIGV3_REQUIRED: u32 = 0x0800_0000;
pub const IMA_FAIL_UNVERIFIABLE_SIGS: u32 = 0x1000_0000;
pub const IMA_MODSIG_ALLOWED: u32 = 0x2000_0000;
pub const IMA_CHECK_BLACKLIST: u32 = 0x4000_0000;
pub const IMA_VERITY_REQUIRED: u32 = 0x8000_0000;
/// Non-action bits that a rule may carry (the new-file bit is per-inode state).
pub const IMA_NONACTION_RULE_FLAGS: u32 = IMA_NONACTION_FLAGS & !IMA_NEW_FILE;

pub const IMA_DO_MASK: u32 = IMA_MEASURE | IMA_APPRAISE | IMA_AUDIT | IMA_HASH | IMA_APPRAISE_SUBMASK;
pub const IMA_DONE_MASK: u32 =
    IMA_MEASURED | IMA_APPRAISED | IMA_AUDITED | IMA_HASHED | IMA_COLLECTED | IMA_APPRAISED_SUBMASK;

/// Condition bits: which filters a rule carries. A filter field is only
/// consulted when its bit is set, so a value stored without its bit is a
/// condition that can never fire.
pub const C_FUNC: u32 = 0x0_0001;
pub const C_MASK: u32 = 0x0_0002;
pub const C_FSMAGIC: u32 = 0x0_0004;
pub const C_UID: u32 = 0x0_0008;
pub const C_FOWNER: u32 = 0x0_0010;
pub const C_FSUUID: u32 = 0x0_0020;
pub const C_INMASK: u32 = 0x0_0040;
pub const C_EUID: u32 = 0x0_0080;
pub const C_PCR: u32 = 0x0_0100;
pub const C_FSNAME: u32 = 0x0_0200;
pub const C_KEYRINGS: u32 = 0x0_0400;
pub const C_LABEL: u32 = 0x0_0800;
pub const C_VALIDATE_ALGOS: u32 = 0x0_1000;
pub const C_GID: u32 = 0x0_2000;
pub const C_EGID: u32 = 0x0_4000;
pub const C_FGROUP: u32 = 0x0_8000;
pub const C_FS_SUBTYPE: u32 = 0x1_0000;

/// Access-mask bits a hook reports and a `mask=` condition names.
pub const MAY_EXEC: u32 = 0x0000_0001;
pub const MAY_WRITE: u32 = 0x0000_0002;
pub const MAY_READ: u32 = 0x0000_0004;
pub const MAY_APPEND: u32 = 0x0000_0008;

/// Appraisal mode bits.
pub const IMA_APPRAISE_ENFORCE: u32 = 0x01;
pub const IMA_APPRAISE_FIX: u32 = 0x02;
pub const IMA_APPRAISE_LOG: u32 = 0x04;
pub const IMA_APPRAISE_MODULES: u32 = 0x08;
pub const IMA_APPRAISE_FIRMWARE: u32 = 0x10;
pub const IMA_APPRAISE_POLICY: u32 = 0x20;
pub const IMA_APPRAISE_KEXEC: u32 = 0x40;

/// EVM state bits.
pub const EVM_INIT_HMAC: u32 = 0x0001;
pub const EVM_INIT_X509: u32 = 0x0002;
pub const EVM_ALLOW_METADATA_WRITES: u32 = 0x0004;
pub const EVM_SIGV3_REQUIRED: u32 = 0x0008;
pub const EVM_SETUP_COMPLETE: u32 = 0x8000_0000;
pub const EVM_KEY_MASK: u32 = EVM_INIT_HMAC | EVM_INIT_X509;
pub const EVM_INIT_MASK: u32 =
    EVM_INIT_HMAC | EVM_INIT_X509 | EVM_SETUP_COMPLETE | EVM_ALLOW_METADATA_WRITES | EVM_SIGV3_REQUIRED;

/// Per-inode EVM bits.
pub const EVM_NEW_FILE: u32 = 0x0000_0001;
pub const EVM_IMMUTABLE_DIGSIG: u32 = 0x0000_0002;

/// Include the filesystem UUID in the EVM HMAC.
pub const EVM_ATTR_FSUUID: u32 = 0x0001;
