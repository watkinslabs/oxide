// TPM 2.0 / 1.2 wire constants. Numbers only — no policy, no dispatch.
// Every value here is part of an externally-defined ABI; logic that acts on
// them lives in `rc.rs`, `codec/`, `tis.rs`, `crb.rs`, `eventlog/`.

/// Command header: tag u16 BE, length u32 BE, code u32 BE.
pub const HEADER_SIZE: usize = 10;
/// Byte offset of the tag field within a command/response header.
pub const HDR_OFF_TAG: usize = 0;
/// Byte offset of the length field within a command/response header.
pub const HDR_OFF_LEN: usize = 2;
/// Byte offset of the command code / response code field.
pub const HDR_OFF_CODE: usize = 6;

// ---- TPM_ST_* structure tags ---------------------------------------------

/// Command/response carries no authorisation sessions.
pub const TPM2_ST_NO_SESSIONS: u16 = 0x8001;
/// Command/response carries an authorisation area.
pub const TPM2_ST_SESSIONS: u16 = 0x8002;
/// Attestation structure tag for creation data.
pub const TPM2_ST_CREATION: u16 = 0x8021;
/// TPM 1.2 request tag.
pub const TPM_TAG_RQU_COMMAND: u16 = 193;

// ---- TPM2_CC_* command codes ---------------------------------------------

/// Lowest assigned command code.
pub const TPM2_CC_FIRST: u32 = 0x011F;
pub const TPM2_CC_HIERARCHY_CONTROL: u32 = 0x0121;
pub const TPM2_CC_HIERARCHY_CHANGE_AUTH: u32 = 0x0129;
pub const TPM2_CC_CREATE_PRIMARY: u32 = 0x0131;
pub const TPM2_CC_SEQUENCE_COMPLETE: u32 = 0x013E;
pub const TPM2_CC_SELF_TEST: u32 = 0x0143;
pub const TPM2_CC_STARTUP: u32 = 0x0144;
pub const TPM2_CC_SHUTDOWN: u32 = 0x0145;
pub const TPM2_CC_NV_READ: u32 = 0x014E;
pub const TPM2_CC_CREATE: u32 = 0x0153;
pub const TPM2_CC_LOAD: u32 = 0x0157;
pub const TPM2_CC_SEQUENCE_UPDATE: u32 = 0x015C;
pub const TPM2_CC_UNSEAL: u32 = 0x015E;
pub const TPM2_CC_CONTEXT_LOAD: u32 = 0x0161;
pub const TPM2_CC_CONTEXT_SAVE: u32 = 0x0162;
pub const TPM2_CC_FLUSH_CONTEXT: u32 = 0x0165;
pub const TPM2_CC_READ_PUBLIC: u32 = 0x0173;
pub const TPM2_CC_START_AUTH_SESS: u32 = 0x0176;
pub const TPM2_CC_VERIFY_SIGNATURE: u32 = 0x0177;
pub const TPM2_CC_GET_CAPABILITY: u32 = 0x017A;
pub const TPM2_CC_GET_RANDOM: u32 = 0x017B;
pub const TPM2_CC_GET_TEST_RESULT: u32 = 0x017C;
pub const TPM2_CC_PCR_READ: u32 = 0x017E;
pub const TPM2_CC_PCR_EXTEND: u32 = 0x0182;
pub const TPM2_CC_EVENT_SEQUENCE_COMPLETE: u32 = 0x0185;
pub const TPM2_CC_HASH_SEQUENCE_START: u32 = 0x0186;
pub const TPM2_CC_CREATE_LOADED: u32 = 0x0191;
pub const TPM2_CC_NV_WRITE: u32 = 0x0137;
pub const TPM2_CC_NV_READ_PUBLIC: u32 = 0x0169;
pub const TPM2_CC_STIR_RANDOM: u32 = 0x0146;
/// Highest assigned command code.
pub const TPM2_CC_LAST: u32 = 0x0193;

// ---- TPM2_RC_* response codes --------------------------------------------

/// Command completed successfully.
pub const TPM2_RC_SUCCESS: u32 = 0x0000;
/// Format-one base: bit 7 selects the format-one encoding.
pub const TPM2_RC_FMT1: u32 = 0x0080;
/// Format-zero TPM 2.0 error base.
pub const TPM2_RC_VER1: u32 = 0x0100;
/// Format-zero TPM 2.0 warning base.
pub const TPM2_RC_WARN: u32 = 0x0900;

pub const TPM2_RC_HASH: u32 = 0x0083;
pub const TPM2_RC_VALUE: u32 = 0x0084;
pub const TPM2_RC_SIZE: u32 = 0x0095;
pub const TPM2_RC_HANDLE: u32 = 0x008B;
pub const TPM2_RC_INTEGRITY: u32 = 0x009F;
pub const TPM2_RC_INITIALIZE: u32 = 0x0100;
pub const TPM2_RC_FAILURE: u32 = 0x0101;
pub const TPM2_RC_DISABLED: u32 = 0x0120;
pub const TPM2_RC_UPGRADE: u32 = 0x012D;
pub const TPM2_RC_COMMAND_CODE: u32 = 0x0143;
pub const TPM2_RC_SESSION_MEMORY: u32 = 0x0903;
pub const TPM2_RC_TESTING: u32 = 0x090A;
pub const TPM2_RC_REFERENCE_H0: u32 = 0x0910;
pub const TPM2_RC_RETRY: u32 = 0x0922;

/// Software-stack layer occupies the upper half of a 32-bit code.
pub const RC_LAYER_SHIFT: u32 = 16;
/// Layer stamped on codes the in-kernel resource manager synthesises.
pub const RESMGR_TPM_RC_LAYER: u32 = 11 << RC_LAYER_SHIFT;

// ---- TPM2_ALG_* algorithm identifiers ------------------------------------

pub const TPM_ALG_ERROR: u16 = 0x0000;
pub const TPM_ALG_SHA1: u16 = 0x0004;
pub const TPM_ALG_AES: u16 = 0x0006;
pub const TPM_ALG_KEYEDHASH: u16 = 0x0008;
pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_ALG_SHA384: u16 = 0x000C;
pub const TPM_ALG_SHA512: u16 = 0x000D;
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ALG_SM3_256: u16 = 0x0012;
pub const TPM_ALG_ECC: u16 = 0x0023;
pub const TPM_ALG_CFB: u16 = 0x0043;

pub const SHA1_DIGEST_SIZE: usize = 20;
pub const SHA256_DIGEST_SIZE: usize = 32;
pub const SHA384_DIGEST_SIZE: usize = 48;
pub const SHA512_DIGEST_SIZE: usize = 64;
pub const SM3_256_DIGEST_SIZE: usize = 32;

// ---- TPM2_RH_* / handle ranges -------------------------------------------

pub const TPM2_RH_OWNER: u32 = 0x40000001;
pub const TPM2_RH_NULL: u32 = 0x40000007;
pub const TPM2_RH_LOCKOUT: u32 = 0x4000000A;
pub const TPM2_RH_ENDORSEMENT: u32 = 0x4000000B;
pub const TPM2_RH_PLATFORM: u32 = 0x4000000C;
/// Password authorisation session handle.
pub const TPM2_RS_PW: u32 = 0x40000009;

/// Handle range bases, selected by the most significant octet.
pub const TPM2_HT_HMAC_SESSION: u32 = 0x02000000;
pub const TPM2_HT_POLICY_SESSION: u32 = 0x03000000;
pub const TPM2_HT_TRANSIENT: u32 = 0x80000000;
/// Mask isolating the most significant octet of a handle.
pub const TPM2_HT_MASK: u32 = 0xFF000000;
/// Mask isolating the index part of a handle.
pub const TPM2_HANDLE_INDEX_MASK: u32 = 0x00FFFFFF;

// ---- Capabilities and properties -----------------------------------------

pub const TPM2_CAP_HANDLES: u32 = 1;
pub const TPM2_CAP_COMMANDS: u32 = 2;
pub const TPM2_CAP_PCRS: u32 = 5;
pub const TPM2_CAP_TPM_PROPERTIES: u32 = 6;

pub const TPM2_PT_GROUP: u32 = 0x00000100;
pub const TPM2_PT_FIXED: u32 = TPM2_PT_GROUP;
pub const TPM2_PT_MANUFACTURER: u32 = TPM2_PT_FIXED + 5;
pub const TPM2_PT_PCR_COUNT: u32 = TPM2_PT_FIXED + 18;
pub const TPM2_PT_MAX_COMMAND_SIZE: u32 = TPM2_PT_FIXED + 30;
pub const TPM2_PT_MAX_RESPONSE_SIZE: u32 = TPM2_PT_FIXED + 31;
pub const TPM2_PT_MAX_DIGEST: u32 = TPM2_PT_FIXED + 32;
pub const TPM2_PT_TOTAL_COMMANDS: u32 = TPM2_PT_FIXED + 41;

/// Bit position of the command-handle count within a command attribute word.
pub const TPM2_CC_ATTR_CHANDLES: u32 = 25;
/// Bit position of the response-handle flag within a command attribute word.
pub const TPM2_CC_ATTR_RHANDLE: u32 = 28;
/// Bit position of the vendor-defined flag within a command attribute word.
pub const TPM2_CC_ATTR_VENDOR: u32 = 29;

// ---- Startup types --------------------------------------------------------

/// Startup with state discarded — PCRs take their reset values.
pub const TPM2_SU_CLEAR: u16 = 0x0000;
/// Startup restoring previously saved state.
pub const TPM2_SU_STATE: u16 = 0x0001;

// ---- TPM 1.2 ordinals -----------------------------------------------------

pub const TPM_ORD_PCR_EXTEND: u32 = 20;
pub const TPM_ORD_PCRREAD: u32 = 21;
pub const TPM_ORD_GET_RANDOM: u32 = 70;
pub const TPM_ORD_CONTINUE_SELFTEST: u32 = 83;
pub const TPM_ORD_GET_CAP: u32 = 101;
pub const TPM_ORD_SAVESTATE: u32 = 152;
pub const TPM_ORD_STARTUP: u32 = 153;
/// TPM 1.2 startup: reset state.
pub const TPM_ST_CLEAR: u16 = 1;
