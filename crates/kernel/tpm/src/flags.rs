// Bit definitions and register offsets for the two hardware interfaces, plus
// the session/object attribute bits carried in command bodies. Bits only —
// the handshakes that act on them live in `tis.rs` / `crb.rs`.

// ---- FIFO interface: register offsets ------------------------------------
//
// Every register is banked per locality; the locality index occupies bits
// 12..14 of the offset.

/// Locality index shift within a FIFO-interface register offset.
pub const TIS_LOCALITY_SHIFT: u32 = 12;
/// Largest locality a FIFO interface exposes.
pub const TIS_MAX_LOCALITY: u8 = 4;
/// Address span of the whole FIFO interface.
pub const TIS_MEM_LEN: u32 = 0x5000;

const fn tis_reg(base: u32, loc: u8) -> u32 { base | ((loc as u32) << TIS_LOCALITY_SHIFT) }

/// Access register of locality `loc`.
/// # C: O(1)
pub const fn tpm_access(loc: u8) -> u32 { tis_reg(0x0000, loc) }
/// Interrupt-enable register of locality `loc`.
/// # C: O(1)
pub const fn tpm_int_enable(loc: u8) -> u32 { tis_reg(0x0008, loc) }
/// Interrupt-vector register of locality `loc`.
/// # C: O(1)
pub const fn tpm_int_vector(loc: u8) -> u32 { tis_reg(0x000C, loc) }
/// Interrupt-status register of locality `loc`.
/// # C: O(1)
pub const fn tpm_int_status(loc: u8) -> u32 { tis_reg(0x0010, loc) }
/// Interface-capability register of locality `loc`.
/// # C: O(1)
pub const fn tpm_intf_caps(loc: u8) -> u32 { tis_reg(0x0014, loc) }
/// Status register of locality `loc`; burst count occupies bits 8..23.
/// # C: O(1)
pub const fn tpm_sts(loc: u8) -> u32 { tis_reg(0x0018, loc) }
/// Data FIFO of locality `loc`.
/// # C: O(1)
pub const fn tpm_data_fifo(loc: u8) -> u32 { tis_reg(0x0024, loc) }
/// Device/vendor identifier register of locality `loc`.
/// # C: O(1)
pub const fn tpm_did_vid(loc: u8) -> u32 { tis_reg(0x0F00, loc) }
/// Revision identifier register of locality `loc`.
/// # C: O(1)
pub const fn tpm_rid(loc: u8) -> u32 { tis_reg(0x0F04, loc) }

// ---- FIFO interface: ACCESS bits -----------------------------------------

/// Set once the device has completed self test and the other bits are valid.
pub const TPM_ACCESS_VALID: u8 = 0x80;
/// Reads as the locality currently owning the interface; written to release.
pub const TPM_ACCESS_ACTIVE_LOCALITY: u8 = 0x20;
/// A higher locality has an outstanding request.
pub const TPM_ACCESS_REQUEST_PENDING: u8 = 0x04;
/// Written to ask for the locality.
pub const TPM_ACCESS_REQUEST_USE: u8 = 0x02;

// ---- FIFO interface: STS bits --------------------------------------------

pub const TPM_STS_VALID: u8 = 0x80;
pub const TPM_STS_COMMAND_READY: u8 = 0x40;
pub const TPM_STS_GO: u8 = 0x20;
pub const TPM_STS_DATA_AVAIL: u8 = 0x10;
pub const TPM_STS_DATA_EXPECT: u8 = 0x08;
pub const TPM_STS_RESPONSE_RETRY: u8 = 0x02;
/// Bits required to read as zero; any set bit means the read is not valid.
pub const TPM_STS_READ_ZERO: u8 = 0x23;
/// Shift of the burst-count field within the 32-bit status register.
pub const TPM_STS_BURST_SHIFT: u32 = 8;
/// Mask of the burst-count field once shifted down.
pub const TPM_STS_BURST_MASK: u32 = 0xFFFF;

// ---- FIFO interface: interface-capability bits ---------------------------

pub const TPM_GLOBAL_INT_ENABLE: u32 = 0x8000_0000;
pub const TPM_INTF_BURST_COUNT_STATIC: u32 = 0x100;
pub const TPM_INTF_CMD_READY_INT: u32 = 0x080;
pub const TPM_INTF_INT_EDGE_FALLING: u32 = 0x040;
pub const TPM_INTF_INT_EDGE_RISING: u32 = 0x020;
pub const TPM_INTF_INT_LEVEL_LOW: u32 = 0x010;
pub const TPM_INTF_INT_LEVEL_HIGH: u32 = 0x008;
pub const TPM_INTF_LOCALITY_CHANGE_INT: u32 = 0x004;
pub const TPM_INTF_STS_VALID_INT: u32 = 0x002;
pub const TPM_INTF_DATA_AVAIL_INT: u32 = 0x001;

// ---- Command-response-buffer interface: control-area offsets -------------

pub const CRB_LOC_STATE: u32 = 0x0000;
pub const CRB_LOC_CTRL: u32 = 0x0008;
pub const CRB_LOC_STS: u32 = 0x000C;
pub const CRB_INTF_ID: u32 = 0x0030;
pub const CRB_CTRL_EXT: u32 = 0x0038;
/// The control area proper starts one head-structure past the interface base.
pub const CRB_CTRL_BASE: u32 = 0x0040;
pub const CRB_CTRL_REQ: u32 = CRB_CTRL_BASE;
pub const CRB_CTRL_STS: u32 = CRB_CTRL_BASE + 0x04;
pub const CRB_CTRL_CANCEL: u32 = CRB_CTRL_BASE + 0x08;
pub const CRB_CTRL_START: u32 = CRB_CTRL_BASE + 0x0C;
pub const CRB_CTRL_INT_ENABLE: u32 = CRB_CTRL_BASE + 0x10;
pub const CRB_CTRL_INT_STS: u32 = CRB_CTRL_BASE + 0x14;
pub const CRB_CTRL_CMD_SIZE: u32 = CRB_CTRL_BASE + 0x18;
pub const CRB_CTRL_CMD_PA_LOW: u32 = CRB_CTRL_BASE + 0x1C;
pub const CRB_CTRL_CMD_PA_HIGH: u32 = CRB_CTRL_BASE + 0x20;
pub const CRB_CTRL_RSP_SIZE: u32 = CRB_CTRL_BASE + 0x24;
pub const CRB_CTRL_RSP_PA: u32 = CRB_CTRL_BASE + 0x28;

// ---- Command-response-buffer interface: control bits ---------------------

/// Written to loc_ctrl to claim the locality.
pub const CRB_LOC_CTRL_REQUEST_ACCESS: u32 = 1 << 0;
/// Written to loc_ctrl to release the locality.
pub const CRB_LOC_CTRL_RELINQUISH: u32 = 1 << 1;
/// loc_state: the requested locality is assigned.
pub const CRB_LOC_STATE_LOC_ASSIGNED: u32 = 1 << 1;
/// loc_state: the register values are valid.
pub const CRB_LOC_STATE_TPM_REG_VALID_STS: u32 = 1 << 7;
/// ctrl_req: ask the device to leave idle; the device clears the bit.
pub const CRB_CTRL_REQ_CMD_READY: u32 = 1 << 0;
/// ctrl_req: ask the device to enter idle; the device clears the bit.
pub const CRB_CTRL_REQ_GO_IDLE: u32 = 1 << 1;
/// ctrl_sts: the device is in an unrecoverable condition.
pub const CRB_CTRL_STS_ERROR: u32 = 1 << 0;
/// ctrl_sts: the device is idle.
pub const CRB_CTRL_STS_TPM_IDLE: u32 = 1 << 1;
/// ctrl_start: written to run the command; the device clears it on completion.
pub const CRB_START_INVOKE: u32 = 1 << 0;
/// ctrl_cancel: written to abort the running command.
pub const CRB_CANCEL_INVOKE: u32 = 1 << 0;

// ---- Session and object attributes ---------------------------------------

pub const TPM2_SA_CONTINUE_SESSION: u8 = 1 << 0;
pub const TPM2_SA_AUDIT_EXCLUSIVE: u8 = 1 << 1;
pub const TPM2_SA_AUDIT_RESET: u8 = 1 << 3;
pub const TPM2_SA_DECRYPT: u8 = 1 << 5;
pub const TPM2_SA_ENCRYPT: u8 = 1 << 6;
pub const TPM2_SA_AUDIT: u8 = 1 << 7;

pub const TPM2_OA_FIXED_TPM: u32 = 1 << 1;
pub const TPM2_OA_ST_CLEAR: u32 = 1 << 2;
pub const TPM2_OA_FIXED_PARENT: u32 = 1 << 4;
pub const TPM2_OA_SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
pub const TPM2_OA_USER_WITH_AUTH: u32 = 1 << 6;
pub const TPM2_OA_ADMIN_WITH_POLICY: u32 = 1 << 7;
pub const TPM2_OA_NO_DA: u32 = 1 << 10;
pub const TPM2_OA_ENCRYPTED_DUPLICATION: u32 = 1 << 11;
pub const TPM2_OA_RESTRICTED: u32 = 1 << 16;
pub const TPM2_OA_DECRYPT: u32 = 1 << 17;
pub const TPM2_OA_SIGN: u32 = 1 << 18;
