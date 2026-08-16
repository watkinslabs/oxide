//! L2CAP wire and ABI constants: header widths, fixed channel identifiers,
//! signalling command codes and their result enumerations, configuration
//! option types and results, the control-field bit layout for both widths, and
//! the socket ABI (`sockaddr_l2`, the `SOL_L2CAP` options).
//!
//! Constants only. Every decision that consults one lives in `l2cap`.

// ---- header widths ----------------------------------------------------------

/// `l2cap_hdr`: little-endian payload length then channel identifier.
pub const HDR_SIZE: usize = 4;
/// Width of the length field alone, which a fragment reassembler needs before
/// it knows how much more to collect.
pub const LEN_SIZE: usize = 2;
/// Basic header plus a 16-bit enhanced control field.
pub const ENH_HDR_SIZE: usize = 6;
/// Basic header plus a 32-bit extended control field.
pub const EXT_HDR_SIZE: usize = 8;
pub const ENH_CTRL_SIZE: usize = 2;
pub const EXT_CTRL_SIZE: usize = 4;
/// Trailing CRC-16 frame check sequence, when negotiated.
pub const FCS_SIZE: usize = 2;
/// Length prefix the first frame of a segmented SDU carries.
pub const SDULEN_SIZE: usize = 2;
/// PSM length prefix on a connectionless frame.
pub const PSMLEN_SIZE: usize = 2;
/// `l2cap_cmd_hdr`: code, identifier, little-endian length.
pub const CMD_HDR_SIZE: usize = 4;

// ---- defaults ---------------------------------------------------------------

pub const DEFAULT_MTU: u16 = 672;
pub const DEFAULT_MIN_MTU: u16 = 48;
/// Signalling MTU on BR/EDR: a signalling packet longer than this is rejected
/// whole rather than parsed.
pub const SIG_MTU: usize = 48;
pub const DEFAULT_FLUSH_TO: u16 = 0xFFFF;
pub const EFS_DEFAULT_FLUSH_TO: u32 = 0xFFFF_FFFF;
pub const DEFAULT_TX_WINDOW: u16 = 63;
pub const DEFAULT_EXT_WINDOW: u16 = 0x3FFF;
pub const DEFAULT_MAX_TX: u8 = 3;
pub const DEFAULT_RETRANS_TO: u16 = 2000;
pub const DEFAULT_MONITOR_TO: u16 = 12000;
pub const DEFAULT_MAX_PDU_SIZE: u16 = 1492;
pub const DEFAULT_ACK_TO: u16 = 200;
pub const DEFAULT_MAX_SDU_SIZE: u16 = 0xFFFF;
pub const DEFAULT_SDU_ITIME: u32 = 0xFFFF_FFFF;
pub const DEFAULT_ACC_LAT: u32 = 0xFFFF_FFFF;
/// Largest BR/EDR baseband payload, which caps an ERTM PDU so one PDU is one
/// HCI fragment.
pub const BREDR_MAX_PAYLOAD: u16 = 1019;
/// Smallest MTU an LE channel may declare.
pub const LE_MIN_MTU: u16 = 23;
/// Credit ceiling: a grant that would push the outstanding count past this is a
/// protocol violation.
pub const LE_MAX_CREDITS: u16 = 65535;

// ---- fixed channel identifiers ----------------------------------------------

pub const CID_SIGNALING: u16 = 0x0001;
pub const CID_CONN_LESS: u16 = 0x0002;
pub const CID_ATT: u16 = 0x0004;
pub const CID_LE_SIGNALING: u16 = 0x0005;
pub const CID_SMP: u16 = 0x0006;
pub const CID_SMP_BREDR: u16 = 0x0007;
pub const CID_DYN_START: u16 = 0x0040;
pub const CID_DYN_END: u16 = 0xffff;
/// Highest dynamic identifier an LE link may use.
pub const CID_LE_DYN_END: u16 = 0x007f;

/// Fixed-channel-supported mask bits, as carried by an information response.
pub const FC_SIG_BREDR: u8 = 0x02;
pub const FC_CONNLESS: u8 = 0x04;
pub const FC_ATT: u8 = 0x10;
pub const FC_SIG_LE: u8 = 0x20;
pub const FC_SMP_LE: u8 = 0x40;
pub const FC_SMP_BREDR: u8 = 0x80;
/// Width of the fixed-channel mask on the wire.
pub const FIXED_CHAN_MASK_LEN: usize = 8;

// ---- signalling command codes -----------------------------------------------

pub const COMMAND_REJ: u8 = 0x01;
pub const CONN_REQ: u8 = 0x02;
pub const CONN_RSP: u8 = 0x03;
pub const CONF_REQ: u8 = 0x04;
pub const CONF_RSP: u8 = 0x05;
pub const DISCONN_REQ: u8 = 0x06;
pub const DISCONN_RSP: u8 = 0x07;
pub const ECHO_REQ: u8 = 0x08;
pub const ECHO_RSP: u8 = 0x09;
pub const INFO_REQ: u8 = 0x0a;
pub const INFO_RSP: u8 = 0x0b;
pub const CONN_PARAM_UPDATE_REQ: u8 = 0x12;
pub const CONN_PARAM_UPDATE_RSP: u8 = 0x13;
pub const LE_CONN_REQ: u8 = 0x14;
pub const LE_CONN_RSP: u8 = 0x15;
pub const LE_CREDITS: u8 = 0x16;
pub const ECRED_CONN_REQ: u8 = 0x17;
pub const ECRED_CONN_RSP: u8 = 0x18;
pub const ECRED_RECONF_REQ: u8 = 0x19;
pub const ECRED_RECONF_RSP: u8 = 0x1a;

/// Command reject reasons, each with its own payload width.
pub const REJ_NOT_UNDERSTOOD: u16 = 0x0000;
pub const REJ_MTU_EXCEEDED: u16 = 0x0001;
pub const REJ_INVALID_CID: u16 = 0x0002;

/// Fixed payload widths of the commands whose length is not variable.
pub const CMD_REJ_UNK_LEN: usize = 2;
pub const CMD_REJ_MTU_LEN: usize = 4;
pub const CMD_REJ_CID_LEN: usize = 6;
pub const CONN_REQ_LEN: usize = 4;
pub const CONN_RSP_LEN: usize = 8;
pub const CONF_REQ_MIN_LEN: usize = 4;
pub const CONF_RSP_MIN_LEN: usize = 6;
pub const DISCONN_LEN: usize = 4;
pub const INFO_REQ_LEN: usize = 2;
pub const INFO_RSP_MIN_LEN: usize = 4;
pub const CONN_PARAM_UPDATE_REQ_LEN: usize = 8;
pub const CONN_PARAM_UPDATE_RSP_LEN: usize = 2;
pub const LE_CONN_REQ_LEN: usize = 10;
pub const LE_CONN_RSP_LEN: usize = 10;
pub const LE_CREDITS_LEN: usize = 4;
pub const ECRED_CONN_REQ_HDR_LEN: usize = 8;
pub const ECRED_CONN_RSP_HDR_LEN: usize = 8;
pub const ECRED_RECONF_REQ_HDR_LEN: usize = 4;
pub const ECRED_RECONF_RSP_LEN: usize = 2;
/// Width of one channel identifier in an ECRED command's identifier array.
pub const CID_WIDTH: usize = 2;

// ---- connect results --------------------------------------------------------

pub const CR_SUCCESS: u16 = 0x0000;
pub const CR_PEND: u16 = 0x0001;
pub const CR_BAD_PSM: u16 = 0x0002;
pub const CR_SEC_BLOCK: u16 = 0x0003;
pub const CR_NO_MEM: u16 = 0x0004;
pub const CR_INVALID_SCID: u16 = 0x0006;
pub const CR_SCID_IN_USE: u16 = 0x0007;

/// Credit-based connect results, a separate enumeration from the BR/EDR one.
pub const CR_LE_SUCCESS: u16 = 0x0000;
pub const CR_LE_BAD_PSM: u16 = 0x0002;
pub const CR_LE_NO_MEM: u16 = 0x0004;
pub const CR_LE_AUTHENTICATION: u16 = 0x0005;
pub const CR_LE_AUTHORIZATION: u16 = 0x0006;
pub const CR_LE_BAD_KEY_SIZE: u16 = 0x0007;
pub const CR_LE_ENCRYPTION: u16 = 0x0008;
pub const CR_LE_INVALID_SCID: u16 = 0x0009;
pub const CR_LE_SCID_IN_USE: u16 = 0x000A;
pub const CR_LE_UNACCEPT_PARAMS: u16 = 0x000B;
pub const CR_LE_INVALID_PARAMS: u16 = 0x000C;

pub const CS_NO_INFO: u16 = 0x0000;
pub const CS_AUTHEN_PEND: u16 = 0x0001;
pub const CS_AUTHOR_PEND: u16 = 0x0002;

/// ECRED reconfigure results.
pub const RECONF_SUCCESS: u16 = 0x0000;
pub const RECONF_INVALID_MTU: u16 = 0x0001;
pub const RECONF_INVALID_MPS: u16 = 0x0002;
pub const RECONF_INVALID_CID: u16 = 0x0003;
pub const RECONF_INVALID_PARAMS: u16 = 0x0004;

/// LE connection parameter update results.
pub const CONN_PARAM_ACCEPTED: u16 = 0x0000;
pub const CONN_PARAM_REJECTED: u16 = 0x0001;

// ---- information exchange ---------------------------------------------------

pub const IT_CL_MTU: u16 = 0x0001;
pub const IT_FEAT_MASK: u16 = 0x0002;
pub const IT_FIXED_CHAN: u16 = 0x0003;

pub const IR_SUCCESS: u16 = 0x0000;
pub const IR_NOTSUPP: u16 = 0x0001;

/// Extended feature mask bits.
pub const FEAT_FLOWCTL: u32 = 0x0000_0001;
pub const FEAT_RETRANS: u32 = 0x0000_0002;
pub const FEAT_BIDIR_QOS: u32 = 0x0000_0004;
pub const FEAT_ERTM: u32 = 0x0000_0008;
pub const FEAT_STREAMING: u32 = 0x0000_0010;
pub const FEAT_FCS: u32 = 0x0000_0020;
pub const FEAT_EXT_FLOW: u32 = 0x0000_0040;
pub const FEAT_FIXED_CHAN: u32 = 0x0000_0080;
pub const FEAT_EXT_WINDOW: u32 = 0x0000_0100;
pub const FEAT_UCD: u32 = 0x0000_0200;
/// Width of the feature mask on the wire.
pub const FEAT_MASK_LEN: usize = 4;

// ---- configuration ----------------------------------------------------------

pub const CONF_OPT_SIZE: usize = 2;
/// Hint bit: an option carrying it may be ignored without an error.
pub const CONF_HINT: u8 = 0x80;
pub const CONF_MASK: u8 = 0x7f;

pub const CONF_MTU: u8 = 0x01;
pub const CONF_FLUSH_TO: u8 = 0x02;
pub const CONF_QOS: u8 = 0x03;
pub const CONF_RFC: u8 = 0x04;
pub const CONF_FCS: u8 = 0x05;
pub const CONF_EFS: u8 = 0x06;
pub const CONF_EWS: u8 = 0x07;

/// Value widths of the fixed-width configuration options.
pub const CONF_MTU_LEN: usize = 2;
pub const CONF_FLUSH_TO_LEN: usize = 2;
pub const CONF_RFC_LEN: usize = 9;
pub const CONF_FCS_LEN: usize = 1;
pub const CONF_EFS_LEN: usize = 16;
pub const CONF_EWS_LEN: usize = 2;
pub const CONF_QOS_LEN: usize = 22;
/// Largest option value a configuration request may carry.
pub const CONF_MAX_SIZE: usize = 22;

pub const CONF_SUCCESS: u16 = 0x0000;
pub const CONF_UNACCEPT: u16 = 0x0001;
pub const CONF_REJECT: u16 = 0x0002;
pub const CONF_UNKNOWN: u16 = 0x0003;
pub const CONF_PENDING: u16 = 0x0004;
pub const CONF_EFS_REJECT: u16 = 0x0005;

/// Continuation flag: more options follow in a further request or response.
pub const CONF_FLAG_CONTINUATION: u16 = 0x0001;

/// Rounds of configuration a channel will attempt before giving up.
pub const CONF_MAX_CONF_REQ: u8 = 2;
pub const CONF_MAX_CONF_RSP: u8 = 2;

/// Transmission modes as they appear in an RFC option.
pub const MODE_BASIC: u8 = 0x00;
pub const MODE_RETRANS: u8 = 0x01;
pub const MODE_FLOWCTL: u8 = 0x02;
pub const MODE_ERTM: u8 = 0x03;
pub const MODE_STREAMING: u8 = 0x04;
/// Internal modes, chosen outside the on-air range so they can never collide
/// with a mode a peer proposes.
pub const MODE_LE_FLOWCTL: u8 = 0x80;
pub const MODE_EXT_FLOWCTL: u8 = 0x81;

pub const FCS_NONE: u8 = 0x00;
pub const FCS_CRC16: u8 = 0x01;

/// Extended flow specification service types.
pub const SERV_NOTRAFIC: u8 = 0x00;
pub const SERV_BESTEFFORT: u8 = 0x01;
pub const SERV_GUARANTEED: u8 = 0x02;
pub const BESTEFFORT_ID: u8 = 0x01;

// ---- enhanced (16-bit) control field ----------------------------------------

pub const CTRL_SAR: u16 = 0xC000;
pub const CTRL_REQSEQ: u16 = 0x3F00;
pub const CTRL_TXSEQ: u16 = 0x007E;
pub const CTRL_SUPERVISE: u16 = 0x000C;
pub const CTRL_FINAL: u16 = 0x0080;
pub const CTRL_POLL: u16 = 0x0010;
pub const CTRL_FRAME_TYPE: u16 = 0x0001;

pub const CTRL_TXSEQ_SHIFT: u32 = 1;
pub const CTRL_SUPER_SHIFT: u32 = 2;
pub const CTRL_POLL_SHIFT: u32 = 4;
pub const CTRL_FINAL_SHIFT: u32 = 7;
pub const CTRL_REQSEQ_SHIFT: u32 = 8;
pub const CTRL_SAR_SHIFT: u32 = 14;

// ---- extended (32-bit) control field ----------------------------------------

pub const EXT_CTRL_TXSEQ: u32 = 0xFFFC_0000;
pub const EXT_CTRL_SAR: u32 = 0x0003_0000;
pub const EXT_CTRL_SUPERVISE: u32 = 0x0003_0000;
pub const EXT_CTRL_REQSEQ: u32 = 0x0000_FFFC;
pub const EXT_CTRL_POLL: u32 = 0x0004_0000;
pub const EXT_CTRL_FINAL: u32 = 0x0000_0002;
pub const EXT_CTRL_FRAME_TYPE: u32 = 0x0000_0001;

pub const EXT_CTRL_FINAL_SHIFT: u32 = 1;
pub const EXT_CTRL_REQSEQ_SHIFT: u32 = 2;
pub const EXT_CTRL_SAR_SHIFT: u32 = 16;
pub const EXT_CTRL_SUPER_SHIFT: u32 = 16;
pub const EXT_CTRL_POLL_SHIFT: u32 = 18;
pub const EXT_CTRL_TXSEQ_SHIFT: u32 = 18;

/// Supervisory function of an S-frame.
pub const SUPER_RR: u8 = 0x00;
pub const SUPER_REJ: u8 = 0x01;
pub const SUPER_RNR: u8 = 0x02;
pub const SUPER_SREJ: u8 = 0x03;

/// Segmentation and reassembly field of an I-frame.
pub const SAR_UNSEGMENTED: u8 = 0x00;
pub const SAR_START: u8 = 0x01;
pub const SAR_END: u8 = 0x02;
pub const SAR_CONTINUE: u8 = 0x03;

/// Transmitter states of the ERTM state machine.
pub const TX_STATE_XMIT: u8 = 0;
pub const TX_STATE_WAIT_F: u8 = 1;

/// Receiver states of the ERTM state machine.
pub const RX_STATE_RECV: u8 = 0;
pub const RX_STATE_SREJ_SENT: u8 = 1;
pub const RX_STATE_MOVE: u8 = 2;
pub const RX_STATE_WAIT_P: u8 = 3;
pub const RX_STATE_WAIT_F: u8 = 4;

// ---- ECRED ------------------------------------------------------------------

pub const ECRED_MIN_MTU: u16 = 64;
pub const ECRED_MIN_MPS: u16 = 64;
/// Most channels one ECRED command may name.
pub const ECRED_MAX_CID: usize = 5;

// ---- PSM --------------------------------------------------------------------

pub const PSM_SDP: u16 = 0x0001;
pub const PSM_RFCOMM: u16 = 0x0003;
pub const PSM_3DSP: u16 = 0x0021;
pub const PSM_IPSP: u16 = 0x0023;

pub const PSM_DYN_START: u16 = 0x1001;
pub const PSM_DYN_END: u16 = 0xffff;
pub const PSM_AUTO_END: u16 = 0x10ff;
pub const PSM_LE_DYN_START: u16 = 0x0080;
pub const PSM_LE_DYN_END: u16 = 0x00ff;

/// Bits a BR/EDR PSM must satisfy: odd, with the low bit of the upper byte
/// clear.
pub const PSM_BREDR_MASK: u16 = 0x0101;
pub const PSM_BREDR_VALID: u16 = 0x0001;

// ---- socket ABI -------------------------------------------------------------

/// `sockaddr_l2` width: family, PSM, address, channel identifier, address type.
pub const SOCKADDR_L2_LEN: usize = 14;
pub const SOCKADDR_L2_FAMILY_OFF: usize = 0;
pub const SOCKADDR_L2_PSM_OFF: usize = 2;
pub const SOCKADDR_L2_BDADDR_OFF: usize = 4;
pub const SOCKADDR_L2_CID_OFF: usize = 10;
pub const SOCKADDR_L2_BDADDR_TYPE_OFF: usize = 12;

/// `SOL_L2CAP` option numbers.
pub const L2CAP_OPTIONS: u32 = 0x01;
pub const L2CAP_CONNINFO: u32 = 0x02;
pub const L2CAP_LM: u32 = 0x03;

/// `struct l2cap_options` width, with the padding the C layout implies before
/// the trailing 16-bit window size.
pub const L2CAP_OPTIONS_LEN: usize = 12;
pub const L2CAP_CONNINFO_LEN: usize = 6;
/// Width of the class-of-device field a connection-info reply carries.
pub const DEV_CLASS_LEN: usize = 3;

/// Link-mode bits of the legacy `L2CAP_LM` option.
pub const LM_MASTER: u32 = 0x0001;
pub const LM_AUTH: u32 = 0x0002;
pub const LM_ENCRYPT: u32 = 0x0004;
pub const LM_TRUSTED: u32 = 0x0008;
pub const LM_RELIABLE: u32 = 0x0010;
pub const LM_SECURE: u32 = 0x0020;
pub const LM_FIPS: u32 = 0x0040;

/// Channel kinds, which decide which option set and which security default
/// apply to a socket.
pub const CHAN_RAW: u8 = 1;
pub const CHAN_CONN_LESS: u8 = 2;
pub const CHAN_CONN_ORIENTED: u8 = 3;
pub const CHAN_FIXED: u8 = 4;

/// Smallest encryption key size a link may carry and still satisfy a level
/// below FIPS.
pub const MIN_ENC_KEY_SIZE: u8 = 7;
/// Key size the FIPS level requires.
pub const FIPS_ENC_KEY_SIZE: u8 = 16;

#[cfg(test)]
#[path = "tests/l2cap.rs"]
mod tests;
