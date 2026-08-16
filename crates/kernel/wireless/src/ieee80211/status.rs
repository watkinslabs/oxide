// Status codes an association exchange carries and reason codes a
// deauthenticate or disassociate carries. Both are 16-bit fields on the air
// and both reach userspace unchanged, so a wrong number here is a wrong
// number in `wpa_supplicant`'s log and in its retry decision.

/// A status code carried in an authentication or association response.
pub type StatusCode = u16;
/// A reason code carried in a deauthenticate or disassociate frame.
pub type ReasonCode = u16;

/// `WLAN_STATUS_*`.
pub mod status {

    pub const SUCCESS: u16 = 0;
    pub const UNSPECIFIED_FAILURE: u16 = 1;
    pub const CAPS_UNSUPPORTED: u16 = 10;
    pub const REASSOC_NO_ASSOC: u16 = 11;
    pub const ASSOC_DENIED_UNSPEC: u16 = 12;
    pub const NOT_SUPPORTED_AUTH_ALG: u16 = 13;
    pub const UNKNOWN_AUTH_TRANSACTION: u16 = 14;
    pub const CHALLENGE_FAIL: u16 = 15;
    pub const AUTH_TIMEOUT: u16 = 16;
    pub const AP_UNABLE_TO_HANDLE_NEW_STA: u16 = 17;
    pub const ASSOC_DENIED_RATES: u16 = 18;
    pub const ASSOC_DENIED_NOSHORTPREAMBLE: u16 = 19;
    pub const ASSOC_DENIED_NOPBCC: u16 = 20;
    pub const ASSOC_DENIED_NOAGILITY: u16 = 21;
    pub const ASSOC_DENIED_NOSPECTRUM: u16 = 22;
    pub const ASSOC_REJECTED_BAD_POWER: u16 = 23;
    pub const ASSOC_REJECTED_BAD_SUPP_CHAN: u16 = 24;
    pub const ASSOC_DENIED_NOSHORTTIME: u16 = 25;
    pub const ASSOC_DENIED_NODSSSOFDM: u16 = 26;
    pub const ASSOC_REJECTED_TEMPORARILY: u16 = 30;
    pub const ROBUST_MGMT_FRAME_POLICY_VIOLATION: u16 = 31;
    pub const INVALID_IE: u16 = 40;
    pub const INVALID_GROUP_CIPHER: u16 = 41;
    pub const INVALID_PAIRWISE_CIPHER: u16 = 42;
    pub const INVALID_AKMP: u16 = 43;
    pub const UNSUPP_RSN_VERSION: u16 = 44;
    pub const INVALID_RSN_IE_CAP: u16 = 45;
    pub const CIPHER_SUITE_REJECTED: u16 = 46;
    pub const UNSPECIFIED_QOS: u16 = 32;
    pub const ASSOC_DENIED_NOBANDWIDTH: u16 = 33;
    pub const ASSOC_DENIED_LOWACK: u16 = 34;
    pub const ASSOC_DENIED_UNSUPP_QOS: u16 = 35;
    pub const REQUEST_DECLINED: u16 = 37;
    pub const INVALID_QOS_PARAM: u16 = 38;
    pub const CHANGE_TSPEC: u16 = 39;
    pub const WAIT_TS_DELAY: u16 = 47;
    pub const NO_DIRECT_LINK: u16 = 48;
    pub const STA_NOT_PRESENT: u16 = 49;
    pub const STA_NOT_QSTA: u16 = 50;
    pub const ANTI_CLOG_REQUIRED: u16 = 76;
    pub const FCG_NOT_SUPP: u16 = 78;
    /// Alternate name for `FCG_NOT_SUPP`.
    pub const STA_NO_TBTT: u16 = FCG_NOT_SUPP;
    /// Alternate name for `CHANGE_TSPEC`.
    pub const REJECTED_WITH_SUGGESTED_CHANGES: u16 = CHANGE_TSPEC;
    /// Alternate name for `WAIT_TS_DELAY`.
    pub const REJECTED_FOR_DELAY_PERIOD: u16 = WAIT_TS_DELAY;
    pub const REJECT_WITH_SCHEDULE: u16 = 83;
    pub const PENDING_ADMITTING_FST_SESSION: u16 = 86;
    pub const PERFORMING_FST_NOW: u16 = 87;
    pub const PENDING_GAP_IN_BA_WINDOW: u16 = 88;
    pub const REJECT_U_PID_SETTING: u16 = 89;
    pub const REJECT_DSE_BAND: u16 = 96;
    pub const DENIED_WITH_SUGGESTED_BAND_AND_CHANNEL: u16 = 99;
    pub const DENIED_DUE_TO_SPECTRUM_MANAGEMENT: u16 = 103;
    pub const REJECTED_NDP_BLOCK_ACK_SUGGESTED: u16 = 109;
    pub const FILS_AUTHENTICATION_FAILURE: u16 = 112;
    pub const UNKNOWN_AUTHENTICATION_SERVER: u16 = 113;
    pub const SAE_HASH_TO_ELEMENT: u16 = 126;
    pub const SAE_PK: u16 = 127;
    pub const DENIED_TID_TO_LINK_MAPPING: u16 = 133;
    pub const PREF_TID_TO_LINK_MAPPING_SUGGESTED: u16 = 134;
    pub const IEEE8021X_AUTH_SUCCESS: u16 = 153;
}

/// `WLAN_REASON_*`.
pub mod reason {

    pub const UNSPECIFIED: u16 = 1;
    pub const PREV_AUTH_NOT_VALID: u16 = 2;
    pub const DEAUTH_LEAVING: u16 = 3;
    pub const DISASSOC_DUE_TO_INACTIVITY: u16 = 4;
    pub const DISASSOC_AP_BUSY: u16 = 5;
    pub const CLASS2_FRAME_FROM_NONAUTH_STA: u16 = 6;
    pub const CLASS3_FRAME_FROM_NONASSOC_STA: u16 = 7;
    pub const DISASSOC_STA_HAS_LEFT: u16 = 8;
    pub const STA_REQ_ASSOC_WITHOUT_AUTH: u16 = 9;
    pub const DISASSOC_BAD_POWER: u16 = 10;
    pub const DISASSOC_BAD_SUPP_CHAN: u16 = 11;
    pub const INVALID_IE: u16 = 13;
    pub const MIC_FAILURE: u16 = 14;
    pub const FOURWAY_HANDSHAKE_TIMEOUT: u16 = 15;
    pub const GROUP_KEY_HANDSHAKE_TIMEOUT: u16 = 16;
    pub const IE_DIFFERENT: u16 = 17;
    pub const INVALID_GROUP_CIPHER: u16 = 18;
    pub const INVALID_PAIRWISE_CIPHER: u16 = 19;
    pub const INVALID_AKMP: u16 = 20;
    pub const UNSUPP_RSN_VERSION: u16 = 21;
    pub const INVALID_RSN_IE_CAP: u16 = 22;
    pub const IEEE8021X_FAILED: u16 = 23;
    pub const CIPHER_SUITE_REJECTED: u16 = 24;
    pub const TDLS_TEARDOWN_UNREACHABLE: u16 = 25;
    pub const TDLS_TEARDOWN_UNSPECIFIED: u16 = 26;
    pub const DISASSOC_UNSPECIFIED_QOS: u16 = 32;
    pub const DISASSOC_QAP_NO_BANDWIDTH: u16 = 33;
    pub const DISASSOC_LOW_ACK: u16 = 34;
    pub const DISASSOC_QAP_EXCEED_TXOP: u16 = 35;
    pub const QSTA_LEAVE_QBSS: u16 = 36;
    pub const QSTA_NOT_USE: u16 = 37;
    pub const QSTA_REQUIRE_SETUP: u16 = 38;
    pub const QSTA_TIMEOUT: u16 = 39;
    pub const QSTA_CIPHER_NOT_SUPP: u16 = 45;
    pub const MESH_PEER_CANCELED: u16 = 52;
    pub const MESH_MAX_PEERS: u16 = 53;
    pub const MESH_CONFIG: u16 = 54;
    pub const MESH_CLOSE: u16 = 55;
    pub const MESH_MAX_RETRIES: u16 = 56;
    pub const MESH_CONFIRM_TIMEOUT: u16 = 57;
    pub const MESH_INVALID_GTK: u16 = 58;
    pub const MESH_INCONSISTENT_PARAM: u16 = 59;
    pub const MESH_INVALID_SECURITY: u16 = 60;
    pub const MESH_PATH_ERROR: u16 = 61;
    pub const MESH_PATH_NOFORWARD: u16 = 62;
    pub const MESH_PATH_DEST_UNREACHABLE: u16 = 63;
    pub const MAC_EXISTS_IN_MBSS: u16 = 64;
    pub const MESH_CHAN_REGULATORY: u16 = 65;
    pub const MESH_CHAN: u16 = 66;
}

/// Whether a status code reports success. # C: O(1)
pub fn is_success(code: StatusCode) -> bool { code == status::SUCCESS }
