// The IPv4 header option area's ABI: the option kinds, the timestamp flag
// nibble, and the widest area a header can carry. UAPI only — no policy, no
// dispatch, no target gate.

/// Widest IPv4 header option area: the header length field caps the header at
/// 60 bytes, of which 20 are fixed.
pub const MAX_IPOPTLEN: usize = 40;

/// IPv4 option kinds the option-area compiler recognizes.
pub const IPOPT_END: u8 = 0;
pub const IPOPT_NOOP: u8 = 1;
pub const IPOPT_SEC: u8 = 130;
pub const IPOPT_LSRR: u8 = 131;
pub const IPOPT_TIMESTAMP: u8 = 68;
pub const IPOPT_CIPSO: u8 = 134;
pub const IPOPT_RR: u8 = 7;
pub const IPOPT_SID: u8 = 136;
pub const IPOPT_SSRR: u8 = 137;
pub const IPOPT_RA: u8 = 148;

/// The option-kind bit that marks an option as belonging in every fragment.
pub const IPOPT_COPIED: u8 = 0x80;

/// `IPOPT_TS_*` — the timestamp option's flag nibble.
pub const IPOPT_TS_TSONLY: u8 = 0;
pub const IPOPT_TS_TSANDADDR: u8 = 1;
pub const IPOPT_TS_PRESPEC: u8 = 3;

