//! Bit flags carried in expression attributes.

// --- lookup ---

pub const NFT_LOOKUP_F_INV: u32 = 1 << 0;

// --- limit ---

pub const NFT_LIMIT_F_INV: u32 = 1 << 0;

// --- quota. The depleted bit is reported by the kernel, never accepted. ---

pub const NFT_QUOTA_F_INV:      u32 = 1 << 0;
pub const NFT_QUOTA_F_DEPLETED: u32 = 1 << 1;

// --- connlimit ---

pub const NFT_CONNLIMIT_F_INV: u32 = 1 << 0;

// --- queue ---

pub const NFT_QUEUE_FLAG_BYPASS:     u32 = 0x01;
pub const NFT_QUEUE_FLAG_CPU_FANOUT: u32 = 0x02;
pub const NFT_QUEUE_FLAG_MASK:       u32 = 0x03;

// --- exthdr ---

pub const NFT_EXTHDR_F_PRESENT: u32 = 1 << 0;

// --- osf ---

pub const NFT_OSF_F_VERSION: u32 = 1 << 0;

/// Fingerprint TTL policies: exact match, less-than, or ignore the TTL.
pub const NF_OSF_TTL_TRUE:   u8 = 0;
pub const NF_OSF_TTL_LESS:   u8 = 1;
pub const NF_OSF_TTL_NOCHECK: u8 = 2;

// --- fib ---

pub const NFTA_FIB_F_SADDR:   u32 = 1 << 0;
pub const NFTA_FIB_F_DADDR:   u32 = 1 << 1;
pub const NFTA_FIB_F_MARK:    u32 = 1 << 2;
pub const NFTA_FIB_F_IIF:     u32 = 1 << 3;
pub const NFTA_FIB_F_OIF:     u32 = 1 << 4;
pub const NFTA_FIB_F_PRESENT: u32 = 1 << 5;
pub const NFTA_FIB_F_ALL: u32 = NFTA_FIB_F_SADDR | NFTA_FIB_F_DADDR | NFTA_FIB_F_MARK
    | NFTA_FIB_F_IIF | NFTA_FIB_F_OIF | NFTA_FIB_F_PRESENT;

// --- payload checksum ---

pub const NFT_PAYLOAD_L4CSUM_PSEUDOHDR: u32 = 1 << 0;

// --- log ---

pub const NF_LOG_TCPSEQ:  u32 = 0x01;
pub const NF_LOG_TCPOPT:  u32 = 0x02;
pub const NF_LOG_IPOPT:   u32 = 0x04;
pub const NF_LOG_UID:     u32 = 0x08;
pub const NF_LOG_NFLOG:   u32 = 0x10;
pub const NF_LOG_MACDECODE: u32 = 0x20;
pub const NF_LOG_MASK:    u32 = 0x2f;

/// Kernel log levels a `log` expression may request. The audit level is one
/// past the last printable level, so a request at or above it is refused.
pub const LOGLEVEL_EMERG:   u32 = 0;
pub const LOGLEVEL_WARNING: u32 = 4;
pub const LOGLEVEL_DEBUG:   u32 = 7;
pub const LOGLEVEL_AUDIT:   u32 = 8;

// --- synproxy ---

pub const NF_SYNPROXY_OPT_MSS:       u32 = 0x01;
pub const NF_SYNPROXY_OPT_WSCALE:    u32 = 0x02;
pub const NF_SYNPROXY_OPT_SACK_PERM: u32 = 0x04;
pub const NF_SYNPROXY_OPT_TIMESTAMP: u32 = 0x08;
pub const NF_SYNPROXY_OPT_ECN:       u32 = 0x10;
pub const NF_SYNPROXY_OPT_MASK: u32 = NF_SYNPROXY_OPT_MSS | NF_SYNPROXY_OPT_WSCALE
    | NF_SYNPROXY_OPT_SACK_PERM | NF_SYNPROXY_OPT_TIMESTAMP;
