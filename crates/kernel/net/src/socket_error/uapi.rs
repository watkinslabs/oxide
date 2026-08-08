//! Linux extended-error wire constants.

/// `sock_extended_err.ee_origin` values.
pub const SO_EE_ORIGIN_NONE: u8 = 0;
pub const SO_EE_ORIGIN_LOCAL: u8 = 1;
pub const SO_EE_ORIGIN_ICMP: u8 = 2;
pub const SO_EE_ORIGIN_ICMP6: u8 = 3;
pub const SO_EE_ORIGIN_TXSTATUS: u8 = 4;
pub const SO_EE_ORIGIN_ZEROCOPY: u8 = 5;
pub const SO_EE_ORIGIN_TXTIME: u8 = 6;
/// Alias the timestamping surface uses for `SO_EE_ORIGIN_TXSTATUS`.
pub const SO_EE_ORIGIN_TIMESTAMPING: u8 = SO_EE_ORIGIN_TXSTATUS;

/// `sock_extended_err.ee_code` values, per origin.
pub const SO_EE_CODE_ZEROCOPY_COPIED: u8 = 1;
pub const SO_EE_CODE_TXTIME_INVALID_PARAM: u8 = 1;
pub const SO_EE_CODE_TXTIME_MISSED: u8 = 2;

/// `sock_ee_data_rfc4884.flags` bit reporting an unusable extension offset.
pub const SO_EE_RFC4884_FLAG_INVALID: u8 = 1;

/// `scm_timestamping` selector carried in `ee_info` of a timestamping record.
pub const SCM_TSTAMP_SND: u32 = 0;
pub const SCM_TSTAMP_SCHED: u32 = 1;
pub const SCM_TSTAMP_ACK: u32 = 2;
pub const SCM_TSTAMP_COMPLETION: u32 = 3;

/// Wire size of `sock_extended_err`, ahead of the offender sockaddr.
pub const SOCK_EXTENDED_ERR_LEN: usize = 16;

/// Default receive-memory budget one socket's error queue may occupy.
pub const SOCK_ERRQUEUE_RMEM_DEFAULT: usize = 212_992;

/// Per-record accounting overhead charged against the receive-memory budget.
pub const SOCK_ERRQUEUE_RECORD_OVERHEAD: usize = 256;

/// Origins whose pending errno the socket publishes as `SO_ERROR`. # C: O(1)
pub const fn is_icmp_origin(origin: u8) -> bool {
    origin == SO_EE_ORIGIN_ICMP || origin == SO_EE_ORIGIN_ICMP6
}

/// Origins a `IP_RECVERR`/`IPV6_RECVERR` disable leaves queued. # C: O(1)
pub const fn survives_recverr_purge(origin: u8) -> bool {
    origin == SO_EE_ORIGIN_ZEROCOPY || origin == SO_EE_ORIGIN_TIMESTAMPING
}

/// Whether `ee_type`/`ee_code` come from a received ICMP header. # C: O(1)
pub const fn carries_icmp_header(origin: u8) -> bool { is_icmp_origin(origin) }
