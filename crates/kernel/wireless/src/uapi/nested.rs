// Nested attribute spaces. Each module is one `nla_nest` namespace; numbers
// restart at 1 inside every nest, so they only mean anything relative to the
// attribute that opened the nest.

/// `NL80211_BSS_*` — one cached BSS inside `NL80211_ATTR_BSS`.
pub mod bss {
    pub const BSSID: u16 = 1;
    pub const FREQUENCY: u16 = 2;
    pub const TSF: u16 = 3;
    pub const BEACON_INTERVAL: u16 = 4;
    pub const CAPABILITY: u16 = 5;
    pub const INFORMATION_ELEMENTS: u16 = 6;
    pub const SIGNAL_MBM: u16 = 7;
    pub const SIGNAL_UNSPEC: u16 = 8;
    pub const STATUS: u16 = 9;
    pub const SEEN_MS_AGO: u16 = 10;
    pub const BEACON_IES: u16 = 11;
    pub const CHAN_WIDTH: u16 = 12;
    pub const BEACON_TSF: u16 = 13;
    pub const PRESP_DATA: u16 = 14;
    pub const LAST_SEEN_BOOTTIME: u16 = 15;
    pub const PAD: u16 = 16;
    pub const PARENT_TSF: u16 = 17;
    pub const PARENT_BSSID: u16 = 18;
    pub const CHAIN_SIGNAL: u16 = 19;
    pub const FREQUENCY_OFFSET: u16 = 20;
    pub const MLO_LINK_ID: u16 = 21;
    pub const MLD_ADDR: u16 = 22;
    pub const USE_FOR: u16 = 23;
    pub const CANNOT_USE_REASONS: u16 = 24;
    pub const MAX: u16 = CANNOT_USE_REASONS;
}

/// `NL80211_BSS_STATUS_*` — how the local interface stands to a cached BSS.
pub mod bss_status {
    pub const AUTHENTICATED: u32 = 0;
    pub const ASSOCIATED: u32 = 1;
    pub const IBSS_JOINED: u32 = 2;
}

/// `NL80211_STA_INFO_*` — the per-station report `iw dev link` reads.
pub mod sta_info {
    pub const INACTIVE_TIME: u16 = 1;
    pub const RX_BYTES: u16 = 2;
    pub const TX_BYTES: u16 = 3;
    pub const LLID: u16 = 4;
    pub const PLID: u16 = 5;
    pub const PLINK_STATE: u16 = 6;
    pub const SIGNAL: u16 = 7;
    pub const TX_BITRATE: u16 = 8;
    pub const RX_PACKETS: u16 = 9;
    pub const TX_PACKETS: u16 = 10;
    pub const TX_RETRIES: u16 = 11;
    pub const TX_FAILED: u16 = 12;
    pub const SIGNAL_AVG: u16 = 13;
    pub const RX_BITRATE: u16 = 14;
    pub const BSS_PARAM: u16 = 15;
    pub const CONNECTED_TIME: u16 = 16;
    pub const STA_FLAGS: u16 = 17;
    pub const BEACON_LOSS: u16 = 18;
    pub const T_OFFSET: u16 = 19;
    pub const LOCAL_PM: u16 = 20;
    pub const PEER_PM: u16 = 21;
    pub const NONPEER_PM: u16 = 22;
    pub const RX_BYTES64: u16 = 23;
    pub const TX_BYTES64: u16 = 24;
    pub const CHAIN_SIGNAL: u16 = 25;
    pub const CHAIN_SIGNAL_AVG: u16 = 26;
    pub const EXPECTED_THROUGHPUT: u16 = 27;
    pub const RX_DROP_MISC: u16 = 28;
    pub const BEACON_RX: u16 = 29;
    pub const BEACON_SIGNAL_AVG: u16 = 30;
    pub const TID_STATS: u16 = 31;
    pub const RX_DURATION: u16 = 32;
    pub const PAD: u16 = 33;
    pub const ACK_SIGNAL: u16 = 34;
    pub const ACK_SIGNAL_AVG: u16 = 35;
    pub const RX_MPDUS: u16 = 36;
    pub const FCS_ERROR_COUNT: u16 = 37;
    pub const CONNECTED_TO_GATE: u16 = 38;
    pub const TX_DURATION: u16 = 39;
    pub const AIRTIME_WEIGHT: u16 = 40;
    pub const AIRTIME_LINK_METRIC: u16 = 41;
    pub const ASSOC_AT_BOOTTIME: u16 = 42;
    pub const CONNECTED_TO_AS: u16 = 43;
    pub const MAX: u16 = CONNECTED_TO_AS;
}

/// `NL80211_RATE_INFO_*` — one direction's negotiated rate, nested inside a
/// station report.
pub mod rate_info {
    pub const BITRATE: u16 = 1;
    pub const MCS: u16 = 2;
    pub const WIDTH_40: u16 = 3;
    pub const SHORT_GI: u16 = 4;
    pub const BITRATE32: u16 = 5;
    pub const VHT_MCS: u16 = 6;
    pub const VHT_NSS: u16 = 7;
    pub const WIDTH_80: u16 = 8;
    pub const WIDTH_80P80: u16 = 9;
    pub const WIDTH_160: u16 = 10;
    pub const WIDTH_10: u16 = 11;
    pub const WIDTH_5: u16 = 12;
    pub const HE_MCS: u16 = 13;
    pub const HE_NSS: u16 = 14;
    pub const HE_GI: u16 = 15;
    pub const HE_DCM: u16 = 16;
    pub const HE_RU_ALLOC: u16 = 17;
    pub const WIDTH_320: u16 = 18;
    pub const EHT_MCS: u16 = 19;
    pub const EHT_NSS: u16 = 20;
    pub const EHT_GI: u16 = 21;
    pub const EHT_RU_ALLOC: u16 = 22;
    pub const MAX: u16 = EHT_RU_ALLOC;
}

/// `NL80211_STA_FLAG_*` — bit positions inside `nl80211_sta_flag_update`.
pub mod sta_flag {
    pub const AUTHORIZED: u32 = 1;
    pub const SHORT_PREAMBLE: u32 = 2;
    pub const WME: u32 = 3;
    pub const MFP: u32 = 4;
    pub const AUTHENTICATED: u32 = 5;
    pub const TDLS_PEER: u32 = 6;
    pub const ASSOCIATED: u32 = 7;
    pub const SPP_AMSDU: u32 = 8;
    pub const MAX: u32 = SPP_AMSDU;
}

/// `NL80211_BAND_ATTR_*` — one band inside `NL80211_ATTR_WIPHY_BANDS`.
pub mod band_attr {
    pub const FREQS: u16 = 1;
    pub const RATES: u16 = 2;
    pub const HT_MCS_SET: u16 = 3;
    pub const HT_CAPA: u16 = 4;
    pub const HT_AMPDU_FACTOR: u16 = 5;
    pub const HT_AMPDU_DENSITY: u16 = 6;
    pub const VHT_MCS_SET: u16 = 7;
    pub const VHT_CAPA: u16 = 8;
    pub const IFTYPE_DATA: u16 = 9;
    pub const EDMG_CHANNELS: u16 = 10;
    pub const EDMG_BW_CONFIG: u16 = 11;
    pub const S1G_MCS_NSS_SET: u16 = 12;
    pub const S1G_CAPA: u16 = 13;
    pub const MAX: u16 = S1G_CAPA;
}

/// `NL80211_FREQUENCY_ATTR_*` — one channel inside a band's frequency list.
pub mod freq_attr {
    pub const FREQ: u16 = 1;
    pub const DISABLED: u16 = 2;
    pub const NO_IR: u16 = 3;
    pub const RADAR: u16 = 5;
    pub const MAX_TX_POWER: u16 = 6;
    pub const DFS_STATE: u16 = 7;
    pub const DFS_TIME: u16 = 8;
    pub const NO_HT40_MINUS: u16 = 9;
    pub const NO_HT40_PLUS: u16 = 10;
    pub const NO_80MHZ: u16 = 11;
    pub const NO_160MHZ: u16 = 12;
    pub const DFS_CAC_TIME: u16 = 13;
    pub const INDOOR_ONLY: u16 = 14;
    pub const IR_CONCURRENT: u16 = 15;
    pub const NO_20MHZ: u16 = 16;
    pub const NO_10MHZ: u16 = 17;
    pub const WMM: u16 = 18;
    pub const NO_HE: u16 = 19;
    pub const OFFSET: u16 = 20;
    pub const NO_320MHZ: u16 = 26;
    pub const NO_EHT: u16 = 27;
    pub const PSD: u16 = 28;
    pub const MAX: u16 = 41;
}

/// `NL80211_BITRATE_ATTR_*` — one legacy rate inside a band's rate list.
pub mod bitrate_attr {
    pub const RATE: u16 = 1;
    pub const SHORTPREAMBLE_2GHZ: u16 = 2;
    pub const MAX: u16 = SHORTPREAMBLE_2GHZ;
}

/// `NL80211_KEY_*` — one key inside `NL80211_ATTR_KEY` / `NL80211_ATTR_KEYS`.
pub mod key {
    pub const DATA: u16 = 1;
    pub const IDX: u16 = 2;
    pub const CIPHER: u16 = 3;
    pub const SEQ: u16 = 4;
    pub const DEFAULT: u16 = 5;
    pub const DEFAULT_MGMT: u16 = 6;
    pub const TYPE: u16 = 7;
    pub const DEFAULT_TYPES: u16 = 8;
    pub const MODE: u16 = 9;
    pub const DEFAULT_BEACON: u16 = 10;
    pub const LTF_SEED: u16 = 11;
    pub const MAX: u16 = LTF_SEED;
}

/// `NL80211_SURVEY_INFO_*` — one channel's occupancy report.
pub mod survey_info {
    pub const FREQUENCY: u16 = 1;
    pub const NOISE: u16 = 2;
    pub const IN_USE: u16 = 3;
    pub const TIME: u16 = 4;
    pub const TIME_BUSY: u16 = 5;
    pub const TIME_EXT_BUSY: u16 = 6;
    pub const TIME_RX: u16 = 7;
    pub const TIME_TX: u16 = 8;
    pub const TIME_SCAN: u16 = 9;
    pub const PAD: u16 = 10;
    pub const TIME_BSS_RX: u16 = 11;
    pub const FREQUENCY_OFFSET: u16 = 12;
    pub const MAX: u16 = FREQUENCY_OFFSET;
}

/// `NL80211_ATTR_REG_RULE_*` — one regulatory rule inside `REG_RULES`.
pub mod reg_rule_attr {
    pub const FLAGS: u16 = 1;
    pub const FREQ_RANGE_START: u16 = 2;
    pub const FREQ_RANGE_END: u16 = 3;
    pub const FREQ_RANGE_MAX_BW: u16 = 4;
    pub const POWER_RULE_MAX_ANT_GAIN: u16 = 5;
    pub const POWER_RULE_MAX_EIRP: u16 = 6;
    pub const DFS_CAC_TIME: u16 = 7;
    pub const POWER_RULE_PSD: u16 = 8;
    pub const MAX: u16 = POWER_RULE_PSD;
}

/// `NL80211_MNTR_FLAG_*` — monitor-interface capture selection.
pub mod mntr_flag {
    pub const FCSFAIL: u16 = 1;
    pub const PLCPFAIL: u16 = 2;
    pub const CONTROL: u16 = 3;
    pub const OTHER_BSS: u16 = 4;
    pub const COOK_FRAMES: u16 = 5;
    pub const ACTIVE: u16 = 6;
    pub const SKIP_TX: u16 = 7;
    pub const MAX: u16 = SKIP_TX;
}

/// `NL80211_SCHED_SCAN_MATCH_ATTR_*` — one match set of a scheduled scan.
pub mod sched_scan_match {
    pub const SSID: u16 = 1;
    pub const RSSI: u16 = 2;
    pub const RELATIVE_RSSI: u16 = 3;
    pub const RSSI_ADJUST: u16 = 4;
    pub const BSSID: u16 = 5;
    pub const PER_BAND_RSSI: u16 = 6;
    pub const MAX: u16 = PER_BAND_RSSI;
}

/// `NL80211_ATTR_CQM_*` — connection-quality monitoring configuration and
/// the events it raises.
pub mod cqm {
    pub const RSSI_THOLD: u16 = 1;
    pub const RSSI_HYST: u16 = 2;
    pub const RSSI_THRESHOLD_EVENT: u16 = 3;
    pub const PKT_LOSS_EVENT: u16 = 4;
    pub const TXE_RATE: u16 = 5;
    pub const TXE_PKTS: u16 = 6;
    pub const TXE_INTVL: u16 = 7;
    pub const BEACON_LOSS_EVENT: u16 = 8;
    pub const RSSI_LEVEL: u16 = 9;
    pub const MAX: u16 = RSSI_LEVEL;

    /// `NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW`.
    pub const RSSI_EVENT_LOW: u32 = 0;
    /// `NL80211_CQM_RSSI_THRESHOLD_EVENT_HIGH`.
    pub const RSSI_EVENT_HIGH: u32 = 1;
    /// `NL80211_CQM_RSSI_BEACON_LOSS_EVENT`.
    pub const RSSI_EVENT_BEACON_LOSS: u32 = 2;
}

/// `NL80211_TXRATE_*` — per-band rate mask inside `NL80211_ATTR_TX_RATES`.
pub mod txrate {
    pub const LEGACY: u16 = 1;
    pub const HT: u16 = 2;
    pub const VHT: u16 = 3;
    pub const GI: u16 = 4;
    pub const HE: u16 = 5;
    pub const HE_GI: u16 = 6;
    pub const HE_LTF: u16 = 7;
    pub const MAX: u16 = HE_LTF;
}
