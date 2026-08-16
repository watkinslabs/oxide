// Value enumerations carried inside nl80211 attributes. These are the
// vocabularies userspace and the kernel agree on for interface type, channel
// width, authentication, regulatory provenance and the rest.

/// `NL80211_IFTYPE_*` — what a virtual interface is for.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u32)]
pub enum IfType {
    #[default]
    Unspecified = 0,
    Adhoc = 1,
    Station = 2,
    Ap = 3,
    ApVlan = 4,
    Wds = 5,
    Monitor = 6,
    MeshPoint = 7,
    P2pClient = 8,
    P2pGo = 9,
    P2pDevice = 10,
    Ocb = 11,
    Nan = 12,
    NanData = 13,
    Pd = 14,
}

impl IfType {
    /// Decode a wire value. An unknown number is not silently mapped onto a
    /// type this kernel would then act on. # C: O(1)
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => Self::Unspecified, 1 => Self::Adhoc, 2 => Self::Station, 3 => Self::Ap,
            4 => Self::ApVlan, 5 => Self::Wds, 6 => Self::Monitor, 7 => Self::MeshPoint,
            8 => Self::P2pClient, 9 => Self::P2pGo, 10 => Self::P2pDevice, 11 => Self::Ocb,
            12 => Self::Nan, 13 => Self::NanData, 14 => Self::Pd,
            _ => return None,
        })
    }
    /// Wire value. # C: O(1)
    pub fn as_u32(self) -> u32 { self as u32 }
    /// Whether this type carries a netdev, as opposed to living only as a
    /// wireless device (`P2P_DEVICE` and `NAN` have no network interface).
    /// # C: O(1)
    pub fn has_netdev(self) -> bool {
        !matches!(self, Self::P2pDevice | Self::Nan | Self::Pd)
    }
    /// Whether this type runs the station-side management state machine.
    /// # C: O(1)
    pub fn is_client(self) -> bool { matches!(self, Self::Station | Self::P2pClient) }
    /// Whether this type beacons. # C: O(1)
    pub fn is_ap(self) -> bool { matches!(self, Self::Ap | Self::P2pGo) }
}

/// `NL80211_CHAN_WIDTH_*`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u32)]
pub enum ChanWidth {
    Width20NoHt = 0,
    #[default]
    Width20 = 1,
    Width40 = 2,
    Width80 = 3,
    Width80P80 = 4,
    Width160 = 5,
    Width5 = 6,
    Width10 = 7,
    Width1 = 8,
    Width2 = 9,
    Width4 = 10,
    Width8 = 11,
    Width16 = 12,
    Width320 = 13,
}

impl ChanWidth {
    /// Decode a wire value. # C: O(1)
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => Self::Width20NoHt, 1 => Self::Width20, 2 => Self::Width40, 3 => Self::Width80,
            4 => Self::Width80P80, 5 => Self::Width160, 6 => Self::Width5, 7 => Self::Width10,
            8 => Self::Width1, 9 => Self::Width2, 10 => Self::Width4, 11 => Self::Width8,
            12 => Self::Width16, 13 => Self::Width320,
            _ => return None,
        })
    }
    /// Wire value. # C: O(1)
    pub fn as_u32(self) -> u32 { self as u32 }
    /// Occupied bandwidth in kHz. `80+80` occupies two 80 MHz segments and is
    /// reported as the total it really uses. # C: O(1)
    pub fn khz(self) -> u32 {
        match self {
            Self::Width1 => 1_000, Self::Width2 => 2_000, Self::Width4 => 4_000,
            Self::Width5 => 5_000, Self::Width8 => 8_000, Self::Width10 => 10_000,
            Self::Width16 => 16_000,
            Self::Width20NoHt | Self::Width20 => 20_000,
            Self::Width40 => 40_000, Self::Width80 => 80_000,
            Self::Width80P80 | Self::Width160 => 160_000,
            Self::Width320 => 320_000,
        }
    }
}

/// `NL80211_AUTHTYPE_*`.
pub mod auth_type {
    pub const OPEN_SYSTEM: u32 = 0;
    pub const SHARED_KEY: u32 = 1;
    pub const FT: u32 = 2;
    pub const NETWORK_EAP: u32 = 3;
    pub const SAE: u32 = 4;
    pub const FILS_SK: u32 = 5;
    pub const FILS_SK_PFS: u32 = 6;
    pub const FILS_PK: u32 = 7;
    pub const EPPKE: u32 = 8;
    pub const IEEE8021X: u32 = 9;
    pub const MAX: u32 = IEEE8021X;
    /// `NL80211_AUTHTYPE_AUTOMATIC` — let the SME pick.
    pub const AUTOMATIC: u32 = MAX + 1;
}

/// `NL80211_MFP_*` — management frame protection demand.
pub mod mfp {
    pub const NO: u32 = 0;
    pub const REQUIRED: u32 = 1;
    pub const OPTIONAL: u32 = 2;
    pub const MAX: u32 = OPTIONAL;
}

/// `NL80211_WPA_VERSION_*` bits.
pub mod wpa_version {
    pub const V1: u32 = 1 << 0;
    pub const V2: u32 = 1 << 1;
    pub const V3: u32 = 1 << 2;
    pub const ALL: u32 = V1 | V2 | V3;
}

/// `NL80211_KEYTYPE_*`.
pub mod key_type {
    pub const GROUP: u32 = 0;
    pub const PAIRWISE: u32 = 1;
    pub const PEERKEY: u32 = 2;
    pub const MAX: u32 = PEERKEY;
}

/// `NL80211_BAND_*`.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum Band {
    #[default]
    Band2Ghz = 0,
    Band5Ghz = 1,
    Band60Ghz = 2,
    Band6Ghz = 3,
    BandS1Ghz = 4,
    BandLc = 5,
}

impl Band {
    /// Decode a wire value. # C: O(1)
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => Self::Band2Ghz, 1 => Self::Band5Ghz, 2 => Self::Band60Ghz,
            3 => Self::Band6Ghz, 4 => Self::BandS1Ghz, 5 => Self::BandLc,
            _ => return None,
        })
    }
    /// Wire value. # C: O(1)
    pub fn as_u32(self) -> u32 { self as u32 }
}

/// `NL80211_REGDOM_SET_BY_*` — who asked for the current regulatory domain.
/// The order is the priority order: a later initiator does not lose to an
/// earlier one, and a country IE never overrides a user request.
pub mod reg_initiator {
    pub const CORE: u32 = 0;
    pub const USER: u32 = 1;
    pub const DRIVER: u32 = 2;
    pub const COUNTRY_IE: u32 = 3;
    pub const MAX: u32 = COUNTRY_IE;
}

/// `NL80211_REGDOM_TYPE_*`.
pub mod reg_type {
    pub const COUNTRY: u32 = 0;
    pub const WORLD: u32 = 1;
    pub const CUSTOM_WORLD: u32 = 2;
    pub const INTERSECTION: u32 = 3;
    pub const MAX: u32 = INTERSECTION;
}

/// `NL80211_DFS_*` regions.
pub mod dfs_region {
    pub const UNSET: u8 = 0;
    pub const FCC: u8 = 1;
    pub const ETSI: u8 = 2;
    pub const JP: u8 = 3;
    pub const MAX: u8 = JP;
}

/// `NL80211_DFS_*` per-channel radar clearance state.
pub mod dfs_state {
    pub const USABLE: u32 = 0;
    pub const UNAVAILABLE: u32 = 1;
    pub const AVAILABLE: u32 = 2;
    pub const MAX: u32 = AVAILABLE;
}

/// `NL80211_RRF_*` regulatory rule flags.
pub mod reg_rule_flags {
    pub const NO_OFDM: u32 = 1 << 0;
    pub const NO_CCK: u32 = 1 << 1;
    pub const NO_INDOOR: u32 = 1 << 2;
    pub const NO_OUTDOOR: u32 = 1 << 3;
    pub const DFS: u32 = 1 << 4;
    pub const PTP_ONLY: u32 = 1 << 5;
    pub const PTMP_ONLY: u32 = 1 << 6;
    pub const NO_IR: u32 = 1 << 7;
    pub const AUTO_BW: u32 = 1 << 11;
    pub const IR_CONCURRENT: u32 = 1 << 12;
    pub const NO_HT40MINUS: u32 = 1 << 13;
    pub const NO_HT40PLUS: u32 = 1 << 14;
    pub const NO_80MHZ: u32 = 1 << 15;
    pub const NO_160MHZ: u32 = 1 << 16;
    pub const NO_HE: u32 = 1 << 17;
    pub const NO_320MHZ: u32 = 1 << 18;
    pub const NO_EHT: u32 = 1 << 19;
    pub const PSD: u32 = 1 << 20;
    pub const DFS_CONCURRENT: u32 = 1 << 21;
    /// Both HT40 directions barred at once.
    pub const NO_HT40: u32 = NO_HT40MINUS | NO_HT40PLUS;
}

/// `NL80211_CHAN_*` legacy secondary-channel selection, still sent by older
/// userspace instead of an explicit width.
pub mod channel_type {
    pub const NO_HT: u32 = 0;
    pub const HT20: u32 = 1;
    pub const HT40MINUS: u32 = 2;
    pub const HT40PLUS: u32 = 3;
    pub const MAX: u32 = HT40PLUS;
}

/// `NL80211_PS_*` power-save state.
pub mod ps_state {
    pub const DISABLED: u32 = 0;
    pub const ENABLED: u32 = 1;
    pub const MAX: u32 = ENABLED;
}

/// `NL80211_TIMEOUT_*` — why a connect attempt gave up.
pub mod timeout_reason {
    pub const UNSPECIFIED: u32 = 0;
    pub const SCAN: u32 = 1;
    pub const AUTH: u32 = 2;
    pub const ASSOC: u32 = 3;
    pub const MAX: u32 = ASSOC;
}

/// `NL80211_SCAN_FLAG_*`.
pub mod scan_flags {
    pub const LOW_PRIORITY: u32 = 1 << 0;
    pub const FLUSH: u32 = 1 << 1;
    pub const AP: u32 = 1 << 2;
    pub const RANDOM_ADDR: u32 = 1 << 3;
    pub const FILS_MAX_CHANNEL_TIME: u32 = 1 << 4;
    pub const ACCEPT_BCAST_PROBE_RESP: u32 = 1 << 5;
    pub const OCE_PROBE_REQ_HIGH_TX_RATE: u32 = 1 << 6;
    pub const OCE_PROBE_REQ_DEFERRAL_SUPPRESSION: u32 = 1 << 7;
    pub const LOW_SPAN: u32 = 1 << 8;
    pub const LOW_POWER: u32 = 1 << 9;
    pub const HIGH_ACCURACY: u32 = 1 << 10;
    pub const RANDOM_SN: u32 = 1 << 11;
    pub const MIN_PREQ_CONTENT: u32 = 1 << 12;
    pub const FREQ_KHZ: u32 = 1 << 13;
    pub const COLOCATED_6GHZ: u32 = 1 << 14;
    /// Every flag this build understands; anything else is `EOPNOTSUPP`.
    pub const KNOWN: u32 = (1 << 15) - 1;
}

/// `NL80211_HIDDEN_SSID_*` — how an AP hides its SSID in beacons.
pub mod hidden_ssid {
    pub const NOT_IN_USE: u32 = 0;
    pub const ZERO_LEN: u32 = 1;
    pub const ZERO_CONTENTS: u32 = 2;
    pub const MAX: u32 = ZERO_CONTENTS;
}

/// `NL80211_PROTOCOL_FEATURE_*`.
pub mod protocol_features {
    pub const SPLIT_WIPHY_DUMP: u32 = 1 << 0;
}

/// `NL80211_FEATURE_*` — the first, exhausted feature word.
pub mod feature_flags {
    pub const SK_TX_STATUS: u32 = 1 << 0;
    pub const HT_IBSS: u32 = 1 << 1;
    pub const INACTIVITY_TIMER: u32 = 1 << 2;
    pub const CELL_BASE_REG_HINTS: u32 = 1 << 3;
    pub const SAE: u32 = 1 << 5;
    pub const LOW_PRIORITY_SCAN: u32 = 1 << 6;
    pub const SCAN_FLUSH: u32 = 1 << 7;
    pub const AP_SCAN: u32 = 1 << 8;
    pub const VIF_TXPOWER: u32 = 1 << 9;
    pub const ADVERTISE_CHAN_LIMITS: u32 = 1 << 14;
    pub const FULL_AP_CLIENT_STATE: u32 = 1 << 15;
    pub const ACTIVE_MONITOR: u32 = 1 << 17;
    pub const DYNAMIC_SMPS: u32 = 1 << 25;
    pub const STATIC_SMPS: u32 = 1 << 24;
    pub const MAC_ON_CREATE: u32 = 1 << 27;
    pub const SCAN_RANDOM_MAC_ADDR: u32 = 1 << 29;
}

/// `NL80211_EXT_FEATURE_*` bit positions inside `NL80211_ATTR_EXT_FEATURES`.
pub mod ext_feature {
    pub const RRM: u32 = 1;
    pub const SCAN_START_TIME: u32 = 3;
    pub const SET_SCAN_DWELL: u32 = 5;
    pub const CQM_RSSI_LIST: u32 = 13;
    pub const FOUR_WAY_HANDSHAKE_STA_PSK: u32 = 15;
    pub const FOUR_WAY_HANDSHAKE_STA_1X: u32 = 16;
    pub const MFP_OPTIONAL: u32 = 21;
    pub const CONTROL_PORT_OVER_NL80211: u32 = 26;
    pub const ACK_SIGNAL_SUPPORT: u32 = 27;
    pub const TXQS: u32 = 28;
    pub const CAN_REPLACE_PTK0: u32 = 31;
    pub const EXT_KEY_ID: u32 = 37;
    pub const BEACON_PROTECTION: u32 = 42;
    pub const CONTROL_PORT_NO_PREAUTH: u32 = 43;
    pub const BEACON_PROTECTION_CLIENT: u32 = 47;
    pub const SCAN_FREQ_KHZ: u32 = 48;
    pub const CONTROL_PORT_OVER_NL80211_TX_STATUS: u32 = 49;
}

/// `NL80211_AC_*` — the four EDCA access categories, in nl80211's order.
pub mod ac {
    pub const VO: u32 = 0;
    pub const VI: u32 = 1;
    pub const BE: u32 = 2;
    pub const BK: u32 = 3;
    pub const MAX: u32 = BK;
}
