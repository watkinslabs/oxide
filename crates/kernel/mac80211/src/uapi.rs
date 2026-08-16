// ABI numbers this layer is not free to choose: EtherTypes, the access
// categories and the traffic-identifier mapping onto them, and the on-air
// widths of every cipher's header and integrity field.
//
// Nothing here is a policy decision. A value that can be argued about lives
// in `limits` or `flags`; a value that is fixed by the wire lives here.

/// EtherType of the port-access protocol whose frames are the ONLY thing
/// allowed out of an interface before its controlled port is authorized.
pub const ETH_P_PAE: u16 = 0x888e;
/// EtherType of a preauthentication frame, carried the same way.
pub const ETH_P_PREAUTH: u16 = 0x88c7;
/// EtherType of the tunnelled-direct-link setup protocol.
pub const ETH_P_TDLS: u16 = 0x890d;
/// EtherType below which the two-byte field is an 802.3 length, not a type.
pub const ETH_P_802_3_MIN: u16 = 0x0600;
/// AppleTalk address-resolution — one of the two protocols that must use the
/// bridge-tunnel encapsulation instead of the RFC 1042 one.
pub const ETH_P_AARP: u16 = 0x80f3;
/// Internetwork packet exchange — the other one.
pub const ETH_P_IPX: u16 = 0x8137;

/// Width of an Ethernet header: two addresses and the type field.
pub const ETH_HDR_LEN: usize = 14;
/// Width of the SNAP header an 802.11 frame carries before an EtherType.
pub const SNAP_HDR_LEN: usize = 8;
/// Largest Ethernet payload a converted frame may carry.
pub const ETH_DATA_LEN: usize = 1500;

/// The four access categories, in the order the standard numbers them. A
/// frame's category picks its transmit queue and its contention parameters.
pub mod ac {
    /// Voice — highest priority.
    pub const VO: u8 = 0;
    pub const VI: u8 = 1;
    pub const BE: u8 = 2;
    /// Background — lowest priority.
    pub const BK: u8 = 3;
    /// Categories in total; a driver with hardware queues has this many.
    pub const COUNT: usize = 4;
}

/// Access category one traffic identifier maps to. The mapping is not
/// monotonic in the identifier: 1 and 2 are BACKGROUND and sit BELOW 0, which
/// is best effort, and a table that treated the identifier as a priority
/// would put background traffic ahead of ordinary traffic. # C: O(1)
pub const fn tid_to_ac(tid: u8) -> u8 {
    match tid & 0x07 {
        0 | 3 => ac::BE,
        1 | 2 => ac::BK,
        4 | 5 => ac::VI,
        _ => ac::VO,
    }
}

/// The traffic identifier a driver queue index stands for, for a frame that
/// carries no QoS control field. # C: O(1)
pub const fn ac_to_tid(ac: u8) -> u8 {
    match ac {
        self::ac::VO => 6,
        self::ac::VI => 4,
        self::ac::BK => 1,
        _ => 0,
    }
}

/// Cipher header and integrity-field widths. Each is fixed by the cipher's
/// own definition and is the difference between a frame that decrypts and one
/// that is silently truncated.
pub mod cipher_len {
    /// Counter-mode header: packet number, key id and the extended-id bit.
    pub const CCMP_HDR: usize = 8;
    /// Counter-mode integrity field.
    pub const CCMP_MIC: usize = 8;
    /// The 256-bit counter-mode variant doubles only the integrity field.
    pub const CCMP_256_MIC: usize = 16;
    /// Packet-number width every counter-mode cipher uses.
    pub const CCMP_PN: usize = 6;
    /// Galois-mode header, the same shape as the counter-mode one.
    pub const GCMP_HDR: usize = 8;
    pub const GCMP_MIC: usize = 16;
    pub const GCMP_PN: usize = 6;
    /// Temporal-key header: the two-part initialisation vector.
    pub const TKIP_IV: usize = 8;
    /// Temporal-key integrity check value, appended after the payload.
    pub const TKIP_ICV: usize = 4;
    /// The message-integrity code the temporal-key cipher adds to the MSDU.
    pub const MICHAEL_MIC: usize = 8;
    /// Wired-equivalent header and integrity field.
    pub const WEP_IV: usize = 4;
    pub const WEP_ICV: usize = 4;
    /// Management-frame integrity element body: key id, packet number, tag.
    pub const BIP_MMIE: usize = 18;
    pub const BIP_MMIE_256: usize = 26;
    /// Widest header any cipher prepends, for headroom reservation.
    pub const MAX_HDR: usize = CCMP_HDR;
    /// Widest trailer any cipher appends.
    pub const MAX_TAIL: usize = GCMP_MIC + TKIP_ICV;
}

/// Offsets into a temporal-key key blob. The blob carries three keys: the
/// encryption key and the two directional integrity keys, and swapping the
/// two integrity keys produces a link on which every frame fails its
/// integrity check in one direction only.
pub mod tkip_key {
    pub const ENCR_OFFSET: usize = 0;
    pub const ENCR_LEN: usize = 16;
    pub const TX_MIC_OFFSET: usize = 16;
    pub const RX_MIC_OFFSET: usize = 24;
    pub const MIC_LEN: usize = 8;
    /// Total blob width a temporal-key install carries.
    pub const TOTAL_LEN: usize = 32;
}

/// Element identifiers this layer builds or consults that the shared element
/// module does not already name.
pub mod elem_id {
    pub const SSID: u8 = 0;
    pub const SUPP_RATES: u8 = 1;
    pub const DS_PARAMS: u8 = 3;
    pub const TIM: u8 = 5;
    pub const COUNTRY: u8 = 7;
    pub const ERP_INFO: u8 = 42;
    pub const HT_CAPABILITY: u8 = 45;
    pub const RSN: u8 = 48;
    pub const EXT_SUPP_RATES: u8 = 50;
    pub const HT_OPERATION: u8 = 61;
    pub const VHT_CAPABILITY: u8 = 191;
    pub const VHT_OPERATION: u8 = 192;
    pub const VENDOR_SPECIFIC: u8 = 221;
}

/// A supported-rate element's byte carries the rate in half-megabit units
/// with this bit set when the rate is a basic one every station must accept.
pub const RATE_BASIC: u8 = 0x80;
/// Rate value mask once the basic bit is removed.
pub const RATE_VALUE_MASK: u8 = 0x7f;

/// Convert a rate in 100 kbit/s units to the half-megabit unit an element
/// carries. # C: O(1)
pub const fn rate_to_elem(bitrate_100kbps: u32) -> u8 { (bitrate_100kbps / 5) as u8 }
/// Convert an element rate byte back to 100 kbit/s units. # C: O(1)
pub const fn elem_to_rate(byte: u8) -> u32 { (byte & RATE_VALUE_MASK) as u32 * 5 }

/// Link type a managed-mode interface presents to the network stack. A
/// station interface is an Ethernet device to everything above it: the
/// conversion in `netdev` is what makes that true.
pub const ARPHRD_ETHER: u16 = 1;
/// Link type a monitor interface presents, carrying whole 802.11 frames.
pub const ARPHRD_IEEE80211_RADIOTAP: u16 = 803;
