// Cipher and AKM suite selectors. A selector is an OUI in the top three
// bytes and a suite type in the low byte, sent big-endian on the air and
// carried host-endian in nl80211 attributes.

/// `00:0F:AC` — the IEEE 802.11 OUI every standard suite is under.
pub const OUI_IEEE80211: u32 = 0x000f_ac;
/// `00:14:72` — the OUI the SMS4 suite is under.
pub const OUI_WAPI: u32 = 0x0014_72;
/// `50:6F:9A` — the Wi-Fi Alliance OUI.
pub const OUI_WFA: u32 = 0x506f_9a;

/// Build a suite selector from an OUI and a suite type. # C: O(1)
pub const fn suite(oui: u32, ty: u8) -> u32 { (oui << 8) | ty as u32 }

/// The OUI half of a suite selector. # C: O(1)
pub const fn suite_oui(sel: u32) -> u32 { sel >> 8 }
/// The suite-type half of a suite selector. # C: O(1)
pub const fn suite_type(sel: u32) -> u8 { (sel & 0xff) as u8 }

/// `WLAN_CIPHER_SUITE_*`.
pub mod cipher {
    use super::{suite, OUI_IEEE80211, OUI_WAPI};

    /// Pairwise selector meaning "use whatever the group cipher is".
    pub const USE_GROUP: u32 = suite(OUI_IEEE80211, 0);
    pub const WEP40: u32 = suite(OUI_IEEE80211, 1);
    pub const TKIP: u32 = suite(OUI_IEEE80211, 2);
    pub const CCMP: u32 = suite(OUI_IEEE80211, 4);
    pub const WEP104: u32 = suite(OUI_IEEE80211, 5);
    pub const AES_CMAC: u32 = suite(OUI_IEEE80211, 6);
    pub const GCMP: u32 = suite(OUI_IEEE80211, 8);
    pub const GCMP_256: u32 = suite(OUI_IEEE80211, 9);
    pub const CCMP_256: u32 = suite(OUI_IEEE80211, 10);
    pub const BIP_GMAC_128: u32 = suite(OUI_IEEE80211, 11);
    pub const BIP_GMAC_256: u32 = suite(OUI_IEEE80211, 12);
    pub const BIP_CMAC_256: u32 = suite(OUI_IEEE80211, 13);
    pub const SMS4: u32 = suite(OUI_WAPI, 1);
}

/// `WLAN_AKM_SUITE_*`.
pub mod akm {
    use super::{suite, OUI_IEEE80211, OUI_WFA};

    pub const IEEE8021X: u32 = suite(OUI_IEEE80211, 1);
    pub const PSK: u32 = suite(OUI_IEEE80211, 2);
    pub const FT_8021X: u32 = suite(OUI_IEEE80211, 3);
    pub const FT_PSK: u32 = suite(OUI_IEEE80211, 4);
    pub const IEEE8021X_SHA256: u32 = suite(OUI_IEEE80211, 5);
    pub const PSK_SHA256: u32 = suite(OUI_IEEE80211, 6);
    pub const TDLS: u32 = suite(OUI_IEEE80211, 7);
    pub const SAE: u32 = suite(OUI_IEEE80211, 8);
    pub const FT_OVER_SAE: u32 = suite(OUI_IEEE80211, 9);
    pub const AP_PEER_KEY: u32 = suite(OUI_IEEE80211, 10);
    pub const IEEE8021X_SUITE_B: u32 = suite(OUI_IEEE80211, 11);
    pub const IEEE8021X_SUITE_B_192: u32 = suite(OUI_IEEE80211, 12);
    pub const FT_8021X_SHA384: u32 = suite(OUI_IEEE80211, 13);
    pub const FILS_SHA256: u32 = suite(OUI_IEEE80211, 14);
    pub const FILS_SHA384: u32 = suite(OUI_IEEE80211, 15);
    pub const FT_FILS_SHA256: u32 = suite(OUI_IEEE80211, 16);
    pub const FT_FILS_SHA384: u32 = suite(OUI_IEEE80211, 17);
    pub const OWE: u32 = suite(OUI_IEEE80211, 18);
    pub const FT_PSK_SHA384: u32 = suite(OUI_IEEE80211, 19);
    pub const PSK_SHA384: u32 = suite(OUI_IEEE80211, 20);
    pub const WFA_DPP: u32 = suite(OUI_WFA, 2);
}

/// Widest key any suite here takes.
pub const MAX_KEY_LEN: usize = 32;
/// Widest replay/packet-number sequence any suite here reports.
pub const MAX_PN_LEN: usize = 16;

/// Key length one cipher suite takes, and the length a `SET_KEY` for it must
/// carry exactly. `None` for a selector this build has no cipher for.
/// # C: O(1)
pub fn key_len(suite: u32) -> Option<usize> {
    Some(match suite {
        cipher::WEP40 => 5,
        cipher::WEP104 => 13,
        cipher::TKIP => 32,
        cipher::CCMP | cipher::GCMP | cipher::AES_CMAC | cipher::BIP_GMAC_128 => 16,
        cipher::CCMP_256 | cipher::GCMP_256 | cipher::BIP_CMAC_256
            | cipher::BIP_GMAC_256 => 32,
        _ => return None,
    })
}

/// Sequence-counter width a `SET_KEY` may supply for one cipher suite.
/// A suite whose replay counter is not installable takes none. # C: O(1)
pub fn seq_len(suite: u32) -> usize {
    match suite {
        cipher::TKIP | cipher::CCMP | cipher::CCMP_256
            | cipher::GCMP | cipher::GCMP_256 => 6,
        cipher::AES_CMAC | cipher::BIP_CMAC_256
            | cipher::BIP_GMAC_128 | cipher::BIP_GMAC_256 => 6,
        _ => 0,
    }
}

/// Whether a suite protects only management frames — the integrity group
/// ciphers, which may be installed only at key index 4 or 5. # C: O(1)
pub fn is_mgmt_cipher(suite: u32) -> bool {
    matches!(suite, cipher::AES_CMAC | cipher::BIP_CMAC_256
        | cipher::BIP_GMAC_128 | cipher::BIP_GMAC_256)
}

/// Whether a suite is one of the two beacon-protection integrity ciphers,
/// installable only at key index 6 or 7. # C: O(1)
pub fn is_beacon_cipher(suite: u32) -> bool { is_mgmt_cipher(suite) }

/// Whether a suite may be installed as a pairwise key. The integrity group
/// ciphers and the group-cipher placeholder may not. # C: O(1)
pub fn is_pairwise_capable(suite: u32) -> bool {
    !is_mgmt_cipher(suite) && suite != cipher::USE_GROUP
}
