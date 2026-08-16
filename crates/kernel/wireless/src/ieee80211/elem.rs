// Information elements: the `{id, len, body}` stream that carries everything
// a beacon, probe response or association frame says about a network.
//
// Two rules decide correctness here and both are enforced by the iterator: an
// element whose declared length runs past the end of the buffer terminates
// the walk rather than being read short, and an element id repeated in one
// stream keeps its FIRST occurrence, because a later duplicate is how a
// forged element gets substituted for a real one.

/// Element ids this stack reads.
pub mod id {
    pub const SSID: u8 = 0;
    pub const SUPP_RATES: u8 = 1;
    pub const DS_PARAMS: u8 = 3;
    pub const CF_PARAMS: u8 = 4;
    pub const TIM: u8 = 5;
    pub const IBSS_PARAMS: u8 = 6;
    pub const COUNTRY: u8 = 7;
    pub const REQUEST: u8 = 10;
    pub const CHALLENGE: u8 = 16;
    pub const PWR_CONSTRAINT: u8 = 32;
    pub const PWR_CAPABILITY: u8 = 33;
    pub const TPC_REQUEST: u8 = 34;
    pub const TPC_REPORT: u8 = 35;
    pub const SUPPORTED_CHANNELS: u8 = 36;
    pub const CHANNEL_SWITCH: u8 = 37;
    pub const QUIET: u8 = 40;
    pub const ERP_INFO: u8 = 42;
    pub const HT_CAPABILITY: u8 = 45;
    pub const QOS_CAPA: u8 = 46;
    pub const RSN: u8 = 48;
    pub const EXT_SUPP_RATES: u8 = 50;
    pub const MOBILITY_DOMAIN: u8 = 54;
    pub const FAST_BSS_TRANSITION: u8 = 55;
    pub const TIMEOUT_INTERVAL: u8 = 56;
    pub const SUPPORTED_REGCLASSES: u8 = 59;
    pub const HT_OPERATION: u8 = 61;
    pub const SECONDARY_CHANNEL_OFFSET: u8 = 62;
    pub const RRM_ENABLED_CAPA: u8 = 70;
    pub const MULTIPLE_BSSID: u8 = 71;
    pub const BSS_COEX_2040: u8 = 72;
    pub const OVERLAP_BSS_SCAN: u8 = 74;
    pub const EXT_CAPABILITY: u8 = 127;
    pub const MESH_ID: u8 = 114;
    pub const MESH_CONFIG: u8 = 113;
    pub const VHT_CAPABILITY: u8 = 191;
    pub const VHT_OPERATION: u8 = 192;
    pub const OPMODE_NOTIF: u8 = 199;
    pub const REDUCED_NEIGHBOR_REPORT: u8 = 201;
    pub const VENDOR_SPECIFIC: u8 = 221;
    /// Container: the real id is the first body byte.
    pub const EXTENSION: u8 = 255;
}

/// Ids inside an `EXTENSION` element.
pub mod ext_id {
    pub const HE_CAPABILITY: u8 = 35;
    pub const HE_OPERATION: u8 = 36;
    pub const HE_6GHZ_CAPA: u8 = 59;
    pub const EHT_OPERATION: u8 = 106;
    pub const EHT_CAPABILITY: u8 = 108;
    pub const MULTI_LINK: u8 = 107;
}

/// Element header width: one id byte, one length byte.
pub const HDR_LEN: usize = 2;
/// Longest body a single element can declare.
pub const MAX_BODY_LEN: usize = 255;

/// One element: its id, its extension id if it has one, and its body with
/// the header already stripped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Element<'a> {
    pub id: u8,
    /// First body byte of an `EXTENSION` element.
    pub ext_id: Option<u8>,
    /// Body, excluding the extension id when there is one.
    pub body: &'a [u8],
}

/// Walk an element stream. # C: O(1) per step
pub fn parse(buf: &[u8]) -> ElementIter<'_> { ElementIter { buf, off: 0 } }

pub struct ElementIter<'a> { buf: &'a [u8], off: usize }

impl<'a> Iterator for ElementIter<'a> {
    type Item = Element<'a>;
    fn next(&mut self) -> Option<Element<'a>> {
        if self.off + HDR_LEN > self.buf.len() { return None; }
        let id = self.buf[self.off];
        let len = self.buf[self.off + 1] as usize;
        let start = self.off + HDR_LEN;
        // A declared length past the end is a truncated or forged stream; stop
        // rather than hand back a body that is not the one the sender wrote.
        if start + len > self.buf.len() { self.off = self.buf.len(); return None; }
        let mut body = &self.buf[start..start + len];
        let mut ext_id = None;
        if id == id::EXTENSION {
            let (first, rest) = body.split_first()?;
            ext_id = Some(*first);
            body = rest;
        }
        self.off = start + len;
        Some(Element { id, ext_id, body })
    }
}

/// First element with this id. # C: O(N elements)
pub fn find(buf: &[u8], want: u8) -> Option<Element<'_>> {
    parse(buf).find(|e| e.id == want)
}

/// First extension element with this extension id. # C: O(N elements)
pub fn find_ext(buf: &[u8], want: u8) -> Option<Element<'_>> {
    parse(buf).find(|e| e.id == id::EXTENSION && e.ext_id == Some(want))
}

/// First vendor-specific element whose body starts with this OUI and type.
/// # C: O(N elements)
pub fn find_vendor(buf: &[u8], oui: [u8; 3], oui_type: u8) -> Option<Element<'_>> {
    parse(buf).find(|e| e.id == id::VENDOR_SPECIFIC
        && e.body.len() >= 4 && e.body[..3] == oui && e.body[3] == oui_type)
}

/// Whether an element stream is well formed all the way to its end — no
/// element declares a body past the buffer. # C: O(N elements)
pub fn is_well_formed(buf: &[u8]) -> bool {
    let mut off = 0;
    while off < buf.len() {
        if off + HDR_LEN > buf.len() { return false; }
        let len = buf[off + 1] as usize;
        if off + HDR_LEN + len > buf.len() { return false; }
        if buf[off] == id::EXTENSION && len == 0 { return false; }
        off += HDR_LEN + len;
    }
    true
}

/// `50:6F:9A` — the Wi-Fi Alliance OUI, on WMM and WPA vendor elements.
pub const OUI_MICROSOFT: [u8; 3] = [0x00, 0x50, 0xf2];
/// WPA (version 1) vendor-element type under the Microsoft OUI.
pub const OUI_TYPE_WPA: u8 = 1;
/// WMM vendor-element type under the Microsoft OUI.
pub const OUI_TYPE_WMM: u8 = 2;

/// The elements the stack actually consults, resolved in one pass. Absent
/// elements stay `None`; a duplicate id does not replace the first.
#[derive(Clone, Copy, Debug, Default)]
pub struct Elements<'a> {
    pub ssid: Option<&'a [u8]>,
    pub supp_rates: Option<&'a [u8]>,
    pub ext_supp_rates: Option<&'a [u8]>,
    pub ds_params: Option<&'a [u8]>,
    pub tim: Option<&'a [u8]>,
    pub country: Option<&'a [u8]>,
    pub erp_info: Option<u8>,
    pub ht_capability: Option<&'a [u8]>,
    pub ht_operation: Option<&'a [u8]>,
    pub vht_capability: Option<&'a [u8]>,
    pub vht_operation: Option<&'a [u8]>,
    pub he_capability: Option<&'a [u8]>,
    pub he_operation: Option<&'a [u8]>,
    pub rsn: Option<&'a [u8]>,
    pub wpa: Option<&'a [u8]>,
    pub wmm: Option<&'a [u8]>,
    pub mesh_id: Option<&'a [u8]>,
    pub ext_capability: Option<&'a [u8]>,
    pub challenge: Option<&'a [u8]>,
}

impl<'a> Elements<'a> {
    /// Resolve every element the stack reads in a single walk. # C: O(N elements)
    pub fn parse(buf: &'a [u8]) -> Self {
        let mut out = Self::default();
        for e in parse(buf) {
            let slot = match (e.id, e.ext_id) {
                (id::SSID, _) => &mut out.ssid,
                (id::SUPP_RATES, _) => &mut out.supp_rates,
                (id::EXT_SUPP_RATES, _) => &mut out.ext_supp_rates,
                (id::DS_PARAMS, _) => &mut out.ds_params,
                (id::TIM, _) => &mut out.tim,
                (id::COUNTRY, _) => &mut out.country,
                (id::HT_CAPABILITY, _) => &mut out.ht_capability,
                (id::HT_OPERATION, _) => &mut out.ht_operation,
                (id::VHT_CAPABILITY, _) => &mut out.vht_capability,
                (id::VHT_OPERATION, _) => &mut out.vht_operation,
                (id::RSN, _) => &mut out.rsn,
                (id::MESH_ID, _) => &mut out.mesh_id,
                (id::EXT_CAPABILITY, _) => &mut out.ext_capability,
                (id::CHALLENGE, _) => &mut out.challenge,
                (id::EXTENSION, Some(ext_id::HE_CAPABILITY)) => &mut out.he_capability,
                (id::EXTENSION, Some(ext_id::HE_OPERATION)) => &mut out.he_operation,
                (id::ERP_INFO, _) => {
                    if out.erp_info.is_none() { out.erp_info = e.body.first().copied(); }
                    continue;
                }
                (id::VENDOR_SPECIFIC, _) => {
                    if e.body.len() < 4 || e.body[..3] != OUI_MICROSOFT { continue; }
                    let slot = match e.body[3] {
                        OUI_TYPE_WPA => &mut out.wpa,
                        OUI_TYPE_WMM => &mut out.wmm,
                        _ => continue,
                    };
                    if slot.is_none() { *slot = Some(e.body); }
                    continue;
                }
                _ => continue,
            };
            if slot.is_none() { *slot = Some(e.body); }
        }
        out
    }

    /// SSID as it appears on the air. A hidden network sends a zero-length
    /// SSID or an all-zero one; both are reported as they were sent, because
    /// deciding they mean "hidden" is the scan layer's job, not the parser's.
    /// # C: O(1)
    pub fn ssid_bytes(&self) -> &'a [u8] { self.ssid.unwrap_or(&[]) }

    /// Operating channel a beacon advertises, from the DS parameter set or,
    /// on a band with no DS element, from the HT operation element's primary
    /// channel. # C: O(1)
    pub fn channel(&self) -> Option<u8> {
        if let Some(ds) = self.ds_params { if let Some(c) = ds.first() { return Some(*c); } }
        self.ht_operation.and_then(|h| h.first().copied())
    }
}
