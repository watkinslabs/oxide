// Scanning and the BSS cache: what a scan asks for, what comes back, and how
// long a result stays worth reporting.
//
// The cache is not a list of frames. One network heard on one channel is one
// entry however many beacons and probe responses arrive for it, and an entry
// carries BOTH sets of elements, because a probe response can name an SSID a
// beacon hides and userspace needs the beacon's elements even after a probe
// response has arrived.

extern crate alloc;

use alloc::vec::Vec;

use crate::ieee80211::{elem, MacAddr};
use crate::uapi::enums::ChanWidth;

/// A scan result stops being reported this long after it was last heard.
pub const SCAN_RESULT_EXPIRE_NS: u64 = 30_000_000_000;
/// Entries the cache holds before the oldest is dropped to make room.
pub const MAX_BSS_ENTRIES: usize = 1000;
/// Longest SSID list a scan request may carry beyond what the radio allows.
pub const MAX_SCAN_SSIDS: usize = 20;

/// One network the scan cache holds.
#[derive(Clone, Debug)]
pub struct Bss {
    pub bssid: MacAddr,
    /// Centre frequency in MHz.
    pub freq: u32,
    /// Offset from `freq` in kHz.
    pub freq_offset: u32,
    /// Timing synchronisation value from the last frame heard.
    pub tsf: u64,
    pub beacon_interval: u16,
    pub capability: u16,
    /// Elements from the most recent frame, probe response preferred.
    pub ies: Vec<u8>,
    /// Elements from the most recent beacon, kept separately because a probe
    /// response does not carry everything a beacon does.
    pub beacon_ies: Vec<u8>,
    /// Whether `ies` came from a probe response rather than a beacon.
    pub presp_data: bool,
    /// Signal strength in millibel-milliwatts.
    pub signal_mbm: i32,
    /// Monotonic nanoseconds when this entry was last heard.
    pub last_seen_ns: u64,
    /// Monotonic nanoseconds when this entry was first heard.
    pub first_seen_ns: u64,
    /// Channel width the network advertises.
    pub chan_width: ChanWidth,
    /// Whether the local interface is authenticated or associated to it.
    pub status: Option<u32>,
    /// How many holders still need this entry; an entry the connect path is
    /// using is not expired out from under it.
    pub hold: u32,
}

impl Bss {
    /// SSID this network advertises, from whichever element set has one. A
    /// hidden network's beacon carries an empty or zeroed SSID and its probe
    /// response carries the real one, so the probe response wins. # C: O(N elements)
    pub fn ssid(&self) -> Vec<u8> {
        for buf in [&self.ies, &self.beacon_ies] {
            if let Some(e) = elem::find(buf, elem::id::SSID) {
                if !e.body.is_empty() && !e.body.iter().all(|&b| b == 0) {
                    return e.body.to_vec();
                }
            }
        }
        Vec::new()
    }

    /// Whether this network hides its SSID. # C: O(N elements)
    pub fn is_hidden(&self) -> bool { self.ssid().is_empty() }

    /// Whether the network claims privacy. # C: O(1)
    pub fn privacy(&self) -> bool {
        self.capability & crate::ieee80211::mgmt::capability::PRIVACY != 0
    }

    /// Age in milliseconds at a given monotonic time. # C: O(1)
    pub fn age_ms(&self, now_ns: u64) -> u32 {
        (now_ns.saturating_sub(self.last_seen_ns) / 1_000_000) as u32
    }

    /// Whether this entry is the same network as one identified by address,
    /// channel and SSID. Address alone is not enough: one radio can serve
    /// several networks, and one network can appear on several channels.
    /// # C: O(N elements)
    pub fn matches(&self, bssid: MacAddr, freq: u32, ssid: &[u8]) -> bool {
        self.bssid == bssid && self.freq == freq
            && (ssid.is_empty() || self.ssid() == ssid)
    }
}

/// One SSID a scan request asks for.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanSsid(pub Vec<u8>);

/// What a `TRIGGER_SCAN` asked for.
#[derive(Clone, Debug, Default)]
pub struct ScanRequest {
    /// SSIDs to probe for. An empty list means passive scanning only; a list
    /// containing one empty SSID means a wildcard active scan.
    pub ssids: Vec<ScanSsid>,
    /// Channels in MHz. Empty means every channel the radio supports.
    pub freqs: Vec<u32>,
    /// Extra elements to append to each probe request.
    pub ie: Vec<u8>,
    pub flags: u32,
    /// Netlink port that asked, so the result goes back to it.
    pub portid: u32,
    /// Address the probe requests are sent from, when randomised.
    pub mac_addr: Option<MacAddr>,
    pub mac_addr_mask: Option<MacAddr>,
    /// Dwell times in milliseconds, when the request set them.
    pub duration_ms: u16,
    pub duration_mandatory: bool,
    /// Monotonic nanoseconds the scan started at.
    pub start_ns: u64,
}

impl ScanRequest {
    /// Whether this request probes actively on at least one SSID. # C: O(1)
    pub fn is_active(&self) -> bool { !self.ssids.is_empty() }
    /// Whether the request flushes the cache of everything older than itself
    /// once it completes. # C: O(1)
    pub fn flushes(&self) -> bool {
        self.flags & crate::uapi::enums::scan_flags::FLUSH != 0
    }
}

/// The scan in progress on one radio, if any.
#[derive(Clone, Debug)]
pub struct ScanState {
    pub request: ScanRequest,
    /// Whether an abort has been asked for and not yet taken effect.
    pub aborting: bool,
}

/// The per-radio BSS cache.
#[derive(Debug, Default)]
pub struct BssCache {
    entries: Vec<Bss>,
    /// Bumped on every insert, update and expiry, so a dump can report a
    /// generation and a reader can tell its results are from one snapshot.
    pub generation: u32,
}

/// What an insert did, which decides whether an event goes to userspace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BssUpdate { Inserted, Updated }

impl BssCache {
    /// Insert or refresh one network heard on the air.
    ///
    /// A beacon must not overwrite the elements a probe response supplied,
    /// because the probe response is the only place a hidden network's SSID
    /// appears; the beacon's elements go to their own slot instead.
    /// # C: O(N entries)
    pub fn insert(&mut self, mut bss: Bss, from_probe_resp: bool, now_ns: u64) -> BssUpdate {
        bss.presp_data = from_probe_resp;
        bss.last_seen_ns = now_ns;
        let ssid = bss.ssid();
        if let Some(existing) = self.entries.iter_mut()
            .find(|e| e.bssid == bss.bssid && e.freq == bss.freq
                   && (ssid.is_empty() || e.ssid().is_empty() || e.ssid() == ssid))
        {
            existing.tsf = bss.tsf;
            existing.beacon_interval = bss.beacon_interval;
            existing.capability = bss.capability;
            existing.signal_mbm = bss.signal_mbm;
            existing.last_seen_ns = now_ns;
            existing.chan_width = bss.chan_width;
            if from_probe_resp {
                existing.ies = bss.ies;
                existing.presp_data = true;
            } else {
                existing.beacon_ies = bss.ies.clone();
                // A network never yet heard by probe response reports the
                // beacon's elements as its element set.
                if !existing.presp_data { existing.ies = bss.ies; }
            }
            self.generation = self.generation.wrapping_add(1);
            return BssUpdate::Updated;
        }
        bss.first_seen_ns = now_ns;
        if !from_probe_resp { bss.beacon_ies = bss.ies.clone(); }
        if self.entries.len() >= MAX_BSS_ENTRIES { self.drop_oldest(); }
        self.entries.push(bss);
        self.generation = self.generation.wrapping_add(1);
        BssUpdate::Inserted
    }

    /// Drop the oldest entry no one is holding. # C: O(N entries)
    fn drop_oldest(&mut self) {
        let victim = self.entries.iter().enumerate()
            .filter(|(_, e)| e.hold == 0)
            .min_by_key(|(_, e)| e.last_seen_ns)
            .map(|(i, _)| i);
        if let Some(i) = victim { self.entries.remove(i); }
    }

    /// Remove entries last heard before `cutoff_ns`. An entry a caller is
    /// holding stays: the connect path resolves a BSS and then uses it across
    /// several steps, and an expiry underneath it would leave the attempt
    /// pointing at nothing. # C: O(N entries)
    pub fn expire(&mut self, cutoff_ns: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| e.hold > 0 || e.last_seen_ns >= cutoff_ns);
        let dropped = before - self.entries.len();
        if dropped > 0 { self.generation = self.generation.wrapping_add(1); }
        dropped
    }

    /// Remove entries older than the standard expiry at this time. # C: O(N entries)
    pub fn expire_now(&mut self, now_ns: u64) -> usize {
        self.expire(now_ns.saturating_sub(SCAN_RESULT_EXPIRE_NS))
    }

    /// Every entry, most recently heard first. # C: O(N log N)
    pub fn snapshot(&self) -> Vec<Bss> {
        let mut out = self.entries.clone();
        out.sort_by(|a, b| b.last_seen_ns.cmp(&a.last_seen_ns));
        out
    }

    /// Entry matching an address, channel and SSID. # C: O(N entries)
    pub fn find(&self, bssid: MacAddr, freq: u32, ssid: &[u8]) -> Option<&Bss> {
        self.entries.iter().find(|e| e.matches(bssid, freq, ssid))
    }

    /// Best entry for an SSID by signal strength, optionally pinned to one
    /// address or one channel. This is the choice a connect makes when
    /// userspace named a network and not a BSS. # C: O(N entries)
    pub fn best_for(&self, ssid: &[u8], bssid: Option<MacAddr>, freq: Option<u32>)
        -> Option<&Bss>
    {
        self.entries.iter()
            .filter(|e| ssid.is_empty() || e.ssid() == ssid)
            .filter(|e| bssid.is_none_or(|b| e.bssid == b))
            .filter(|e| freq.is_none_or(|f| e.freq == f))
            .max_by_key(|e| e.signal_mbm)
    }

    /// Take a hold on an entry so expiry cannot remove it. # C: O(N entries)
    pub fn hold(&mut self, bssid: MacAddr, freq: u32) -> bool {
        let Some(e) = self.entries.iter_mut().find(|e| e.bssid == bssid && e.freq == freq)
            else { return false; };
        e.hold += 1;
        true
    }

    /// Release a hold. # C: O(N entries)
    pub fn release(&mut self, bssid: MacAddr, freq: u32) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.bssid == bssid && e.freq == freq) {
            e.hold = e.hold.saturating_sub(1);
        }
    }

    /// Mark an entry with the local interface's relationship to it, clearing
    /// the mark from every other entry — a station is associated to at most
    /// one BSS. # C: O(N entries)
    pub fn set_status(&mut self, bssid: MacAddr, freq: u32, status: Option<u32>) {
        for e in self.entries.iter_mut() {
            if e.bssid == bssid && e.freq == freq { e.status = status; }
            else if e.status == status && status.is_some() { e.status = None; }
        }
    }

    /// Drop everything. # C: O(1)
    pub fn clear(&mut self) {
        self.entries.clear();
        self.generation = self.generation.wrapping_add(1);
    }

    /// Entries held. # C: O(1)
    pub fn len(&self) -> usize { self.entries.len() }
    /// Whether the cache holds nothing. # C: O(1)
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}
