// The software scan: walking the channels, dwelling on each, and probing
// only where probing is allowed.
//
// The regulatory rule is the part that is not negotiable. On a channel whose
// domain forbids initiating radiation, a station may LISTEN but may not
// transmit until it has heard a beacon — so the scan is passive there, and a
// scan that sent probe requests anyway would radiate on a channel the
// regulator closed.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use wireless::chan::{ChanDef, Channel};
use wireless::ieee80211::{build, MacAddr};
use wireless::scan::ScanRequest;

use crate::hw::Local;
use crate::iface::Sdata;
use crate::limits;
use crate::ops::RxStatus;

/// A scan in progress.
pub struct SwScan {
    pub req: ScanRequest,
    /// Interface the scan runs on.
    pub iface_id: u32,
    /// Channels still to visit, in order.
    pub channels: Vec<Channel>,
    /// Position in that list.
    pub at: usize,
    /// Monotonic nanoseconds the current dwell ends at.
    pub dwell_until_ns: u64,
    /// Probes sent on the current channel.
    pub probes_sent: u32,
    pub started_ns: u64,
    /// Channel the interface was on before the scan, restored afterwards.
    pub resume: Option<ChanDef>,
    /// Whether the scan was asked to stop.
    pub aborting: bool,
}

impl SwScan {
    /// The channel currently being visited. # C: O(1)
    pub fn channel(&self) -> Option<Channel> { self.channels.get(self.at).copied() }
    /// Whether every channel has been visited. # C: O(1)
    pub fn done(&self) -> bool { self.at >= self.channels.len() }
}

/// Begin a scan. A second scan while one is running is refused rather than
/// queued: the caller is waiting for a completion event and a queue would
/// make it wait for somebody else's. # C: O(N channels)
pub fn start(local: &Arc<Local>, sdata: &Arc<Sdata>, req: ScanRequest) -> Result<(), Errno> {
    if local.with(|s| s.scan.is_some()) { return Err(Errno::Ebusy); }
    let channels = channels_for(local, &req);
    if channels.is_empty() { return Err(Errno::Einval); }

    // A radio that scans in hardware is asked to; the software walk is what a
    // radio without that gets.
    let ssids: Vec<Vec<u8>> = req.ssids.iter().map(|s| s.0.clone()).collect();
    let freqs: Vec<u32> = channels.iter().map(|c| c.center_freq).collect();
    match local.ops.hw_scan(&local.hw, &sdata.vif(), &freqs, &ssids) {
        Ok(()) => {
            local.with(|s| s.scan = Some(SwScan {
                req, iface_id: sdata.id, channels: Vec::new(), at: 0,
                dwell_until_ns: 0, probes_sent: 0, started_ns: local_now(local),
                resume: sdata.chandef(), aborting: false,
            }));
            return Ok(());
        }
        Err(Errno::Eopnotsupp) => {}
        Err(e) => return Err(e),
    }

    let now = local_now(local);
    local.with(|s| s.scan = Some(SwScan {
        req, iface_id: sdata.id, channels, at: 0, dwell_until_ns: 0, probes_sent: 0,
        started_ns: now, resume: sdata.chandef(), aborting: false,
    }));
    visit(local, sdata, now);
    Ok(())
}

/// Stop a scan early. # C: O(1)
pub fn abort(local: &Arc<Local>) {
    let Some(iface_id) = local.with(|s| s.scan.as_mut().map(|sc| { sc.aborting = true; sc.iface_id }))
        else { return; };
    let Some(sdata) = local.iface_by_id(iface_id) else { return; };
    finish(local, &sdata, true);
}

/// Drive the scan forward. # C: O(1)
pub fn tick(local: &Arc<Local>, now_ns: u64) {
    let Some((iface_id, expired, overrun)) = local.with(|s| {
        let sc = s.scan.as_ref()?;
        // A hardware scan has no channel list here; it reports its own
        // completion and this walk must not step on it.
        if sc.channels.is_empty() { return None; }
        Some((sc.iface_id, now_ns >= sc.dwell_until_ns,
              now_ns.saturating_sub(sc.started_ns) >= limits::SCAN_MAX_TOTAL_NS))
    }) else { return; };
    let Some(sdata) = local.iface_by_id(iface_id) else { return; };
    if overrun { finish(local, &sdata, true); return; }
    if !expired { return; }
    let done = local.with(|s| {
        let Some(sc) = s.scan.as_mut() else { return true; };
        sc.at += 1;
        sc.probes_sent = 0;
        sc.done()
    });
    if done { finish(local, &sdata, false); return; }
    visit(local, sdata_ref(&sdata), now_ns);
}

fn sdata_ref(sdata: &Arc<Sdata>) -> &Arc<Sdata> { sdata }

/// Tune to the current channel, set the dwell, and probe if allowed.
/// # C: O(len)
fn visit(local: &Arc<Local>, sdata: &Arc<Sdata>, now_ns: u64) {
    let Some(chan) = local.with(|s| s.scan.as_ref().and_then(|sc| sc.channel())) else { return; };
    let passive = chan.scan_is_passive();
    let dwell = if passive { limits::SCAN_PASSIVE_DWELL_NS } else { limits::SCAN_ACTIVE_DWELL_NS };
    local.with(|s| { if let Some(sc) = s.scan.as_mut() { sc.dwell_until_ns = now_ns + dwell; } });
    crate::iface::set_channel(local, sdata, ChanDef::new_20(chan));
    if passive { return; }

    let (ssids, extra) = local.with(|s| s.scan.as_ref()
        .map(|sc| (sc.req.ssids.iter().map(|x| x.0.clone()).collect::<Vec<_>>(),
                   sc.req.ie.clone()))
        .unwrap_or_default());
    let addr = local.with(|s| s.scan.as_ref().and_then(|sc| sc.req.mac_addr))
        .unwrap_or(sdata.addr);
    // A request that named no SSID still probes, with the wildcard: an empty
    // SSID element is a request for every network to answer.
    let list = if ssids.is_empty() { alloc::vec![Vec::new()] } else { ssids };
    for ssid in list {
        let mut frame = build::probe_req(addr, MacAddr::BROADCAST, &ssid, &extra);
        crate::tx::tx_mgmt(local, sdata, &mut frame);
    }
    local.with(|s| { if let Some(sc) = s.scan.as_mut() { sc.probes_sent += 1; } });
}

/// Report the scan finished and put the interface back where it was.
/// # C: O(1)
pub fn finish(local: &Arc<Local>, sdata: &Arc<Sdata>, aborted: bool) {
    let Some(scan) = local.with(|s| s.scan.take()) else { return; };
    if let Some(def) = scan.resume { crate::iface::set_channel(local, sdata, def); }
    let Some(wiphy) = local.wiphy() else { return; };
    wireless::events::scan_done(&wiphy, &sdata.wdev, aborted || scan.aborting);
}

/// A driver reporting that its hardware scan finished. # C: O(1)
pub fn hw_scan_done(local: &Arc<Local>, aborted: bool) {
    let Some(iface_id) = local.with(|s| s.scan.as_ref().map(|sc| sc.iface_id)) else { return; };
    let Some(sdata) = local.iface_by_id(iface_id) else { return; };
    finish(local, &sdata, aborted);
}

/// Record a beacon or probe response in the radio's cache, whether a scan is
/// running or not: a beacon heard while merely associated is still the
/// freshest thing known about that network. # C: O(len)
pub fn note_beacon(local: &Arc<Local>, _sdata: &Arc<Sdata>, status: &RxStatus, frame: &[u8]) {
    let Some(wiphy) = local.wiphy() else { return; };
    let rx = wireless::events::RxBeacon {
        freq: status.freq,
        // The cache holds millibel-milliwatts; a driver reports dBm.
        signal_mbm: status.signal as i32 * 100,
        now_ns: status.now_ns,
        frame,
    };
    wireless::events::inform_bss_frame(&wiphy, &rx);
}

/// Channels a request covers, in the radio's own order. A request naming no
/// channel covers every usable one. # C: O(N channels)
pub fn channels_for(local: &Arc<Local>, req: &ScanRequest) -> Vec<Channel> {
    local.hw.bands.iter().flat_map(|b| b.channels.iter())
        .filter(|c| c.is_usable())
        .filter(|c| req.freqs.is_empty() || req.freqs.contains(&c.center_freq))
        .copied().collect()
}

fn local_now(local: &Arc<Local>) -> u64 { local.now_ns() }
