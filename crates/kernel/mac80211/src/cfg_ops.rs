// The bridge from the configuration layer to this one.
//
// Everything userspace asks for arrives here. Each method does the softmac
// work and then, where the driver has something to do about it, calls the
// driver — in that order, so a driver callback never observes state the
// layer has not finished changing.
//
// The handle back to the radio is weak. The radio holds the configuration
// device, the device holds this bridge; a strong reference here would close
// the ring and free neither.

extern crate alloc;

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use syscall::errno::Errno;
use wireless::chan::ChanDef;
use wireless::ieee80211::MacAddr;
use wireless::keys::KeyParams;
use wireless::ops::{ApSettings, AssocRequest, AuthRequest, Cfg80211Ops, MgmtTxRequest,
                    NewIfaceParams, SurveyInfo};
use wireless::scan::ScanRequest;
use wireless::sme::ConnectParams;
use wireless::sta::{StationInfo, StationParams};
use wireless::uapi::enums::IfType;
use wireless::{Wdev, Wiphy};

use crate::hw::Local;
use crate::iface::Sdata;
use crate::key::Key;
use crate::ops::StaState;

/// The configuration bridge of one radio.
pub struct Bridge {
    local: Weak<Local>,
}

impl Bridge {
    /// Build a bridge for a radio. # C: O(1)
    pub fn new(local: Weak<Local>) -> Self { Self { local } }

    fn local(&self) -> Result<Arc<Local>, Errno> { self.local.upgrade().ok_or(Errno::Enodev) }

    fn iface(&self, wdev: &Arc<Wdev>) -> Result<(Arc<Local>, Arc<Sdata>), Errno> {
        let local = self.local()?;
        let sdata = local.iface_by_wdev(wdev.identifier).ok_or(Errno::Enodev)?;
        Ok((local, sdata))
    }
}

impl Cfg80211Ops for Bridge {
    /// # C: O(N interfaces)
    fn add_virtual_intf(&self, _wiphy: &Arc<Wiphy>, params: &NewIfaceParams)
        -> Result<Arc<Wdev>, Errno>
    {
        let local = self.local()?;
        let sdata = crate::iface::add(&local, params.iftype, params.name.clone(),
                                      params.addr)?;
        sdata.with(|s| {
            s.use_4addr = params.use_4addr.unwrap_or(false);
            s.mntr_flags = params.mntr_flags;
        });
        crate::netdev::register(&sdata);
        Ok(sdata.wdev.clone())
    }

    /// # C: O(N interfaces)
    fn del_virtual_intf(&self, _wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>) -> Result<(), Errno> {
        let (local, sdata) = self.iface(wdev)?;
        if let Some(ifindex) = sdata.wdev.ifindex() {
            crate::netdev::unregister(&sdata, net::NetIfaceId::from_raw(ifindex));
        }
        crate::iface::remove(&local, &sdata);
        Ok(())
    }

    /// # C: driver-dependent
    fn change_virtual_intf(&self, _wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, ty: IfType)
        -> Result<(), Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        crate::iface::change_type(&local, &sdata, ty)
    }

    /// # C: O(N peers)
    fn add_key(&self, wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, idx: u8, pairwise: bool,
               peer: Option<MacAddr>, params: &KeyParams) -> Result<(), Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        if !wiphy.has_cipher(params.cipher) { return Err(Errno::Einval); }
        let key = Key::new(params.cipher, params.key.clone(), idx, pairwise, peer,
                           params.seq.as_deref());
        // The hardware is offered the key first. A radio that takes it will
        // encrypt in its own engine and the software path must then leave the
        // frame alone; a radio that refuses leaves the work here.
        let conf = crate::ops::KeyConf {
            cipher: params.cipher, key: params.key.clone(), idx, pairwise, peer,
            flags: key.flags,
        };
        let uploaded = local.ops.set_key(&local.hw, &sdata.vif(), false, &conf).is_ok();
        let mut key = key;
        if uploaded { key.flags |= crate::flags::key::UPLOADED; }
        sdata.with(|s| s.keys.install(key));
        // Installing the first key means the link is protected, so the port
        // is closed until the exchange that opens it completes.
        crate::iface::update_bss(&local, &sdata, |bss| {
            if !bss.assoc { bss.port_authorized = false; }
        });
        Ok(())
    }

    /// # C: O(N peers)
    fn del_key(&self, _wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, idx: u8, pairwise: bool,
               peer: Option<MacAddr>) -> Result<(), Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        if !sdata.with(|s| s.keys.remove(idx, pairwise, peer)) { return Err(Errno::Enoent); }
        let conf = crate::ops::KeyConf {
            cipher: 0, key: Vec::new(), idx, pairwise, peer, flags: 0,
        };
        let _ = local.ops.set_key(&local.hw, &sdata.vif(), true, &conf);
        Ok(())
    }

    /// # C: O(1)
    fn set_default_key(&self, _wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, idx: u8, _uni: bool,
                       _multi: bool) -> Result<(), Errno>
    {
        let (_, sdata) = self.iface(wdev)?;
        if sdata.with(|s| s.keys.set_default(idx)) { Ok(()) } else { Err(Errno::Enoent) }
    }

    /// # C: O(1)
    fn set_default_mgmt_key(&self, _wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, idx: u8)
        -> Result<(), Errno>
    {
        let (_, sdata) = self.iface(wdev)?;
        let ok = sdata.with(|s| {
            if s.keys.get(idx, false, None).is_none() { return false; }
            s.keys.default_mgmt_key = Some(idx);
            true
        });
        if !ok { return Err(Errno::Enoent); }
        Ok(())
    }

    /// # C: O(N channels)
    fn scan(&self, _wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, req: &ScanRequest)
        -> Result<(), Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        crate::scan::start(&local, &sdata, req.clone())
    }

    /// # C: O(1)
    fn abort_scan(&self, _wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>) -> Result<(), Errno> {
        let (local, _) = self.iface(wdev)?;
        crate::scan::abort(&local);
        Ok(())
    }

    /// Run the whole join. Where the request did not name a network, the
    /// radio's own cache is consulted — a connect to an SSID nobody has heard
    /// of has nothing to authenticate against. # C: O(N entries)
    fn connect(&self, wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, params: &ConnectParams)
        -> Result<(), Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        if !sdata.iftype().is_client() { return Err(Errno::Eopnotsupp); }
        let bssid = params.bssid.or(params.bssid_hint)
            .or_else(|| find_bss(wiphy, &params.ssid, params.freq))
            .ok_or(Errno::Enoent)?;
        if let Some(freq) = params.freq.or(params.freq_hint) {
            if let Some(chan) = wiphy.channel(freq) {
                crate::iface::set_channel(&local, &sdata, ChanDef::new_20(chan));
            }
        }
        let alg = wireless::sme::alg_for_auth_type(params.auth_type);
        let mfp = params.mfp != 0;
        crate::mlme::run::start(&local, &sdata, bssid, params.ssid.clone(), alg,
                                params.ie.clone(), mfp);
        Ok(())
    }

    /// # C: O(len)
    fn disconnect(&self, _wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, reason: u16)
        -> Result<(), Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        let action = sdata.with(|s|
            s.mlme.on_event(crate::mlme::MlmeEvent::LocalDisconnect, 0));
        crate::mlme::run::run(&local, &sdata, action);
        if let Some(bssid) = sdata.bssid() {
            crate::mlme::deauth::deauth_peer(&local, &sdata, bssid, reason, false);
        }
        Ok(())
    }

    /// # C: O(len)
    fn auth(&self, wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, req: &AuthRequest)
        -> Result<(), Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        if let Some(chan) = wiphy.channel(req.freq) {
            crate::iface::set_channel(&local, &sdata, ChanDef::new_20(chan));
        }
        if req.local_state_change {
            sdata.wdev.with(|w| w.conn.note_authenticated(req.bssid));
            return Ok(());
        }
        let alg = wireless::sme::alg_for_auth_type(req.auth_type);
        crate::mlme::run::start(&local, &sdata, req.bssid, req.ssid.clone(), alg,
                                req.ie.clone(), false);
        Ok(())
    }

    /// # C: O(len)
    fn assoc(&self, _wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, req: &AssocRequest)
        -> Result<(), Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        if !sdata.wdev.conn().is_authenticated(req.bssid) { return Err(Errno::Enolink); }
        sdata.with(|s| {
            s.mlme.bssid = Some(req.bssid);
            s.mlme.ssid = req.ssid.clone();
            s.mlme.assoc_ie = req.ie.clone();
            s.mlme.mfp = req.use_mfp != 0;
        });
        crate::mlme::run::send_assoc(&local, &sdata);
        Ok(())
    }

    /// # C: O(len)
    fn deauth(&self, _wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, peer: MacAddr, reason: u16,
              local_state_change: bool) -> Result<(), Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        crate::mlme::deauth::deauth_peer(&local, &sdata, peer, reason, local_state_change);
        Ok(())
    }

    /// # C: O(len)
    fn disassoc(&self, _wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, peer: MacAddr, reason: u16,
                local_state_change: bool) -> Result<(), Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        crate::mlme::deauth::disassoc_peer(&local, &sdata, peer, reason, local_state_change);
        Ok(())
    }

    /// # C: O(N stations)
    fn get_station(&self, wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, peer: MacAddr)
        -> Result<StationInfo, Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        let now = local.now_ns();
        let gen = wiphy.generation();
        sdata.stas.with(peer, |sta| sta.to_info(now, gen)).ok_or(Errno::Enoent)
    }

    /// # C: O(N stations)
    fn dump_station(&self, wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, idx: usize)
        -> Result<StationInfo, Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        let addr = sdata.stas.addr_at(idx).ok_or(Errno::Enoent)?;
        let now = local.now_ns();
        let gen = wiphy.generation();
        sdata.stas.with(addr, |sta| sta.to_info(now, gen)).ok_or(Errno::Enoent)
    }

    /// # C: O(N stations)
    fn add_station(&self, _wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, peer: MacAddr,
                   params: &StationParams) -> Result<(), Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        let now = local.now_ns();
        let mut sta = crate::sta_info::Sta::new(peer, now);
        apply_params(&mut sta, params);
        if !sdata.stas.insert(sta) { return Err(Errno::Eexist); }
        apply_flags(&local, &sdata, peer, params);
        Ok(())
    }

    /// # C: O(N stations)
    fn change_station(&self, _wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, peer: MacAddr,
                      params: &StationParams) -> Result<(), Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        sdata.stas.with(peer, |sta| apply_params(sta, params)).ok_or(Errno::Enoent)?;
        apply_flags(&local, &sdata, peer, params);
        Ok(())
    }

    /// # C: O(N stations)
    fn del_station(&self, _wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, peer: Option<MacAddr>,
                   reason: u16) -> Result<(), Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        let peers = match peer { Some(p) => alloc::vec![p], None => sdata.stas.addrs() };
        for p in peers { crate::mlme::deauth::deauth_peer(&local, &sdata, p, reason, false); }
        Ok(())
    }

    /// # C: O(len)
    fn start_ap(&self, wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, settings: &ApSettings)
        -> Result<(), Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        if !sdata.iftype().is_ap() { return Err(Errno::Eopnotsupp); }
        let def = settings.chandef.or_else(|| sdata.chandef()).ok_or(Errno::Einval)?;
        if !def.chan.can_beacon() { return Err(Errno::Einval); }
        crate::iface::set_channel(&local, &sdata, def);
        sdata.with(|s| {
            s.proberesp_ies = settings.proberesp_ies.clone();
            s.assocresp_ies = settings.assocresp_ies.clone();
        });
        crate::iface::update_bss(&local, &sdata, |bss| {
            bss.ssid = settings.ssid.clone();
            bss.beacon_int = if settings.beacon_interval == 0 {
                crate::limits::DEFAULT_BEACON_INT_TU } else { settings.beacon_interval };
            bss.dtim_period = if settings.dtim_period == 0 {
                crate::limits::DEFAULT_DTIM_PERIOD } else { settings.dtim_period };
            bss.bssid = Some(sdata.addr);
            bss.enable_beacon = true;
        });
        let beacon = crate::mlme::beacon::build_beacon(&local, &sdata);
        sdata.with(|s| s.beacon = beacon);
        sdata.wdev.with(|w| { w.beaconing = true; w.ssid = settings.ssid.clone(); });
        wiphy.bump_generation();
        Ok(())
    }

    /// # C: O(N stations)
    fn stop_ap(&self, _wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>) -> Result<(), Errno> {
        let (local, sdata) = self.iface(wdev)?;
        for p in sdata.stas.addrs() {
            crate::mlme::deauth::deauth_peer(&local, &sdata, p,
                wireless::ieee80211::status::reason::DEAUTH_LEAVING, false);
        }
        crate::iface::update_bss(&local, &sdata, |bss| bss.enable_beacon = false);
        sdata.with(|s| s.beacon = None);
        sdata.wdev.with(|w| w.beaconing = false);
        Ok(())
    }

    /// # C: driver-dependent
    fn set_wiphy_params(&self, wiphy: &Arc<Wiphy>) -> Result<(), Errno> {
        let local = self.local()?;
        let conf = wiphy.config();
        local.with(|s| {
            s.frag_threshold = conf.frag_threshold;
            s.rts_threshold = conf.rts_threshold;
            s.conf.short_frame_max_tx_count = conf.retry_short;
            s.conf.long_frame_max_tx_count = conf.retry_long;
        });
        let device_conf = local.with(|s| s.conf);
        local.ops.config(&local.hw, &device_conf, crate::flags::conf_changed::RETRY_LIMITS)
    }

    /// # C: driver-dependent
    fn set_monitor_channel(&self, _wiphy: &Arc<Wiphy>, def: &ChanDef) -> Result<(), Errno> {
        let local = self.local()?;
        if !def.is_valid() { return Err(Errno::Einval); }
        let Some(sdata) = local.ifaces().into_iter()
            .find(|s| s.iftype() == IfType::Monitor) else { return Err(Errno::Enodev); };
        crate::iface::set_channel(&local, &sdata, *def);
        Ok(())
    }

    /// # C: O(1)
    fn set_power_mgmt(&self, _wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, enabled: bool,
                      timeout_ms: i32) -> Result<(), Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        sdata.wdev.with(|w| w.ps_timeout_ms = timeout_ms);
        crate::ps::set_ps(&local, &sdata, enabled);
        Ok(())
    }

    /// # C: O(len)
    fn mgmt_tx(&self, _wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, req: &MgmtTxRequest)
        -> Result<u64, Errno>
    {
        let (local, sdata) = self.iface(wdev)?;
        if req.frame.len() < 24 { return Err(Errno::Einval); }
        let mut frame = req.frame.clone();
        crate::tx::tx_mgmt(&local, &sdata, &mut frame);
        // The cookie identifies this transmission in the status report. The
        // interface identifier and a per-interface counter together are
        // unique for as long as anyone can be waiting on one.
        Ok(sdata.wdev.identifier ^ (sdata.next_seq() as u64) << 48)
    }

    /// # C: driver-dependent
    fn set_regdom(&self, _wiphy: &Arc<Wiphy>) -> Result<(), Errno> {
        let local = self.local()?;
        crate::iface::apply_conf(&local);
        Ok(())
    }

    /// # C: driver-dependent
    fn dump_survey(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, idx: usize)
        -> Result<SurveyInfo, Errno>
    {
        let local = self.local()?;
        local.ops.get_survey(&local.hw, idx).ok_or(Errno::Enoent)
    }
}

/// The network in the radio's cache that a connect request names. # C: O(N entries)
fn find_bss(wiphy: &Arc<Wiphy>, ssid: &[u8], freq: Option<u32>) -> Option<MacAddr> {
    // The strongest signal is the one worth trying first, which is the
    // choice the cache's own selector already makes.
    wiphy.with_state(|s| s.bss.best_for(ssid, None, freq).map(|b| b.bssid))
}

fn apply_params(sta: &mut crate::sta_info::Sta, params: &StationParams) {
    if let Some(aid) = params.aid { sta.aid = aid; }
    if let Some(li) = params.listen_interval { sta.listen_interval = li; }
    if let Some(rates) = &params.supported_rates {
        sta.supported_rates = rates.iter().map(|&b| crate::uapi::elem_to_rate(b)).collect();
    }
    if let Some(four) = params.use_4addr { sta.use_4addr = four; }
}

/// Apply the state a station-flag update asks for, walking the ladder rather
/// than assigning the end state. # C: O(steps)
fn apply_flags(local: &Arc<Local>, sdata: &Arc<Sdata>, peer: MacAddr,
               params: &StationParams) {
    use wireless::uapi::nested::sta_flag;
    let Some(flags) = params.sta_flags else { return; };
    let want = if flags.get(sta_flag::AUTHORIZED) { StaState::Authorized }
               else if flags.get(sta_flag::ASSOCIATED) { StaState::Assoc }
               else if flags.get(sta_flag::AUTHENTICATED) { StaState::Auth }
               else { return; };
    sdata.stas.set_state(peer, want, |from, to| {
        let _ = local.ops.sta_state(&local.hw, &sdata.vif(), peer, from, to);
        true
    });
    if want == StaState::Authorized && !sdata.iftype().is_ap() {
        crate::iface::update_bss(local, sdata, |bss| bss.port_authorized = true);
        if let (Some(wiphy), Some(bssid)) = (local.wiphy(), sdata.bssid()) {
            wireless::events::port_authorized(&wiphy, &sdata.wdev, bssid);
        }
    }
}
