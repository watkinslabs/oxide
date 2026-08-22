// The driver behind every fixture radio: what it was asked to do, and what it
// was told to answer with.

extern crate alloc;
extern crate std;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use std::sync::Mutex;

use syscall::errno::Errno;

use crate::chan::ChanDef;
use crate::ieee80211::MacAddr;
use crate::keys::KeyParams;
use crate::ops::{ApSettings, AssocRequest, AuthRequest, Cfg80211Ops, MgmtTxRequest,
                 NewIfaceParams, SurveyInfo};
use crate::scan::ScanRequest;
use crate::sme::ConnectParams;
use crate::sta::{StationInfo, StationParams};
use crate::uapi::enums::IfType;
use crate::wdev::{BssParams, Wdev};
use crate::wiphy::Wiphy;

use super::station_report;

/// What the fake driver was asked to do, in order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Call {
    AddIface(String, u32),
    DelIface(u64),
    ChangeIface(u64, u32),
    Scan { ssids: usize, freqs: Vec<u32>, flags: u32 },
    AbortScan,
    AddKey { idx: u8, pairwise: bool },
    DelKey { idx: u8, pairwise: bool },
    DefaultKey { idx: u8, uni: bool, multi: bool },
    DefaultMgmtKey(u8),
    Connect,
    Disconnect(u16),
    Auth,
    Assoc,
    Deauth(u16, bool),
    Disassoc(u16, bool),
    StartAp { beacon_interval: u16, dtim: u8 },
    StopAp,
    ChangeBss(BssParams),
    MgmtTx { len: usize, offchan: bool },
    SetChannel(u32),
    SetPowerMgmt(bool),
    SetWiphyParams,
    SetRegdom,
    AddStation(MacAddr),
    ChangeStation(MacAddr),
    DelStation(Option<MacAddr>, u16),
}

/// What the fake driver is told to answer with, so a test can drive the
/// failure paths as well as the success ones.
#[derive(Clone, Copy, Debug, Default)]
pub struct Program {
    pub scan_fails: Option<Errno>,
    pub add_iface_fails: Option<Errno>,
    pub add_key_fails: Option<Errno>,
    pub connect_fails: Option<Errno>,
    pub start_ap_fails: Option<Errno>,
    pub change_bss_fails: Option<Errno>,
    pub mgmt_tx_fails: Option<Errno>,
    pub stations: usize,
    pub surveys: usize,
    pub cookie: u64,
}

/// The driver behind every fixture radio.
pub struct FakeOps {
    pub calls: Mutex<Vec<Call>>,
    pub program: Mutex<Program>,
    pub next_ifindex: Mutex<u32>,
}

impl Default for FakeOps {
    fn default() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            program: Mutex::new(Program { cookie: 0xfeed_1234, ..Default::default() }),
            next_ifindex: Mutex::new(100),
        }
    }
}

impl FakeOps {
    /// Record one driver call. # C: O(1)
    fn record(&self, c: Call) { self.calls.lock().unwrap().push(c); }
    /// The programmed answers. # C: O(1)
    fn prog(&self) -> Program { *self.program.lock().unwrap() }
}

impl Cfg80211Ops for FakeOps {
    fn add_virtual_intf(&self, wiphy: &Arc<Wiphy>, params: &NewIfaceParams)
        -> Result<Arc<Wdev>, Errno>
    {
        self.record(Call::AddIface(params.name.clone(), params.iftype.as_u32()));
        if let Some(e) = self.prog().add_iface_fails { return Err(e); }
        let id = wiphy.next_wdev_identifier();
        let addr = params.addr.unwrap_or(wiphy.perm_addr);
        let wdev = Arc::new(Wdev::new(id, wiphy.index, params.iftype,
                                      params.name.clone(), addr));
        if params.iftype.has_netdev() {
            let mut n = self.next_ifindex.lock().unwrap();
            wdev.with(|w| w.ifindex = Some(*n));
            *n += 1;
        }
        Ok(wdev)
    }
    fn del_virtual_intf(&self, _w: &Arc<Wiphy>, wdev: &Arc<Wdev>) -> Result<(), Errno> {
        self.record(Call::DelIface(wdev.identifier));
        Ok(())
    }
    fn change_virtual_intf(&self, _w: &Arc<Wiphy>, wdev: &Arc<Wdev>, ty: IfType)
        -> Result<(), Errno>
    {
        self.record(Call::ChangeIface(wdev.identifier, ty.as_u32()));
        Ok(())
    }
    fn add_key(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, idx: u8, pairwise: bool,
               _peer: Option<MacAddr>, _p: &KeyParams) -> Result<(), Errno> {
        self.record(Call::AddKey { idx, pairwise });
        match self.prog().add_key_fails { Some(e) => Err(e), None => Ok(()) }
    }
    fn del_key(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, idx: u8, pairwise: bool,
               _peer: Option<MacAddr>) -> Result<(), Errno> {
        self.record(Call::DelKey { idx, pairwise });
        Ok(())
    }
    fn set_default_key(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, idx: u8, uni: bool,
                       multi: bool) -> Result<(), Errno> {
        self.record(Call::DefaultKey { idx, uni, multi });
        Ok(())
    }
    fn set_default_mgmt_key(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, idx: u8)
        -> Result<(), Errno> { self.record(Call::DefaultMgmtKey(idx)); Ok(()) }
    fn scan(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, req: &ScanRequest)
        -> Result<(), Errno>
    {
        self.record(Call::Scan { ssids: req.ssids.len(), freqs: req.freqs.clone(),
                                 flags: req.flags });
        match self.prog().scan_fails { Some(e) => Err(e), None => Ok(()) }
    }
    fn abort_scan(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>) -> Result<(), Errno> {
        self.record(Call::AbortScan); Ok(())
    }
    fn connect(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, _p: &ConnectParams)
        -> Result<(), Errno>
    {
        self.record(Call::Connect);
        match self.prog().connect_fails { Some(e) => Err(e), None => Ok(()) }
    }
    fn disconnect(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, reason: u16)
        -> Result<(), Errno> { self.record(Call::Disconnect(reason)); Ok(()) }
    fn auth(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, _r: &AuthRequest)
        -> Result<(), Errno> { self.record(Call::Auth); Ok(()) }
    fn assoc(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, _r: &AssocRequest)
        -> Result<(), Errno> { self.record(Call::Assoc); Ok(()) }
    fn deauth(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, _p: MacAddr, reason: u16,
              local: bool) -> Result<(), Errno> {
        self.record(Call::Deauth(reason, local)); Ok(())
    }
    fn disassoc(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, _p: MacAddr, reason: u16,
                local: bool) -> Result<(), Errno> {
        self.record(Call::Disassoc(reason, local)); Ok(())
    }
    fn get_station(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, peer: MacAddr)
        -> Result<StationInfo, Errno> { Ok(station_report(peer)) }
    fn dump_station(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, idx: usize)
        -> Result<StationInfo, Errno>
    {
        if idx >= self.prog().stations { return Err(Errno::Enoent); }
        Ok(station_report(MacAddr([0x02, 0, 0, 0, 0, idx as u8])))
    }
    fn add_station(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, peer: MacAddr,
                   _p: &StationParams) -> Result<(), Errno> {
        self.record(Call::AddStation(peer)); Ok(())
    }
    fn change_station(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, peer: MacAddr,
                      _p: &StationParams) -> Result<(), Errno> {
        self.record(Call::ChangeStation(peer)); Ok(())
    }
    fn del_station(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, peer: Option<MacAddr>,
                   reason: u16) -> Result<(), Errno> {
        self.record(Call::DelStation(peer, reason)); Ok(())
    }
    fn start_ap(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, s: &ApSettings)
        -> Result<(), Errno>
    {
        self.record(Call::StartAp { beacon_interval: s.beacon_interval,
                                    dtim: s.dtim_period });
        match self.prog().start_ap_fails { Some(e) => Err(e), None => Ok(()) }
    }
    fn stop_ap(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>) -> Result<(), Errno> {
        self.record(Call::StopAp); Ok(())
    }
    fn change_bss(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, p: &BssParams)
        -> Result<(), Errno>
    {
        self.record(Call::ChangeBss(p.clone()));
        match self.prog().change_bss_fails { Some(e) => Err(e), None => Ok(()) }
    }
    fn set_wiphy_params(&self, _w: &Arc<Wiphy>) -> Result<(), Errno> {
        self.record(Call::SetWiphyParams); Ok(())
    }
    fn set_monitor_channel(&self, _w: &Arc<Wiphy>, def: &ChanDef) -> Result<(), Errno> {
        self.record(Call::SetChannel(def.chan.center_freq)); Ok(())
    }
    fn set_power_mgmt(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, on: bool, _t: i32)
        -> Result<(), Errno> { self.record(Call::SetPowerMgmt(on)); Ok(()) }
    fn mgmt_tx(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, r: &MgmtTxRequest)
        -> Result<u64, Errno>
    {
        self.record(Call::MgmtTx { len: r.frame.len(), offchan: r.offchan });
        match self.prog().mgmt_tx_fails { Some(e) => Err(e), None => Ok(self.prog().cookie) }
    }
    fn set_regdom(&self, _w: &Arc<Wiphy>) -> Result<(), Errno> {
        self.record(Call::SetRegdom); Ok(())
    }
    fn dump_survey(&self, _w: &Arc<Wiphy>, _d: &Arc<Wdev>, idx: usize)
        -> Result<SurveyInfo, Errno>
    {
        if idx >= self.prog().surveys { return Err(Errno::Enoent); }
        Ok(SurveyInfo { freq: 2412 + idx as u32 * 5, noise: Some(-95), in_use: idx == 0,
                        time_ms: Some(1000), time_busy_ms: Some(100),
                        ..Default::default() })
    }
}
