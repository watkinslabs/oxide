//! Process-context SATA media removal and insertion service.

use alloc::{sync::Arc, string::String, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

use crate::device::AhciBlk;
use crate::host::AhciHost;
use crate::irq::{self, IrqBinding};
use crate::port::Ahci;
use crate::regs;

use crate::imp::{AhciBh, AhciRecord, DEVICES};

pub(crate) struct WatchRecord {
    device_key: pci::Bdf,
    command_orig: u16,
    host:       Arc<AhciHost>,
    port:       u32,
    irq:        IrqBinding,
    probe_pending: AtomicBool,
}

impl WatchRecord {
    fn take_link_change(&self) -> bool {
        if !self.irq.take_link_change() { return false; }
        regs::link_is_online(self.host.r32(regs::port_reg(self.port, regs::P_SSTS)))
    }

    pub(crate) fn release(self) {
        self.irq.begin_release(&self.host, self.port);
        self.irq.synchronize_and_release();
    }
}

static WATCHES: Spinlock<Vec<WatchRecord>, DriverLockClass> = Spinlock::new(Vec::new());
static MEDIA_WORK_PENDING: AtomicBool = AtomicBool::new(false);
static MEDIA_WORK_QUEUED: AtomicBool = AtomicBool::new(false);

/// Retain one empty physical port as a hardware-notification endpoint. # C: O(N_ports)
pub(super) fn install_watcher(device_key: pci::Bdf, command_orig: u16,
    host: Arc<AhciHost>, port: u32) -> bool
{
    install_watcher_inner(device_key, command_orig, host, port, false)
}

fn install_watcher_after_detach(device_key: pci::Bdf, command_orig: u16,
    host: Arc<AhciHost>, port: u32) -> bool
{
    install_watcher_inner(device_key, command_orig, host, port, true)
}

fn install_watcher_inner(device_key: pci::Bdf, command_orig: u16,
    host: Arc<AhciHost>, port: u32, recheck_link: bool) -> bool
{
    if DEVICES.lock_bh::<AhciBh>().iter().any(|record|
        record.device_key == device_key && record.port == port)
    {
        return true;
    }
    if WATCHES.lock_bh::<AhciBh>().iter().any(|watch|
        watch.device_key == device_key && watch.port == port)
    {
        return true;
    }
    let Some(irq) = irq::bind_watcher(device_key, &host, port) else { return false; };
    let online = recheck_link
        && regs::link_is_online(host.r32(regs::port_reg(port, regs::P_SSTS)));
    WATCHES.lock_bh::<AhciBh>().push(WatchRecord {
        device_key, command_orig, host, port, irq, probe_pending: AtomicBool::new(online),
    });
    if online { queue_media_work(); }
    true
}

/// Publish one now-live SATA port with its own command-DMA endpoint. # C: O(port probe)
pub(super) fn publish_port(device_key: pci::Bdf, command_orig: u16,
    host: Arc<AhciHost>, port: u32) -> Option<u32>
{
    let mut ctrl = Ahci::bring_up(host, port).ok()?;
    let blk_size = ctrl.blk_size;
    let capacity = ctrl.sectors;
    let serial = ctrl.serial.clone();
    let Some(binding) = irq::bind(device_key, &ctrl) else {
        ctrl.shutdown_and_free();
        return None;
    };
    let dev = Arc::new(AhciBlk::new(ctrl, binding, blk_size, capacity));
    let Some(name) = scsi::publish_block_transport(dev.clone(), serial.as_deref()) else {
        dev.remove();
        return None;
    };
    let name_text = String::from(name.as_str());
    let Some(idx) = block::registry::by_name(&name_text).map(|disk| disk.index) else {
        let _ = block::registry::unregister(&name_text);
        dev.remove();
        return None;
    };
    DEVICES.lock_bh::<AhciBh>().push(AhciRecord { device_key, command_orig, port, name, dev });
    Some(idx)
}

/// Process hard-handler observations without sleeping in the BlockIo softirq. # C: O(N_ports)
pub(super) fn run_completion_bottom_half() {
    let devices: Vec<Arc<AhciBlk>> = DEVICES.lock_bh::<AhciBh>().iter()
        .map(|record| record.dev.clone()).collect();
    let mut work = false;
    for dev in devices { work |= dev.completion_bottom_half(); }
    let watches = WATCHES.lock_bh::<AhciBh>();
    for watch in watches.iter() {
        if watch.take_link_change() {
            watch.probe_pending.store(true, Ordering::Release);
            work = true;
        }
    }
    drop(watches);
    if work || MEDIA_WORK_PENDING.load(Ordering::Acquire) { queue_media_work(); }
}

fn queue_media_work() {
    MEDIA_WORK_PENDING.store(true, Ordering::Release);
    if MEDIA_WORK_QUEUED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
    if !sched::live::workqueue::queue_work(media_work, 0) {
        MEDIA_WORK_QUEUED.store(false, Ordering::Release);
        block::completion::raise();
    }
}

/// Reprobe confirmed SATA link changes after removing stale publication. # Ctx: process
/// # Sleeps: yes
fn media_work(_arg: usize) {
    loop {
        MEDIA_WORK_PENDING.store(false, Ordering::Release);
        let departed: Vec<String> = DEVICES.lock_bh::<AhciBh>().iter()
            .filter(|record| record.dev.media_offline())
            .map(|record| String::from(record.name.as_str())).collect();
        for name in departed { remove_departed_disk(&name); }
        let arrivals: Vec<(pci::Bdf, u32)> = WATCHES.lock_bh::<AhciBh>().iter()
            .filter(|watch| watch.probe_pending.swap(false, Ordering::AcqRel))
            .map(|watch| (watch.device_key, watch.port)).collect();
        for (device_key, port) in arrivals { probe_arrival(device_key, port); }
        MEDIA_WORK_QUEUED.store(false, Ordering::Release);
        if !MEDIA_WORK_PENDING.load(Ordering::Acquire)
            || MEDIA_WORK_QUEUED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err()
        {
            return;
        }
    }
}

fn remove_departed_disk(name: &str) {
    let Some(detach) = block::registry::begin_forced_detach(name) else { return; };
    detach.wait_for_drain();
    let record = {
        let mut devices = DEVICES.lock_bh::<AhciBh>();
        devices.iter().position(|record| record.name.as_str() == name).map(|idx| devices.remove(idx))
    };
    if let Some(record) = record {
        let (host, port) = record.dev.watch_identity();
        record.dev.remove();
        let _ = install_watcher_after_detach(record.device_key, record.command_orig, host, port);
    }
    unregister_completion_if_idle();
}

fn probe_arrival(device_key: pci::Bdf, port: u32) {
    let watch = {
        let mut watches = WATCHES.lock_bh::<AhciBh>();
        watches.iter().position(|watch| watch.device_key == device_key && watch.port == port)
            .map(|idx| watches.remove(idx))
    };
    let Some(watch) = watch else { return; };
    let host = watch.host.clone();
    let command_orig = watch.command_orig;
    watch.release();
    if publish_port(device_key, command_orig, host.clone(), port).is_none() {
        let _ = install_watcher(device_key, command_orig, host, port);
    }
}

pub(super) fn remove_controller(device_key: pci::Bdf) -> (Vec<AhciRecord>, Vec<WatchRecord>) {
    let records = {
        let mut devices = DEVICES.lock_bh::<AhciBh>();
        let mut records = Vec::new();
        let mut i = 0;
        while i < devices.len() {
            if devices[i].device_key == device_key { records.push(devices.remove(i)); }
            else { i += 1; }
        }
        records
    };
    let watches = {
        let mut all = WATCHES.lock_bh::<AhciBh>();
        let mut watches = Vec::new();
        let mut i = 0;
        while i < all.len() {
            if all[i].device_key == device_key { watches.push(all.remove(i)); }
            else { i += 1; }
        }
        watches
    };
    (records, watches)
}

pub(super) fn controller_command_orig(device_key: pci::Bdf) -> Option<u16> {
    DEVICES.lock_bh::<AhciBh>().iter().find(|record| record.device_key == device_key)
        .map(|record| record.command_orig)
        .or_else(|| WATCHES.lock_bh::<AhciBh>().iter().find(|watch| watch.device_key == device_key)
            .map(|watch| watch.command_orig))
}

pub(super) fn controller_bound(device_key: pci::Bdf) -> bool {
    DEVICES.lock_bh::<AhciBh>().iter().any(|record| record.device_key == device_key)
        || WATCHES.lock_bh::<AhciBh>().iter().any(|watch| watch.device_key == device_key)
}

pub(super) fn unregister_completion_if_idle() {
    if DEVICES.lock_bh::<AhciBh>().is_empty() && WATCHES.lock_bh::<AhciBh>().is_empty() {
        let _ = block::completion::unregister(run_completion_bottom_half);
    }
}
