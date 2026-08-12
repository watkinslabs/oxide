//! IGC PCI probe, MSI lifecycle, and canonical net-device attachment.

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

use crate::{controller::Controller, regs};

const PAGE: u64 = 4096;
const MAX_DEVICES: usize = 8;
const ENDPOINT_FREE: u8 = 0;
const ENDPOINT_SETUP: u8 = 1;
const ENDPOINT_ACTIVE: u8 = 2;
const ENDPOINT_HANDLING: u8 = 3;

struct Endpoint { state: AtomicU8, mmio: AtomicU64, in_handler: AtomicU32, polling: AtomicBool }
impl Endpoint { const fn new() -> Self { Self { state: AtomicU8::new(ENDPOINT_FREE), mmio: AtomicU64::new(0), in_handler: AtomicU32::new(0), polling: AtomicBool::new(false) } } }
static ENDPOINTS: [Endpoint; MAX_DEVICES] = [const { Endpoint::new() }; MAX_DEVICES];

struct IgcNetDev { name: alloc::string::String, mac: net::MacAddr, ctrl: Spinlock<Option<Controller>, DriverLockClass>, iface: AtomicU64, generation: AtomicU64, removed: AtomicBool, endpoint: usize }
impl IgcNetDev { fn xmit_frame(&self, frame: &[u8]) -> net::NetResult<()> { self.ctrl.lock_bh::<sched::bh::SchedBh>().as_mut().ok_or(net::NetError::Eagain)?.xmit(frame).map_err(|_| net::NetError::Eagain) } }
fn link_address_for(next_hop: net::pkt::TxNextHop) -> Option<net::MacAddr> { match next_hop { net::pkt::TxNextHop::V4(ip) => ip.is_broadcast().then_some(net::MacAddr::BROADCAST), net::pkt::TxNextHop::V6 { addr, .. } => addr.is_multicast().then(|| net::ndp::multicast_ethernet(addr)) } }
impl net::NetDev for IgcNetDev {
    fn name(&self) -> &str { &self.name }
    fn mac(&self) -> net::MacAddr { self.mac }
    fn mtu(&self) -> u32 { 1500 }
    fn admin_up_changed(&self, up: bool) { if let Some(ctrl) = self.ctrl.lock_bh::<sched::bh::SchedBh>().as_ref() { if up { ctrl.start(); } else { ctrl.stop(); } } }
    fn retire_namespace(&self) { self.generation.fetch_add(1, Ordering::AcqRel); }
    fn resume_namespace(&self) {}
    fn namespace_drop_action(&self) -> net::NamespaceDropAction { net::NamespaceDropAction::MoveToInitial }
    fn xmit(&self, pkt: net::Pkt) -> net::NetResult<()> { self.xmit_observed(pkt, &mut |_, _, _| {}) }
    fn xmit_observed(&self, pkt: net::Pkt, observe: &mut dyn FnMut(&[u8], u16, usize)) -> net::NetResult<()> { let dst = pkt.next_hop.and_then(link_address_for).ok_or(net::NetError::Ehostunreach)?; self.xmit_l2_observed(pkt, dst, observe) }
    fn xmit_l2_observed(&self, pkt: net::Pkt, dst: net::MacAddr, observe: &mut dyn FnMut(&[u8], u16, usize)) -> net::NetResult<()> {
        let body = pkt.data(); if body.len() + 14 > crate::queue::ETH_MAX_FRAME { return Err(net::NetError::Emsgsize); }
        let mut frame = alloc::vec![0u8; body.len() + 14]; net::ethernet::EthHdr::write_to(dst, self.mac, pkt.proto, &mut frame[..14]); frame[14..].copy_from_slice(body); observe(&frame, pkt.proto, 14); self.xmit_frame(&frame)
    }
}

struct Record { bdf: pci::Bdf, command: u16, irq: pci_irq::Binding, dev: Arc<IgcNetDev> }
static DEVICES: Spinlock<Vec<Record>, DriverLockClass> = Spinlock::new(Vec::new());
static POLL_INSTALLED: AtomicBool = AtomicBool::new(false);
static NEXT_NAME: AtomicU32 = AtomicU32::new(0);

fn endpoint_claim(mmio: u64) -> Option<usize> { for (index, endpoint) in ENDPOINTS.iter().enumerate() { if endpoint.state.compare_exchange(ENDPOINT_FREE, ENDPOINT_SETUP, Ordering::AcqRel, Ordering::Acquire).is_ok() { endpoint.mmio.store(mmio, Ordering::Release); endpoint.in_handler.store(0, Ordering::Release); endpoint.polling.store(false, Ordering::Release); return Some(index); } } None }
fn endpoint_release(index: usize) { let endpoint = &ENDPOINTS[index]; endpoint.mmio.store(0, Ordering::Release); endpoint.polling.store(false, Ordering::Release); endpoint.state.store(ENDPOINT_FREE, Ordering::Release); }
fn hard_msi() { let _ = hard_irq(); }
fn hard_irq() -> bool {
    let mut pending = false;
    for endpoint in &ENDPOINTS {
        if endpoint.state.compare_exchange(ENDPOINT_ACTIVE, ENDPOINT_HANDLING, Ordering::AcqRel, Ordering::Acquire).is_err() { continue; }
        endpoint.in_handler.fetch_add(1, Ordering::AcqRel); let mmio = endpoint.mmio.load(Ordering::Acquire);
        // SAFETY: ACTIVE state retains the MMIO mapping until the in-handler count reaches zero on removal.
        let cause = unsafe { core::ptr::read_volatile((mmio + regs::ICR) as *const u32) };
        if cause != 0 && endpoint.polling.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            // SAFETY: active endpoint exclusively masks its IGC source before NET_RX owns deferred completion.
            unsafe { core::ptr::write_volatile((mmio + regs::IMC) as *mut u32, u32::MAX); }
            pending = true;
        }
        endpoint.in_handler.fetch_sub(1, Ordering::Release); endpoint.state.store(ENDPOINT_ACTIVE, Ordering::Release);
    }
    if pending { net::backlog::net_rx_schedule_ingress(); } pending
}
fn release_irq(irq: pci_irq::Binding, endpoint: usize) { while ENDPOINTS[endpoint].in_handler.load(Ordering::Acquire) != 0 { core::hint::spin_loop(); } endpoint_release(endpoint); irq.release(); }
fn poll_rx() {
    let devices: Vec<Arc<IgcNetDev>> = DEVICES.lock_bh::<sched::bh::SchedBh>().iter().map(|record| record.dev.clone()).collect(); let stack = net::sock::stack();
    for dev in devices {
        if dev.removed.load(Ordering::Acquire) { continue; } let raw = dev.iface.load(Ordering::Acquire); if raw == 0 { continue; }
        let iface = net::NetIfaceId::from_raw(raw as u32); let generation = dev.generation.load(Ordering::Acquire);
        let (frames, more) = match dev.ctrl.lock_bh::<sched::bh::SchedBh>().as_mut() { Some(ctrl) => ctrl.take_rx(net::backlog::DEV_RX_WEIGHT), None => continue };
        for frame in frames { let mut pkt = net::Pkt::new_with_headroom(net::DEFAULT_HEADROOM, frame.len()); pkt.data_mut().copy_from_slice(&frame); let _ = stack.netif_rx_ethernet(iface, generation, pkt, net::PacketRxMetadata::default()); }
        if more { net::backlog::net_rx_schedule_ingress(); }
        else if dev.ctrl.lock_bh::<sched::bh::SchedBh>().as_ref().is_some_and(Controller::complete_poll) { net::backlog::net_rx_schedule_ingress(); }
    }
}

fn enable_bus_master(bdf: pci::Bdf) -> Option<u16> { #[cfg(target_arch = "x86_64")] { hal_x86_64::pci::EcamPci::from_published().map(|reader| pci::enable_mem_bus_master(&reader, bdf)) } #[cfg(target_arch = "aarch64")] { hal_aarch64::pci::EcamPci::from_published().map(|reader| pci::enable_mem_bus_master(&reader, bdf)) } }
fn restore_bus_master(bdf: pci::Bdf, command: u16) { #[cfg(target_arch = "x86_64")] if let Some(reader) = hal_x86_64::pci::EcamPci::from_published() { let _ = pci::restore_mem_bus_master(&reader, bdf, command); } #[cfg(target_arch = "aarch64")] if let Some(reader) = hal_aarch64::pci::EcamPci::from_published() { let _ = pci::restore_mem_bus_master(&reader, bdf, command); } }
fn supported(device: &drv::Device) -> bool { device.bus == "pci" && device.class == regs::ETHERNET_CLASS && regs::supported(device.vendor_id, device.device_id) }
fn release_dev(dev: &IgcNetDev) { if let Some(controller) = dev.ctrl.lock_bh::<sched::bh::SchedBh>().take() { controller.release(); } }
fn remove_bdf(bdf: pci::Bdf) {
    let record = { let mut devices = DEVICES.lock_bh::<sched::bh::SchedBh>(); let Some(index) = devices.iter().position(|record| record.bdf == bdf) else { return; }; devices.remove(index) };
    record.dev.removed.store(true, Ordering::Release); let iface = record.dev.iface.swap(0, Ordering::AcqRel); if iface != 0 { let _ = net::sock::stack().unregister_iface_current(net::NetIfaceId::from_raw(iface as u32)); }
    if let Some(controller) = record.dev.ctrl.lock_bh::<sched::bh::SchedBh>().as_ref() { controller.stop(); }
    release_irq(record.irq, record.dev.endpoint); release_dev(&record.dev); restore_bus_master(record.bdf, record.command);
    if DEVICES.lock_bh::<sched::bh::SchedBh>().is_empty() && POLL_INSTALLED.swap(false, Ordering::AcqRel) { net::backlog::unregister_poll(poll_rx); }
}

pub struct IgcDriver;
impl drv::Driver for IgcDriver {
    fn name(&self) -> &'static str { "igc" }
    fn matches(&self, device: &drv::Device) -> bool { supported(device) }
    fn probe(&self, parent: &Arc<drv::Device>) -> drv::KResult<()> {
        let bdf = pci::parse_bdf_addr(&parent.addr).ok_or(drv::Error::ProbeFailed)?; let command = enable_bus_master(bdf).ok_or(drv::Error::ProbeFailed)?;
        let Some(resource) = parent.resources.iter().find(|resource| resource.bar == 0 && resource.flags & drv::IORESOURCE_MEM != 0) else { restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); };
        let bytes = resource.end.checked_sub(resource.start).and_then(|size| size.checked_add(1)).ok_or(drv::Error::ProbeFailed)?; let pages = (resource.start & (PAGE - 1)).checked_add(bytes).and_then(|size| size.checked_add(PAGE - 1)).and_then(|size| size.checked_div(PAGE)).ok_or(drv::Error::ProbeFailed)?;
        // SAFETY: matched BAR0 is exclusively owned by this driver until its remove path finishes.
        let map = unsafe { mmio_map::map_owned(resource.start & !(PAGE - 1), pages) }; let Some(controller) = Controller::bring_up(map, bdf) else { restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); };
        let Some(mac) = controller.mac() else { controller.release(); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); };
        let Some(endpoint) = endpoint_claim(controller.mmio_base()) else { controller.release(); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); };
        let irq = parent.msi_allowed().then(|| pci_irq::request(bdf, pci_irq::BarMapping { bar: 0, base_va: controller.mmio_base(), bytes: controller.mmio_bytes(), offset: 0 }, arch_irq::DeviceAction::Igc, hard_msi)).flatten();
        let Some(irq) = irq else { endpoint_release(endpoint); controller.release(); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); }; ENDPOINTS[endpoint].state.store(ENDPOINT_ACTIVE, Ordering::Release);
        let dev = Arc::new(IgcNetDev { name: alloc::format!("eth{}", NEXT_NAME.fetch_add(1, Ordering::Relaxed)), mac: net::MacAddr(mac), ctrl: Spinlock::new(Some(controller)), iface: AtomicU64::new(0), generation: AtomicU64::new(0), removed: AtomicBool::new(false), endpoint });
        let stack = net::sock::stack(); let namespace = net::net_ns::initial_namespace(); let owner = dev.clone() as Arc<dyn net::NetDev>;
        let Some(reg) = stack.prepare_parented_iface(owner, parent.clone(), &namespace) else { release_irq(irq, endpoint); release_dev(&dev); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); };
        dev.iface.store(reg.id().raw() as u64, Ordering::Release); dev.generation.store(reg.generation(), Ordering::Release);
        if !stack.publish_iface(reg) { dev.iface.store(0, Ordering::Release); release_irq(irq, endpoint); release_dev(&dev); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); }
        if !POLL_INSTALLED.swap(true, Ordering::AcqRel) && !net::backlog::register_poll(poll_rx) { POLL_INSTALLED.store(false, Ordering::Release); let _ = stack.unregister_iface_current(net::NetIfaceId::from_raw(dev.iface.swap(0, Ordering::AcqRel) as u32)); release_irq(irq, endpoint); release_dev(&dev); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); }
        DEVICES.lock_bh::<sched::bh::SchedBh>().push(Record { bdf, command, irq, dev }); Ok(())
    }
    fn remove(&self, device: &drv::Device) { if let Some(bdf) = pci::parse_bdf_addr(&device.addr) { remove_bdf(bdf); } }
    fn shutdown(&self, device: &drv::Device) { if let Some(bdf) = pci::parse_bdf_addr(&device.addr) { remove_bdf(bdf); } }
}
pub static IGC_DRIVER: IgcDriver = IgcDriver;
