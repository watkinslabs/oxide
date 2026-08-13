//! Native AQC113 PCI ownership, interrupt, and bounded receive poll.

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

use crate::{atl2_controller::Controller, atl2_regs as regs};

const PAGE: u64 = 4096;
const ETHERNET_CLASS: u32 = 0x02_00_00;
const VENDOR_AQUANTIA: u16 = 0x1d6a;
const DEVICE_AQC113: u16 = 0x04c0;
const MAX_DEVICES: usize = 8;
const ENDPOINT_FREE: u8 = 0;
const ENDPOINT_SETUP: u8 = 1;
const ENDPOINT_ACTIVE: u8 = 2;
const ENDPOINT_HANDLING: u8 = 3;

struct Endpoint { state: AtomicU8, mmio: AtomicU64, in_handler: AtomicU32, polling: AtomicBool }
impl Endpoint { const fn new() -> Self { Self { state: AtomicU8::new(ENDPOINT_FREE), mmio: AtomicU64::new(0), in_handler: AtomicU32::new(0), polling: AtomicBool::new(false) } } }
static ENDPOINTS: [Endpoint; MAX_DEVICES] = [const { Endpoint::new() }; MAX_DEVICES];

struct AtlanticNetDev {
    name: alloc::string::String, mac: net::MacAddr, controller: Spinlock<Option<Controller>, DriverLockClass>,
    iface: AtomicU64, generation: AtomicU64, removed: AtomicBool, endpoint: usize, irq_control: u32,
}
impl AtlanticNetDev {
    fn xmit_frame(&self, frame: &[u8]) -> net::NetResult<()> {
        self.controller.lock_bh::<sched::bh::SchedBh>().as_mut().ok_or(net::NetError::Eagain)?.xmit(frame).map_err(|_| net::NetError::Eagain)
    }
}
fn link_address_for(next_hop: net::pkt::TxNextHop) -> Option<net::MacAddr> {
    match next_hop { net::pkt::TxNextHop::V4(ip) => ip.is_broadcast().then_some(net::MacAddr::BROADCAST), net::pkt::TxNextHop::V6 { addr, .. } => addr.is_multicast().then(|| net::ndp::multicast_ethernet(addr)) }
}
impl net::NetDev for AtlanticNetDev {
    fn name(&self) -> &str { &self.name }
    fn mac(&self) -> net::MacAddr { self.mac }
    fn mtu(&self) -> u32 { 1500 }
    fn admin_up_changed(&self, up: bool) {
        let mut guard = self.controller.lock_bh::<sched::bh::SchedBh>(); let Some(controller) = guard.as_mut() else { return; };
        if up { controller.start(); controller.enable_irq(self.irq_control); } else { controller.stop(); }
    }
    fn retire_namespace(&self) { self.generation.fetch_add(1, Ordering::AcqRel); }
    fn resume_namespace(&self) {}
    fn namespace_drop_action(&self) -> net::NamespaceDropAction { net::NamespaceDropAction::MoveToInitial }
    fn xmit(&self, pkt: net::Pkt) -> net::NetResult<()> { self.xmit_observed(pkt, &mut |_, _, _| {}) }
    fn xmit_observed(&self, pkt: net::Pkt, observe: &mut dyn FnMut(&[u8], u16, usize)) -> net::NetResult<()> {
        let dst = pkt.next_hop.and_then(link_address_for).ok_or(net::NetError::Ehostunreach)?; self.xmit_l2_observed(pkt, dst, observe)
    }
    fn xmit_l2_observed(&self, pkt: net::Pkt, dst: net::MacAddr, observe: &mut dyn FnMut(&[u8], u16, usize)) -> net::NetResult<()> {
        let body = pkt.data(); if body.len() + 14 > crate::atl2_queue::ETH_MAX_FRAME { return Err(net::NetError::Emsgsize); }
        let mut frame = alloc::vec![0u8; body.len() + 14]; net::ethernet::EthHdr::write_to(dst, self.mac, pkt.proto, &mut frame[..14]); frame[14..].copy_from_slice(body); observe(&frame, pkt.proto, 14); self.xmit_frame(&frame)
    }
}

fn endpoint_claim(mmio: u64) -> Option<usize> {
    for (index, endpoint) in ENDPOINTS.iter().enumerate() {
        if endpoint.state.compare_exchange(ENDPOINT_FREE, ENDPOINT_SETUP, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            endpoint.mmio.store(mmio, Ordering::Release); endpoint.in_handler.store(0, Ordering::Release); endpoint.polling.store(false, Ordering::Release); return Some(index);
        }
    } None
}
fn endpoint_release(index: usize) { let endpoint = &ENDPOINTS[index]; endpoint.mmio.store(0, Ordering::Release); endpoint.polling.store(false, Ordering::Release); endpoint.state.store(ENDPOINT_FREE, Ordering::Release); }
fn hard_msi() { let _ = hard_irq(); }
fn hard_irq() -> bool {
    let mut pending = false;
    for endpoint in &ENDPOINTS {
        if endpoint.state.compare_exchange(ENDPOINT_ACTIVE, ENDPOINT_HANDLING, Ordering::AcqRel, Ordering::Acquire).is_err() { continue; }
        endpoint.in_handler.fetch_add(1, Ordering::AcqRel); let mmio = endpoint.mmio.load(Ordering::Acquire);
        // SAFETY: an ACTIVE endpoint retains this mapped register file until its handler count reaches zero.
        let status = unsafe { core::ptr::read_volatile((mmio + regs::IRQ_STATUS) as *const u32) };
        if status != 0 && endpoint.polling.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            // SAFETY: this handler exclusively masks and acknowledges its live hardware source before deferred polling.
            unsafe { core::ptr::write_volatile((mmio + regs::IRQ_MASK_CLEAR) as *mut u32, regs::IRQ_MASK_ALL); core::ptr::write_volatile((mmio + regs::IRQ_STATUS_CLEAR) as *mut u32, status); }
            pending = true;
        } else if status != 0 {
            // SAFETY: AQC113 interrupt status is write-one-to-clear and this endpoint still owns the source.
            unsafe { core::ptr::write_volatile((mmio + regs::IRQ_STATUS_CLEAR) as *mut u32, status); }
        }
        endpoint.in_handler.fetch_sub(1, Ordering::Release); endpoint.state.store(ENDPOINT_ACTIVE, Ordering::Release);
    }
    if pending { net::backlog::net_rx_schedule_ingress(); } pending
}
fn bind_pci_message(bdf: pci::Bdf, endpoint: usize, controller: &Controller) -> Option<pci_irq::Binding> {
    let binding = pci_irq::request(bdf, pci_irq::BarMapping { bar: 0, base_va: controller.mmio_base(), bytes: controller.mmio_bytes(), offset: 0 }, arch_irq::DeviceAction::Atlantic, hard_msi)?;
    ENDPOINTS[endpoint].state.store(ENDPOINT_ACTIVE, Ordering::Release); Some(binding)
}
fn release_irq(binding: pci_irq::Binding, endpoint: usize) { while ENDPOINTS[endpoint].in_handler.load(Ordering::Acquire) != 0 { core::hint::spin_loop(); } endpoint_release(endpoint); binding.release(); }

struct Record { bdf: pci::Bdf, command: u16, irq: pci_irq::Binding, dev: Arc<AtlanticNetDev> }
static DEVICES: Spinlock<Vec<Record>, DriverLockClass> = Spinlock::new(Vec::new());
static POLL_INSTALLED: AtomicBool = AtomicBool::new(false);
static NEXT_NAME: AtomicU32 = AtomicU32::new(0);
fn release_dev(dev: &AtlanticNetDev) { if let Some(controller) = dev.controller.lock_bh::<sched::bh::SchedBh>().take() { controller.release(); } }
fn poll_rx() {
    let devices: Vec<Arc<AtlanticNetDev>> = DEVICES.lock_bh::<sched::bh::SchedBh>().iter().map(|record| record.dev.clone()).collect(); let stack = net::sock::stack();
    for dev in devices {
        if dev.removed.load(Ordering::Acquire) { continue; } let raw = dev.iface.load(Ordering::Acquire); if raw == 0 { continue; }
        let iface = net::NetIfaceId::from_raw(raw as u32); let generation = dev.generation.load(Ordering::Acquire);
        let (frames, more) = match dev.controller.lock_bh::<sched::bh::SchedBh>().as_mut() { Some(controller) => controller.take_rx(net::backlog::DEV_RX_WEIGHT), None => continue };
        for frame in frames { let mut pkt = net::Pkt::new_with_headroom(net::DEFAULT_HEADROOM, frame.len()); pkt.data_mut().copy_from_slice(&frame); let _ = stack.netif_rx_ethernet(iface, generation, pkt, net::PacketRxMetadata::default()); }
        if more { net::backlog::net_rx_schedule_ingress(); }
        else { let mut guard = dev.controller.lock_bh::<sched::bh::SchedBh>(); if let Some(controller) = guard.as_mut() { if controller.irq_status() != 0 { net::backlog::net_rx_schedule_ingress(); } else { ENDPOINTS[dev.endpoint].polling.store(false, Ordering::Release); controller.enable_irq(dev.irq_control); } } }
    }
}
fn enable_bus_master(bdf: pci::Bdf) -> Option<u16> { #[cfg(target_arch = "x86_64")] { hal_x86_64::pci::EcamPci::from_published().map(|reader| pci::enable_mem_bus_master(&reader, bdf)) } #[cfg(target_arch = "aarch64")] { hal_aarch64::pci::EcamPci::from_published().map(|reader| pci::enable_mem_bus_master(&reader, bdf)) } }
fn restore_bus_master(bdf: pci::Bdf, command: u16) { #[cfg(target_arch = "x86_64")] if let Some(reader) = hal_x86_64::pci::EcamPci::from_published() { let _ = pci::restore_mem_bus_master(&reader, bdf, command); } #[cfg(target_arch = "aarch64")] if let Some(reader) = hal_aarch64::pci::EcamPci::from_published() { let _ = pci::restore_mem_bus_master(&reader, bdf, command); } }
fn supported(device: &drv::Device) -> bool { device.bus == "pci" && device.class == ETHERNET_CLASS && device.vendor_id == VENDOR_AQUANTIA && device.device_id == DEVICE_AQC113 }
fn remove_bdf(bdf: pci::Bdf) {
    let record = { let mut devices = DEVICES.lock_bh::<sched::bh::SchedBh>(); let Some(index) = devices.iter().position(|record| record.bdf == bdf) else { return; }; devices.remove(index) };
    record.dev.removed.store(true, Ordering::Release); let iface = record.dev.iface.swap(0, Ordering::AcqRel); if iface != 0 { let _ = net::sock::stack().unregister_iface_current(net::NetIfaceId::from_raw(iface as u32)); }
    if let Some(controller) = record.dev.controller.lock_bh::<sched::bh::SchedBh>().as_mut() { controller.stop(); }
    release_irq(record.irq, record.dev.endpoint); release_dev(&record.dev); restore_bus_master(record.bdf, record.command);
    if DEVICES.lock_bh::<sched::bh::SchedBh>().is_empty() && POLL_INSTALLED.swap(false, Ordering::AcqRel) { net::backlog::unregister_poll(poll_rx); }
}

pub struct AtlanticDriver;
impl drv::Driver for AtlanticDriver {
    fn name(&self) -> &'static str { "atlantic" }
    fn matches(&self, device: &drv::Device) -> bool { supported(device) }
    fn probe(&self, device: &Arc<drv::Device>) -> drv::KResult<()> {
        let bdf = pci::parse_bdf_addr(&device.addr).ok_or(drv::Error::ProbeFailed)?; let command = enable_bus_master(bdf).ok_or(drv::Error::ProbeFailed)?;
        let Some(bar) = device.resources.iter().find(|resource| resource.bar == 0 && resource.flags & drv::IORESOURCE_MEM != 0) else { restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); };
        let bytes = bar.end.checked_sub(bar.start).and_then(|size| size.checked_add(1)).ok_or(drv::Error::ProbeFailed)?; let pages = (bar.start & (PAGE - 1)).checked_add(bytes).and_then(|size| size.checked_add(PAGE - 1)).and_then(|size| size.checked_div(PAGE)).ok_or(drv::Error::ProbeFailed)?;
        // SAFETY: the matched BAR0 remains exclusively owned until the matching remove transaction unmaps it.
        let map = unsafe { mmio_map::map_owned(bar.start & !(PAGE - 1), pages) }; let Some(mut controller) = Controller::bring_up(map, bdf, device.dma_mask()) else { restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); };
        let Some(mac) = controller.mac().map(net::MacAddr) else { controller.release(); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); };
        let Some(endpoint) = endpoint_claim(controller.mmio_base()) else { controller.release(); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); };
        let Some(irq) = bind_pci_message(bdf, endpoint, &controller) else { endpoint_release(endpoint); controller.release(); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); };
        let irq_control = match pci_irq::delivery(irq) { pci_irq::Delivery::Msi => regs::IRQ_GLOBAL_MSI_SINGLE, pci_irq::Delivery::Msix => regs::IRQ_GLOBAL_MSIX_SINGLE, pci_irq::Delivery::Intx => regs::IRQ_GLOBAL_INTX_SINGLE };
        let dev = Arc::new(AtlanticNetDev { name: alloc::format!("eth{}", NEXT_NAME.fetch_add(1, Ordering::Relaxed)), mac, controller: Spinlock::new(Some(controller)), iface: AtomicU64::new(0), generation: AtomicU64::new(0), removed: AtomicBool::new(false), endpoint, irq_control });
        let stack = net::sock::stack(); let namespace = net::net_ns::initial_namespace(); let owner = dev.clone() as Arc<dyn net::NetDev>;
        let Some(reg) = stack.prepare_parented_iface(owner, device.clone(), &namespace) else { release_irq(irq, endpoint); release_dev(&dev); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); };
        dev.iface.store(reg.id().raw() as u64, Ordering::Release); dev.generation.store(reg.generation(), Ordering::Release);
        if !stack.publish_iface(reg) { dev.iface.store(0, Ordering::Release); release_irq(irq, endpoint); release_dev(&dev); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); }
        if !POLL_INSTALLED.swap(true, Ordering::AcqRel) && !net::backlog::register_poll(poll_rx) { POLL_INSTALLED.store(false, Ordering::Release); let _ = stack.unregister_iface_current(net::NetIfaceId::from_raw(dev.iface.swap(0, Ordering::AcqRel) as u32)); release_irq(irq, endpoint); release_dev(&dev); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); }
        DEVICES.lock_bh::<sched::bh::SchedBh>().push(Record { bdf, command, irq, dev }); Ok(())
    }
    fn remove(&self, device: &drv::Device) { if let Some(bdf) = pci::parse_bdf_addr(&device.addr) { remove_bdf(bdf); } }
    fn shutdown(&self, device: &drv::Device) { if let Some(bdf) = pci::parse_bdf_addr(&device.addr) { remove_bdf(bdf); } }
}
pub static ATLANTIC_DRIVER: AtlanticDriver = AtlanticDriver;
