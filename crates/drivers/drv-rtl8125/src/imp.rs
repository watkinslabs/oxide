//! Native RTL8125 PCI ownership, interrupt, and bounded receive poll.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

use crate::{bringup::{self, Op}, dma_owner::Rings, regs};

const PAGE: u64 = 4096;
const ETHERNET_CLASS: u32 = 0x02_00_00;
const RESET_WAIT_NS: u64 = 10_000_000;
const MAX_DEVICES: usize = 8;
const ENDPOINT_FREE: u8 = 0;
const ENDPOINT_SETUP: u8 = 1;
const ENDPOINT_ACTIVE: u8 = 2;
const ENDPOINT_HANDLING: u8 = 3;

struct Endpoint { state: AtomicU8, mmio: AtomicU64, in_handler: AtomicU32, polling: AtomicBool }
impl Endpoint {
    const fn new() -> Self { Self { state: AtomicU8::new(ENDPOINT_FREE), mmio: AtomicU64::new(0), in_handler: AtomicU32::new(0), polling: AtomicBool::new(false) } }
}
static ENDPOINTS: [Endpoint; MAX_DEVICES] = [const { Endpoint::new() }; MAX_DEVICES];

struct Controller { map: mmio_map::Mapping, rings: Rings, rx_next: usize, tx_next: usize }
impl Controller {
    fn read8(&self, offset: u64) -> u8 { // SAFETY: this controller exclusively owns its byte register window.
        unsafe { core::ptr::read_volatile((self.map.base_va() + offset) as *const u8) } }
    fn read32(&self, offset: u64) -> u32 { // SAFETY: this controller exclusively owns its aligned register window.
        unsafe { core::ptr::read_volatile((self.map.base_va() + offset) as *const u32) } }
    fn write8(&self, offset: u64, value: u8) { // SAFETY: this controller exclusively owns its byte register window.
        unsafe { core::ptr::write_volatile((self.map.base_va() + offset) as *mut u8, value); } }
    fn write16(&self, offset: u64, value: u16) { // SAFETY: this controller exclusively owns its aligned register window.
        unsafe { core::ptr::write_volatile((self.map.base_va() + offset) as *mut u16, value); } }
    fn write32(&self, offset: u64, value: u32) { // SAFETY: this controller exclusively owns its aligned register window.
        unsafe { core::ptr::write_volatile((self.map.base_va() + offset) as *mut u32, value); } }
    fn execute(&self, op: Op) { match op { Op::Write8(o, v) => self.write8(o, v), Op::Write16(o, v) => self.write16(o, v), Op::Write32(o, v) => self.write32(o, v), Op::Read32(o) => { let _ = self.read32(o); } } }
    fn start(&self) -> bool {
        let xid = self.read32(regs::TX_CONFIG);
        let Some(plan) = bringup::start_plan(xid, self.rings.rx_desc_dma, self.rings.tx_desc_dma) else { return false; };
        if !self.rings.initialize_rx() || !self.rings.initialize_tx() { return false; }
        for (index, op) in plan.into_iter().enumerate() { self.execute(op); if index == 1 && !self.wait_reset() { return false; } }
        true
    }
    fn wait_reset(&self) -> bool {
        let deadline = sched::deadline::clock::now_ns().saturating_add(RESET_WAIT_NS);
        while self.read8(regs::CHIP_CMD) & regs::CMD_RESET != 0 {
            if sched::deadline::clock::now_ns() >= deadline { return false; }
            core::hint::spin_loop();
        }
        true
    }
    fn enable_interrupts(&self) { self.write32(regs::INTR_STATUS, u32::MAX); self.write32(regs::INTR_MASK, regs::INTR_DEFAULT as u32); let _ = self.read32(regs::INTR_MASK); }
    fn mac(&self) -> Option<net::MacAddr> {
        let value = self.read32(regs::MAC0); let high = self.read32(regs::MAC0 + 4);
        let mac = [value as u8, (value >> 8) as u8, (value >> 16) as u8, (value >> 24) as u8, high as u8, (high >> 8) as u8];
        regs::mac_valid(mac).then_some(net::MacAddr(mac))
    }
    fn stop(&self) { self.write32(regs::INTR_MASK, 0); self.write8(regs::CHIP_CMD, 0); let _ = self.read32(regs::TX_CONFIG); }
    fn xmit(&mut self, frame: &[u8]) -> net::NetResult<()> {
        if !(14..=regs::ETH_MAX_FRAME).contains(&frame.len()) { return Err(net::NetError::Emsgsize); }
        let index = self.tx_next; let Some((desc_va, data_va)) = self.rings.tx_slot(index) else { return Err(net::NetError::Eagain); };
        pmm::dma::invalidate_from_device(desc_va, core::mem::size_of::<regs::TxDesc>());
        // SAFETY: the TX lock exclusively owns this bounded descriptor slot.
        let desc = unsafe { &mut *(desc_va as *mut regs::TxDesc) };
        if desc.opts1 & regs::DESC_OWN != 0 { return Err(net::NetError::Eagain); }
        // SAFETY: the frame was bounded to this retained per-descriptor buffer.
        unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), data_va as *mut u8, frame.len()); }
        pmm::dma::clean_to_device(data_va, frame.len());
        desc.opts1 = regs::DESC_OWN | regs::DESC_FIRST | regs::DESC_LAST | frame.len() as u32 | if index + 1 == regs::RING_COUNT { regs::DESC_RING_END } else { 0 };
        desc.opts2 = 0;
        pmm::dma::clean_to_device(desc_va, core::mem::size_of::<regs::TxDesc>());
        core::sync::atomic::fence(Ordering::Release);
        self.tx_next = (index + 1) % regs::RING_COUNT; self.write8(regs::TX_POLL, regs::TX_POLL_NORMAL); Ok(())
    }
    fn take_rx(&mut self) -> (Vec<Vec<u8>>, bool) {
        let mut frames = Vec::new();
        while frames.len() < net::backlog::DEV_RX_WEIGHT {
            let index = self.rx_next; let Some((desc_va, data_va)) = self.rings.rx_slot(index) else { break; };
            pmm::dma::invalidate_from_device(desc_va, core::mem::size_of::<regs::RxDesc>());
            // SAFETY: NET_RX serializes access to this bounded RX descriptor slot.
            let desc = unsafe { &mut *(desc_va as *mut regs::RxDesc) };
            core::sync::atomic::fence(Ordering::Acquire);
            let opts1 = desc.opts1;
            if opts1 & regs::DESC_OWN != 0 { return (frames, false); }
            if let Some(length) = regs::received_frame_length(opts1) {
                pmm::dma::invalidate_from_device(data_va, length);
                // SAFETY: a complete descriptor bounds the bytes to its retained RX buffer.
                frames.push(unsafe { core::slice::from_raw_parts(data_va as *const u8, length) }.to_vec());
            }
            desc.opts2 = 0;
            core::sync::atomic::fence(Ordering::Release);
            desc.opts1 = regs::DESC_OWN | regs::BUFFER_BYTES as u32 | if index + 1 == regs::RING_COUNT { regs::DESC_RING_END } else { 0 };
            pmm::dma::clean_to_device(desc_va, core::mem::size_of::<regs::RxDesc>());
            self.rx_next = (index + 1) % regs::RING_COUNT;
        }
        let Some((desc_va, _)) = self.rings.rx_slot(self.rx_next) else { return (frames, false); };
        pmm::dma::invalidate_from_device(desc_va, core::mem::size_of::<regs::RxDesc>());
        // SAFETY: `rx_next` is always reduced modulo the retained ring size.
        let more = unsafe { (*(desc_va as *const regs::RxDesc)).opts1 & regs::DESC_OWN == 0 };
        (frames, more)
    }
    fn release(mut self) { self.stop(); self.rings.release(); self.map.unmap(); }
}

struct RtlNetDev { name: alloc::string::String, mac: net::MacAddr, controller: Spinlock<Option<Controller>, DriverLockClass>, iface: AtomicU64, generation: AtomicU64, removed: AtomicBool, endpoint: usize }
impl RtlNetDev { fn xmit_frame(&self, frame: &[u8]) -> net::NetResult<()> { self.controller.lock_bh::<sched::bh::SchedBh>().as_mut().ok_or(net::NetError::Eagain)?.xmit(frame) } }
fn link_address_for(next_hop: net::pkt::TxNextHop) -> Option<net::MacAddr> { match next_hop { net::pkt::TxNextHop::V4(ip) => ip.is_broadcast().then_some(net::MacAddr::BROADCAST), net::pkt::TxNextHop::V6 { addr, .. } => addr.is_multicast().then(|| net::ndp::multicast_ethernet(addr)) } }
impl net::NetDev for RtlNetDev {
    fn name(&self) -> &str { &self.name }
    fn mac(&self) -> net::MacAddr { self.mac }
    fn mtu(&self) -> u32 { 1500 }
    fn admin_up_changed(&self, _up: bool) {}
    fn retire_namespace(&self) { self.generation.fetch_add(1, Ordering::AcqRel); }
    fn resume_namespace(&self) {}
    fn namespace_drop_action(&self) -> net::NamespaceDropAction { net::NamespaceDropAction::MoveToInitial }
    fn xmit(&self, pkt: net::Pkt) -> net::NetResult<()> { self.xmit_observed(pkt, &mut |_, _, _| {}) }
    fn xmit_observed(&self, pkt: net::Pkt, observe: &mut dyn FnMut(&[u8], u16, usize)) -> net::NetResult<()> { let dst = pkt.next_hop.and_then(link_address_for).ok_or(net::NetError::Ehostunreach)?; self.xmit_l2_observed(pkt, dst, observe) }
    fn xmit_l2_observed(&self, pkt: net::Pkt, dst: net::MacAddr, observe: &mut dyn FnMut(&[u8], u16, usize)) -> net::NetResult<()> {
        let body = pkt.data(); if body.len() + 14 > regs::ETH_MAX_FRAME { return Err(net::NetError::Emsgsize); }
        let mut frame = alloc::vec![0u8; body.len() + 14]; net::ethernet::EthHdr::write_to(dst, self.mac, pkt.proto, &mut frame[..14]); frame[14..].copy_from_slice(body); observe(&frame, pkt.proto, 14); self.xmit_frame(&frame)
    }
}

fn endpoint_claim(mmio: u64) -> Option<usize> { for (index, endpoint) in ENDPOINTS.iter().enumerate() { if endpoint.state.compare_exchange(ENDPOINT_FREE, ENDPOINT_SETUP, Ordering::AcqRel, Ordering::Acquire).is_ok() { endpoint.mmio.store(mmio, Ordering::Release); endpoint.in_handler.store(0, Ordering::Release); endpoint.polling.store(false, Ordering::Release); return Some(index); } } None }
fn endpoint_release(index: usize) { let endpoint = &ENDPOINTS[index]; endpoint.mmio.store(0, Ordering::Release); endpoint.polling.store(false, Ordering::Release); endpoint.state.store(ENDPOINT_FREE, Ordering::Release); }
fn hard_msi() { let _ = hard_irq(); }
fn hard_irq() -> bool {
    let mut pending = false;
    for endpoint in &ENDPOINTS {
        if endpoint.state.compare_exchange(ENDPOINT_ACTIVE, ENDPOINT_HANDLING, Ordering::AcqRel, Ordering::Acquire).is_err() { continue; }
        endpoint.in_handler.fetch_add(1, Ordering::AcqRel);
        let mmio = endpoint.mmio.load(Ordering::Acquire);
        // SAFETY: ACTIVE endpoint ownership keeps this mapped until the in-handler count drains.
        let status = unsafe { core::ptr::read_volatile((mmio + regs::INTR_STATUS) as *const u32) };
        if status & regs::INTR_DEFAULT as u32 != 0 && endpoint.polling.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            // SAFETY: the active endpoint owns the source and masks it before NET_RX takes completion ownership.
            unsafe { core::ptr::write_volatile((mmio + regs::INTR_MASK) as *mut u32, 0); core::ptr::write_volatile((mmio + regs::INTR_STATUS) as *mut u32, status); }
            pending = true;
        } else if status != 0 { // SAFETY: RTL8125 status is write-one-to-clear.
            unsafe { core::ptr::write_volatile((mmio + regs::INTR_STATUS) as *mut u32, status); }
        }
        endpoint.in_handler.fetch_sub(1, Ordering::Release); endpoint.state.store(ENDPOINT_ACTIVE, Ordering::Release);
    }
    if pending { net::backlog::net_rx_schedule_ingress(); }
    pending
}
fn bind_pci_message(bdf: pci::Bdf, endpoint: usize, controller: &Controller) -> Option<pci_irq::Binding> {
    let binding = pci_irq::request(bdf, pci_irq::BarMapping { bar: 0, base_va: controller.map.base_va(), bytes: controller.map.bytes(), offset: 0 }, arch_irq::DeviceAction::R8169, hard_msi)?;
    ENDPOINTS[endpoint].state.store(ENDPOINT_ACTIVE, Ordering::Release); Some(binding)
}
fn release_irq(binding: pci_irq::Binding, endpoint: usize) { while ENDPOINTS[endpoint].in_handler.load(Ordering::Acquire) != 0 { core::hint::spin_loop(); } endpoint_release(endpoint); binding.release(); }
fn complete_poll(endpoint: usize, controller: &Controller) -> bool {
    let status = controller.read32(regs::INTR_STATUS);
    if status & regs::INTR_DEFAULT as u32 != 0 { controller.write32(regs::INTR_STATUS, status); return true; }
    ENDPOINTS[endpoint].polling.store(false, Ordering::Release); controller.enable_interrupts(); false
}

struct Record { bdf: pci::Bdf, command: u16, irq: pci_irq::Binding, dev: Arc<RtlNetDev> }
static DEVICES: Spinlock<Vec<Record>, DriverLockClass> = Spinlock::new(Vec::new());
static POLL_INSTALLED: AtomicBool = AtomicBool::new(false);
static NEXT_NAME: AtomicU32 = AtomicU32::new(0);
fn release_dev(dev: &RtlNetDev) { if let Some(controller) = dev.controller.lock_bh::<sched::bh::SchedBh>().take() { controller.release(); } }
fn poll_rx() {
    let devices: Vec<Arc<RtlNetDev>> = DEVICES.lock_bh::<sched::bh::SchedBh>().iter().map(|record| record.dev.clone()).collect();
    let stack = net::sock::stack();
    for dev in devices {
        if dev.removed.load(Ordering::Acquire) { continue; }
        let raw = dev.iface.load(Ordering::Acquire); if raw == 0 { continue; }
        let iface = net::NetIfaceId::from_raw(raw as u32); let generation = dev.generation.load(Ordering::Acquire);
        let (frames, more) = match dev.controller.lock_bh::<sched::bh::SchedBh>().as_mut() { Some(controller) => controller.take_rx(), None => continue };
        for frame in frames { let mut pkt = net::Pkt::new_with_headroom(net::DEFAULT_HEADROOM, frame.len()); pkt.data_mut().copy_from_slice(&frame); let _ = stack.netif_rx_ethernet(iface, generation, pkt, net::PacketRxMetadata::default()); }
        if more { net::backlog::net_rx_schedule_ingress(); }
        else if let Some(controller) = dev.controller.lock_bh::<sched::bh::SchedBh>().as_ref() { if complete_poll(dev.endpoint, controller) { net::backlog::net_rx_schedule_ingress(); } }
    }
}

fn enable_bus_master(bdf: pci::Bdf) -> Option<u16> { #[cfg(target_arch = "x86_64")] { hal_x86_64::pci::EcamPci::from_published().map(|reader| pci::enable_mem_bus_master(&reader, bdf)) } #[cfg(target_arch = "aarch64")] { hal_aarch64::pci::EcamPci::from_published().map(|reader| pci::enable_mem_bus_master(&reader, bdf)) } }
fn restore_bus_master(bdf: pci::Bdf, command: u16) { #[cfg(target_arch = "x86_64")] if let Some(reader) = hal_x86_64::pci::EcamPci::from_published() { let _ = pci::restore_mem_bus_master(&reader, bdf, command); } #[cfg(target_arch = "aarch64")] if let Some(reader) = hal_aarch64::pci::EcamPci::from_published() { let _ = pci::restore_mem_bus_master(&reader, bdf, command); } }
fn supported(device: &drv::Device) -> bool { device.bus == "pci" && device.class == ETHERNET_CLASS && regs::is_rtl8125(device.vendor_id, device.device_id) }
fn remove_bdf(bdf: pci::Bdf) {
    let record = { let mut devices = DEVICES.lock_bh::<sched::bh::SchedBh>(); let Some(index) = devices.iter().position(|record| record.bdf == bdf) else { return; }; devices.remove(index) };
    record.dev.removed.store(true, Ordering::Release); let iface = record.dev.iface.swap(0, Ordering::AcqRel); if iface != 0 { let _ = net::sock::stack().unregister_iface_current(net::NetIfaceId::from_raw(iface as u32)); }
    if let Some(controller) = record.dev.controller.lock_bh::<sched::bh::SchedBh>().as_ref() { controller.stop(); }
    release_irq(record.irq, record.dev.endpoint); release_dev(&record.dev); restore_bus_master(record.bdf, record.command);
    if DEVICES.lock_bh::<sched::bh::SchedBh>().is_empty() && POLL_INSTALLED.swap(false, Ordering::AcqRel) { net::backlog::unregister_poll(poll_rx); }
}

pub struct Rtl8125Driver;
impl drv::Driver for Rtl8125Driver {
    fn name(&self) -> &'static str { "r8169" }
    fn matches(&self, device: &drv::Device) -> bool { supported(device) }
    fn probe(&self, device: &Arc<drv::Device>) -> drv::KResult<()> {
        let bdf = pci::parse_bdf_addr(&device.addr).ok_or(drv::Error::ProbeFailed)?; let command = enable_bus_master(bdf).ok_or(drv::Error::ProbeFailed)?;
        let Some(bar) = device.resources.iter().find(|resource| resource.bar == 0 && resource.flags & drv::IORESOURCE_MEM != 0) else { restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); };
        let bytes = bar.end.checked_sub(bar.start).and_then(|size| size.checked_add(1)).ok_or(drv::Error::ProbeFailed)?; let pages = (bar.start & (PAGE - 1)).checked_add(bytes).and_then(|size| size.checked_add(PAGE - 1)).and_then(|size| size.checked_div(PAGE)).ok_or(drv::Error::ProbeFailed)?;
        // SAFETY: this matched BAR0 is owned exclusively until the remove path unmaps it.
        let mut map = unsafe { mmio_map::map_owned(bar.start & !(PAGE - 1), pages) }; let Some(rings) = Rings::allocate(bdf) else { map.unmap(); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); };
        let controller = Controller { map, rings, rx_next: 0, tx_next: 0 }; let Some(mac) = controller.mac() else { controller.release(); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); };
        let Some(endpoint) = endpoint_claim(controller.map.base_va()) else { controller.release(); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); };
        let Some(irq) = bind_pci_message(bdf, endpoint, &controller) else { endpoint_release(endpoint); controller.release(); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); };
        if !controller.start() { release_irq(irq, endpoint); controller.release(); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); }
        let dev = Arc::new(RtlNetDev { name: alloc::format!("eth{}", NEXT_NAME.fetch_add(1, Ordering::Relaxed)), mac, controller: Spinlock::new(Some(controller)), iface: AtomicU64::new(0), generation: AtomicU64::new(0), removed: AtomicBool::new(false), endpoint });
        let stack = net::sock::stack(); let namespace = net::net_ns::initial_namespace(); let owner = dev.clone() as Arc<dyn net::NetDev>;
        let Some(reg) = stack.prepare_parented_iface(owner, device.clone(), &namespace) else { release_irq(irq, endpoint); release_dev(&dev); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); };
        dev.iface.store(reg.id().raw() as u64, Ordering::Release); dev.generation.store(reg.generation(), Ordering::Release);
        if !stack.publish_iface(reg) { dev.iface.store(0, Ordering::Release); release_irq(irq, endpoint); release_dev(&dev); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); }
        if !POLL_INSTALLED.swap(true, Ordering::AcqRel) && !net::backlog::register_poll(poll_rx) { POLL_INSTALLED.store(false, Ordering::Release); let _ = stack.unregister_iface_current(net::NetIfaceId::from_raw(dev.iface.swap(0, Ordering::AcqRel) as u32)); release_irq(irq, endpoint); release_dev(&dev); restore_bus_master(bdf, command); return Err(drv::Error::ProbeFailed); }
        dev.controller.lock_bh::<sched::bh::SchedBh>().as_ref().expect("published controller").enable_interrupts();
        DEVICES.lock_bh::<sched::bh::SchedBh>().push(Record { bdf, command, irq, dev }); Ok(())
    }
    fn remove(&self, device: &drv::Device) { if let Some(bdf) = pci::parse_bdf_addr(&device.addr) { remove_bdf(bdf); } }
    fn shutdown(&self, device: &drv::Device) { if let Some(bdf) = pci::parse_bdf_addr(&device.addr) { remove_bdf(bdf); } }
}
pub static RTL8125_DRIVER: Rtl8125Driver = Rtl8125Driver;
