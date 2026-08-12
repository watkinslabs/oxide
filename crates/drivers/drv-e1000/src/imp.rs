use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

use crate::regs;

const MAX_DEVICES: usize = 8;
const PAGE: u64 = 4096;
const DMA32_LIMIT: u64 = 1 << 32;
const RX_ORDER: pmm::Order = pmm::Order(7);
const TX_ORDER: pmm::Order = pmm::Order(7);
const ENDPOINT_FREE: u8 = 0;
const ENDPOINT_SETUP: u8 = 1;
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
const ENDPOINT_ACTIVE: u8 = 2;
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
const ENDPOINT_HANDLING: u8 = 3;

struct Endpoint { state: AtomicU8, mmio: AtomicU64, in_handler: AtomicU32, polling: AtomicBool }
impl Endpoint {
    const fn new() -> Self { Self { state: AtomicU8::new(ENDPOINT_FREE), mmio: AtomicU64::new(0), in_handler: AtomicU32::new(0), polling: AtomicBool::new(false) } }
}
static ENDPOINTS: [Endpoint; MAX_DEVICES] = [const { Endpoint::new() }; MAX_DEVICES];

struct Controller {
    mmio: mmio_map::Mapping,
    rx_desc_pa: u64, tx_desc_pa: u64, rx_data_pa: u64, tx_data_pa: u64,
    rx_desc_dma: u64, tx_desc_dma: u64, rx_data_dma: u64, tx_data_dma: u64,
    bdf: pci::Bdf,
    rx_next: usize, tx_next: usize,
}

impl Controller {
    fn va(pa: u64) -> u64 { pmm::user_as::hhdm_offset().wrapping_add(pa) }
    fn read(&self, off: u64) -> u32 {
        // SAFETY: controller holds the owned MMIO mapping and `off` is an aligned register ABI offset.
        unsafe { core::ptr::read_volatile((self.mmio.base_va() + off) as *const u32) }
    }
    fn write(&self, off: u64, value: u32) {
        // SAFETY: controller holds the owned MMIO mapping and `off` is an aligned register ABI offset.
        unsafe { core::ptr::write_volatile((self.mmio.base_va() + off) as *mut u32, value); }
    }
    fn rx_desc(&self, idx: usize) -> *mut regs::RxDesc {
        (Self::va(self.rx_desc_pa) as *mut regs::RxDesc).wrapping_add(idx)
    }
    fn tx_desc(&self, idx: usize) -> *mut regs::TxDesc {
        (Self::va(self.tx_desc_pa) as *mut regs::TxDesc).wrapping_add(idx)
    }
    fn stop(&mut self) {
        self.write(regs::IMC, u32::MAX);
        self.write(regs::RCTL, self.read(regs::RCTL) & !regs::RCTL_EN);
        self.write(regs::TCTL, self.read(regs::TCTL) & !regs::TCTL_EN);
    }
    fn free(&mut self) {
        self.stop();
        self.mmio.unmap();
        unmap_rings(self.bdf, [self.rx_desc_dma, self.tx_desc_dma, self.rx_data_dma, self.tx_data_dma]);
        // SAFETY: stop disabled DMA before each owned PMM allocation is returned.
        unsafe {
            pmm::setup::free_contig(self.rx_desc_pa, pmm::Order(0));
            pmm::setup::free_contig(self.tx_desc_pa, pmm::Order(0));
            pmm::setup::free_contig(self.rx_data_pa, RX_ORDER);
            pmm::setup::free_contig(self.tx_data_pa, TX_ORDER);
        }
    }
    fn xmit(&mut self, frame: &[u8]) -> net::NetResult<()> {
        if !regs::valid_frame_len(frame.len()) { return Err(net::NetError::Emsgsize); }
        let idx = self.tx_next;
        pmm::dma::invalidate_from_device(Self::va(self.tx_desc_pa) + (idx * core::mem::size_of::<regs::TxDesc>()) as u64,
            core::mem::size_of::<regs::TxDesc>());
        // SAFETY: `idx` is reduced modulo the allocated descriptor ring; lock ownership serializes TX.
        // SAFETY: TX lock owns the in-range descriptor slot until its next device completion.
        let desc = unsafe { &mut *self.tx_desc(idx) };
        if desc.status & regs::TX_STATUS_DD == 0 { return Err(net::NetError::Eagain); }
        let va = Self::va(self.tx_data_pa + (idx * regs::BUFFER_BYTES) as u64);
        // SAFETY: `frame` was bounded by one per-descriptor DMA buffer and the TX lock owns its slot.
        // SAFETY: frame length was bounded to this controller-owned DMA slot above.
        unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), va as *mut u8, frame.len()); }
        desc.addr = self.tx_data_dma + (idx * regs::BUFFER_BYTES) as u64;
        desc.length = frame.len() as u16;
        desc.cmd = regs::TX_CMD_EOP | regs::TX_CMD_IFCS | regs::TX_CMD_RS;
        desc.status = 0;
        pmm::dma::clean_to_device(va, frame.len());
        pmm::dma::clean_to_device(Self::va(self.tx_desc_pa) + (idx * core::mem::size_of::<regs::TxDesc>()) as u64,
            core::mem::size_of::<regs::TxDesc>());
        core::sync::atomic::fence(Ordering::Release);
        self.tx_next = (idx + 1) % regs::RING_COUNT;
        self.write(regs::TDT, regs::ring_tail(self.tx_next));
        Ok(())
    }
    fn take_rx(&mut self) -> (Vec<Vec<u8>>, bool) {
        let mut frames = Vec::new();
        while frames.len() < net::backlog::DEV_RX_WEIGHT {
            let idx = self.rx_next;
            pmm::dma::invalidate_from_device(Self::va(self.rx_desc_pa) + (idx * core::mem::size_of::<regs::RxDesc>()) as u64,
                core::mem::size_of::<regs::RxDesc>());
            // SAFETY: `idx` is reduced modulo the allocated RX descriptor ring; poll serializes RX.
            // SAFETY: RX polling exclusively owns this in-range descriptor slot.
            let desc = unsafe { &mut *self.rx_desc(idx) };
            core::sync::atomic::fence(Ordering::Acquire);
            if desc.status & regs::RX_DESC_DONE == 0 { return (frames, false); }
            let len = desc.length as usize;
            if regs::valid_frame_len(len) {
                let va = Self::va(self.rx_data_pa + (idx * regs::BUFFER_BYTES) as u64);
                pmm::dma::invalidate_from_device(va, len);
                // SAFETY: DD plus Acquire makes the device-written buffer visible; `len` fits its slot.
                // SAFETY: the completed descriptor length is bounded to its allocated DMA slot.
                let bytes = unsafe { core::slice::from_raw_parts(va as *const u8, len) };
                frames.push(bytes.to_vec());
            }
            desc.status = 0; desc.errors = 0; desc.length = 0;
            pmm::dma::invalidate_from_device(Self::va(self.rx_data_pa + (idx * regs::BUFFER_BYTES) as u64), regs::BUFFER_BYTES);
            pmm::dma::clean_to_device(Self::va(self.rx_desc_pa) + (idx * core::mem::size_of::<regs::RxDesc>()) as u64,
                core::mem::size_of::<regs::RxDesc>());
            core::sync::atomic::fence(Ordering::Release);
            self.rx_next = (idx + 1) % regs::RING_COUNT;
            self.write(regs::RDT, regs::ring_tail(idx));
        }
        pmm::dma::invalidate_from_device(Self::va(self.rx_desc_pa) + (self.rx_next * core::mem::size_of::<regs::RxDesc>()) as u64,
            core::mem::size_of::<regs::RxDesc>());
        // SAFETY: `rx_next` remains within the RX descriptor ring after the bounded drain above.
        // SAFETY: rx_next remains an in-range ring index after the bounded drain.
        let more = unsafe { (*self.rx_desc(self.rx_next)).status & regs::RX_DESC_DONE != 0 };
        (frames, more)
    }
}

struct E1000NetDev {
    name: alloc::string::String, mac: net::MacAddr, iface: AtomicU64,
    generation: AtomicU64, removed: AtomicBool, endpoint: usize, ctrl: Spinlock<Controller, DriverLockClass>,
}
impl E1000NetDev {
    fn xmit_frame(&self, frame: &[u8]) -> net::NetResult<()> { self.ctrl.lock_bh::<sched::bh::SchedBh>().xmit(frame) }
}
fn link_address_for(next_hop: net::pkt::TxNextHop) -> Option<net::MacAddr> {
    match next_hop {
        net::pkt::TxNextHop::V4(ip) => ip.is_broadcast().then_some(net::MacAddr::BROADCAST),
        net::pkt::TxNextHop::V6 { addr, .. } => addr.is_multicast().then(|| net::ndp::multicast_ethernet(addr)),
    }
}
impl net::NetDev for E1000NetDev {
    fn name(&self) -> &str { &self.name }
    fn mac(&self) -> net::MacAddr { self.mac }
    fn mtu(&self) -> u32 { 1500 }
    fn admin_up_changed(&self, up: bool) {
        let mut ctrl = self.ctrl.lock_bh::<sched::bh::SchedBh>();
        if up { start(&ctrl); } else { ctrl.stop(); }
    }
    fn retire_namespace(&self) { self.generation.fetch_add(1, Ordering::AcqRel); }
    fn resume_namespace(&self) {}
    fn namespace_drop_action(&self) -> net::NamespaceDropAction { net::NamespaceDropAction::MoveToInitial }
    fn xmit(&self, pkt: net::Pkt) -> net::NetResult<()> { self.xmit_observed(pkt, &mut |_, _, _| {}) }
    fn xmit_observed(&self, pkt: net::Pkt, observe: &mut dyn FnMut(&[u8], u16, usize)) -> net::NetResult<()> {
        let dst = pkt.next_hop.and_then(link_address_for).ok_or(net::NetError::Ehostunreach)?;
        let body = pkt.data();
        if body.len() + 14 > regs::ETH_MAX_FRAME { return Err(net::NetError::Emsgsize); }
        let mut frame = alloc::vec![0u8; body.len() + 14];
        net::ethernet::EthHdr::write_to(dst, self.mac, pkt.proto, &mut frame[..14]);
        frame[14..].copy_from_slice(body); observe(&frame, pkt.proto, 14); self.xmit_frame(&frame)
    }
    fn xmit_l2_observed(&self, pkt: net::Pkt, dst: net::MacAddr, observe: &mut dyn FnMut(&[u8], u16, usize)) -> net::NetResult<()> {
        let body = pkt.data();
        if body.len() + 14 > regs::ETH_MAX_FRAME { return Err(net::NetError::Emsgsize); }
        let mut frame = alloc::vec![0u8; body.len() + 14];
        net::ethernet::EthHdr::write_to(dst, self.mac, pkt.proto, &mut frame[..14]);
        frame[14..].copy_from_slice(body); observe(&frame, pkt.proto, 14); self.xmit_frame(&frame)
    }
}

fn decode_bars(bdf: pci::Bdf) -> [pci::Bar; 6] {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::pci::EcamPci::from_published().map(|r| pci::decode_bars(&r, bdf)).unwrap_or([pci::Bar::None; 6]) }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::pci::EcamPci::from_published().map(|r| pci::decode_bars(&r, bdf)).unwrap_or([pci::Bar::None; 6]) }
}
fn enable_bus_master(bdf: pci::Bdf) -> Option<u16> {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::pci::EcamPci::from_published().map(|r| pci::enable_mem_bus_master(&r, bdf)) }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::pci::EcamPci::from_published().map(|r| pci::enable_mem_bus_master(&r, bdf)) }
}
fn restore_bus_master(bdf: pci::Bdf, original: u16) {
    #[cfg(target_arch = "x86_64")]
    if let Some(r) = hal_x86_64::pci::EcamPci::from_published() { let _ = pci::restore_mem_bus_master(&r, bdf, original); }
    #[cfg(target_arch = "aarch64")]
    if let Some(r) = hal_aarch64::pci::EcamPci::from_published() { let _ = pci::restore_mem_bus_master(&r, bdf, original); }
}

fn wait_for_reset_auto_read() {
    #[cfg(target_os = "oxide-kernel")]
    {
        let deadline = sched::deadline::clock::now_ns().saturating_add(regs::RESET_AUTO_READ_NS);
        while sched::deadline::clock::now_ns() < deadline { core::hint::spin_loop(); }
    }
}

fn dma_bytes(order: pmm::Order) -> usize { (1usize << order.0) * PAGE as usize }

fn unmap_rings(bdf: pci::Bdf, dma: [u64; 4]) {
    let _ = iommu::unmap_dma(bdf, dma[0], PAGE as usize);
    let _ = iommu::unmap_dma(bdf, dma[1], PAGE as usize);
    let _ = iommu::unmap_dma(bdf, dma[2], dma_bytes(RX_ORDER));
    let _ = iommu::unmap_dma(bdf, dma[3], dma_bytes(TX_ORDER));
}
fn map_rings(bdf: pci::Bdf, pa: [u64; 4]) -> Option<[u64; 4]> {
    let rx_desc = iommu::map_dma(bdf, pa[0], PAGE as usize)?;
    let Some(tx_desc) = iommu::map_dma(bdf, pa[1], PAGE as usize) else { let _ = iommu::unmap_dma(bdf, rx_desc, PAGE as usize); return None; };
    let Some(rx_data) = iommu::map_dma(bdf, pa[2], dma_bytes(RX_ORDER)) else {
        let _ = iommu::unmap_dma(bdf, rx_desc, PAGE as usize); let _ = iommu::unmap_dma(bdf, tx_desc, PAGE as usize); return None;
    };
    let Some(tx_data) = iommu::map_dma(bdf, pa[3], dma_bytes(TX_ORDER)) else {
        let _ = iommu::unmap_dma(bdf, rx_desc, PAGE as usize); let _ = iommu::unmap_dma(bdf, tx_desc, PAGE as usize);
        let _ = iommu::unmap_dma(bdf, rx_data, dma_bytes(RX_ORDER)); return None;
    };
    Some([rx_desc, tx_desc, rx_data, tx_data])
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn io_write32(port: u16, value: u32) {
    // SAFETY: the matched 82540 function owns this BAR1 register window during probe.
    unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags)); }
}

fn reset(c: &Controller, io_base: Option<u16>) {
    c.write(regs::IMC, u32::MAX);
    c.write(regs::RCTL, 0);
    c.write(regs::TCTL, regs::TCTL_PSP);
    let ctrl = c.read(regs::CTRL);
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    if let Some(port) = io_base {
        // Linux uses the 82540 I/O window for CTRL.RST: this part cannot
        // acknowledge the MMIO write that asks it to reset its own bus path.
        io_write32(port, regs::CTRL as u32);
        io_write32(port.wrapping_add(4), ctrl | regs::CTRL_RST);
    } else {
        c.write(regs::CTRL, ctrl | regs::CTRL_RST);
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = io_base; c.write(regs::CTRL, ctrl | regs::CTRL_RST); }
    // Linux e1000_get_auto_rd_done waits 5ms for the 82540 EEPROM reload.
    wait_for_reset_auto_read();
    let _ = c.read(regs::ICR);
}

fn configure_rings(mmio: mmio_map::Mapping, io_base: Option<u16>, bdf: pci::Bdf) -> Option<(Controller, net::MacAddr)> {
    let rx_desc_pa = match pmm::setup::alloc_contig_below(pmm::Order(0), DMA32_LIMIT) { Some(pa) => pa, None => { trace("[INFO]  e1000: no rx desc\n"); return None; } };
    let tx_desc_pa = match pmm::setup::alloc_contig_below(pmm::Order(0), DMA32_LIMIT) { Some(pa) => pa, None => {
        trace("[INFO]  e1000: no tx desc\n");
        // SAFETY: this failure path returns the just-allocated and still-unmapped RX descriptor frame.
        unsafe { pmm::setup::free_contig(rx_desc_pa, pmm::Order(0)); } return None;
    } };
    let rx_data_pa = match pmm::setup::alloc_contig_below(RX_ORDER, DMA32_LIMIT) { Some(pa) => pa, None => {
        trace("[INFO]  e1000: no rx dma\n");
        // SAFETY: both descriptor frames are fresh, unpublished allocations on this failure path.
        unsafe { pmm::setup::free_contig(rx_desc_pa, pmm::Order(0)); pmm::setup::free_contig(tx_desc_pa, pmm::Order(0)); } return None;
    } };
    let tx_data_pa = match pmm::setup::alloc_contig_below(TX_ORDER, DMA32_LIMIT) { Some(pa) => pa, None => {
        trace("[INFO]  e1000: no tx dma\n");
        // SAFETY: all prior allocations are fresh, unpublished DMA storage on this failure path.
        unsafe { pmm::setup::free_contig(rx_desc_pa, pmm::Order(0)); pmm::setup::free_contig(tx_desc_pa, pmm::Order(0)); pmm::setup::free_contig(rx_data_pa, RX_ORDER); } return None;
    } };
    let Some([rx_desc_dma, tx_desc_dma, rx_data_dma, tx_data_dma]) = map_rings(bdf, [rx_desc_pa, tx_desc_pa, rx_data_pa, tx_data_pa]) else {
        // SAFETY: no allocation was published to the device before this mapping failure.
        unsafe { pmm::setup::free_contig(rx_desc_pa, pmm::Order(0)); pmm::setup::free_contig(tx_desc_pa, pmm::Order(0)); pmm::setup::free_contig(rx_data_pa, RX_ORDER); pmm::setup::free_contig(tx_data_pa, TX_ORDER); }
        return None;
    };
    if !regs::dma32_range_fits(rx_desc_dma, PAGE as usize)
        || !regs::dma32_range_fits(tx_desc_dma, PAGE as usize)
        || !regs::dma32_range_fits(rx_data_dma, dma_bytes(RX_ORDER))
        || !regs::dma32_range_fits(tx_data_dma, dma_bytes(TX_ORDER))
    {
        unmap_rings(bdf, [rx_desc_dma, tx_desc_dma, rx_data_dma, tx_data_dma]);
        // SAFETY: no allocation was published to the device on this DMA-mask rejection path.
        unsafe { pmm::setup::free_contig(rx_desc_pa, pmm::Order(0)); pmm::setup::free_contig(tx_desc_pa, pmm::Order(0)); pmm::setup::free_contig(rx_data_pa, RX_ORDER); pmm::setup::free_contig(tx_data_pa, TX_ORDER); }
        return None;
    }
    let mut c = Controller { mmio, rx_desc_pa, tx_desc_pa, rx_data_pa, tx_data_pa, rx_desc_dma, tx_desc_dma, rx_data_dma, tx_data_dma, bdf, rx_next: 0, tx_next: 0 };
    trace("[INFO]  e1000: dma allocated\n");
    reset(&c, io_base);
    trace("[INFO]  e1000: reset done\n");
    let mac = match regs::mac_from_rar(c.read(regs::RAL0), c.read(regs::RAH0)) { Some(mac) => net::MacAddr(mac), None => { trace("[INFO]  e1000: no mac\n"); c.free(); return None; } };
    for i in 0..regs::RING_COUNT {
        // SAFETY: every index is inside its freshly allocated ring before device DMA is enabled.
        unsafe {
            *c.rx_desc(i) = regs::RxDesc { addr: rx_data_dma + (i * regs::BUFFER_BYTES) as u64, ..regs::RxDesc::default() };
            *c.tx_desc(i) = regs::TxDesc { addr: tx_data_dma + (i * regs::BUFFER_BYTES) as u64, status: regs::TX_STATUS_DD, ..regs::TxDesc::default() };
        }
    }
    pmm::dma::clean_to_device(Controller::va(rx_desc_pa), regs::ring_bytes::<regs::RxDesc>() as usize);
    pmm::dma::clean_to_device(Controller::va(tx_desc_pa), regs::ring_bytes::<regs::TxDesc>() as usize);
    pmm::dma::invalidate_from_device(Controller::va(rx_data_pa), regs::RING_COUNT * regs::BUFFER_BYTES);
    core::sync::atomic::fence(Ordering::Release);
    let (lo, hi) = regs::split_dma(rx_desc_dma); c.write(regs::RDBAL, lo); c.write(regs::RDBAH, hi); c.write(regs::RDLEN, regs::ring_bytes::<regs::RxDesc>()); c.write(regs::RDH, 0); c.write(regs::RDT, (regs::RING_COUNT - 1) as u32);
    let (lo, hi) = regs::split_dma(tx_desc_dma); c.write(regs::TDBAL, lo); c.write(regs::TDBAH, hi); c.write(regs::TDLEN, regs::ring_bytes::<regs::TxDesc>()); c.write(regs::TDH, 0); c.write(regs::TDT, 0);
    Some((c, mac))
}

fn start(c: &Controller) {
    c.write(regs::RCTL, regs::RCTL_EN | regs::RCTL_BAM | regs::RCTL_SECRC | regs::RCTL_SZ_2048);
    c.write(regs::TCTL, regs::TCTL_EN | regs::TCTL_PSP | (15 << regs::TCTL_CT_SHIFT) | (0x40 << regs::TCTL_COLD_SHIFT));
    // e1000_open configures hardware before e1000_irq_enable; only then may
    // the completion causes be unmasked. The read flushes the posted write.
    let _ = c.read(regs::ICR);
    enable_interrupts(c);
}

fn enable_interrupts(c: &Controller) {
    c.write(regs::IMS, regs::IMS_DEFAULT);
    let _ = c.read(regs::IMS);
}

fn hard_msi() { let _ = hard_irq(); }

fn bind_pci_message(bdf: pci::Bdf, endpoint: usize, ctrl: &Controller) -> Option<pci_irq::Binding> {
    let binding = pci_irq::request(bdf, pci_irq::BarMapping {
        bar: 0, base_va: ctrl.mmio.base_va(), bytes: ctrl.mmio.bytes(), offset: 0,
    }, arch_irq::DeviceAction::E1000, hard_msi)?;
    ENDPOINTS[endpoint].state.store(ENDPOINT_ACTIVE, Ordering::Release);
    Some(binding)
}

struct Record { bdf: pci::Bdf, command_orig: u16, endpoint: usize, irq: pci_irq::Binding, dev: Arc<E1000NetDev> }
static DEVICES: Spinlock<Vec<Record>, DriverLockClass> = Spinlock::new(Vec::new());
static POLL_INSTALLED: AtomicBool = AtomicBool::new(false);
static NEXT_NAME: AtomicU32 = AtomicU32::new(0);

#[cfg(feature = "debug-boot")]
fn trace(stage: &'static str) { klog::write_raw(stage.as_bytes()); }
#[cfg(not(feature = "debug-boot"))]
fn trace(_stage: &'static str) {}

fn endpoint_claim(mmio: u64) -> Option<usize> {
    for (i, e) in ENDPOINTS.iter().enumerate() {
        if e.state.compare_exchange(ENDPOINT_FREE, ENDPOINT_SETUP, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            e.mmio.store(mmio, Ordering::Release); e.in_handler.store(0, Ordering::Release); e.polling.store(false, Ordering::Release); return Some(i);
        }
    } None
}
fn endpoint_release(i: usize) { let e = &ENDPOINTS[i]; e.mmio.store(0, Ordering::Release); e.polling.store(false, Ordering::Release); e.state.store(ENDPOINT_FREE, Ordering::Release); }
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
fn hard_irq() -> bool {
    let mut pending = false;
    for e in &ENDPOINTS {
        if e.state.compare_exchange(ENDPOINT_ACTIVE, ENDPOINT_HANDLING, Ordering::AcqRel, Ordering::Acquire).is_err() { continue; }
        e.in_handler.fetch_add(1, Ordering::AcqRel);
        let mmio = e.mmio.load(Ordering::Acquire);
        // SAFETY: ACTIVE owns this MMIO identity; removal waits for in_handler before unmapping it.
        // SAFETY: ACTIVE owns the live controller MMIO identity until this handler drains.
        let cause = unsafe { core::ptr::read_volatile((mmio + regs::ICR) as *const u32) };
        if cause != 0 && e.polling.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            // SAFETY: ACTIVE publishes the MMIO mapping; mask before deferred poll owns RX cleanup.
            unsafe { core::ptr::write_volatile((mmio + regs::IMC) as *mut u32, u32::MAX); }
            pending = true;
        }
        e.in_handler.fetch_sub(1, Ordering::Release); e.state.store(ENDPOINT_ACTIVE, Ordering::Release);
    }
    if pending { net::backlog::net_rx_schedule_ingress(); }
    pending
}

fn release_irq(irq: pci_irq::Binding, endpoint: usize) {
    while ENDPOINTS[endpoint].in_handler.load(Ordering::Acquire) != 0 { core::hint::spin_loop(); }
    endpoint_release(endpoint);
    irq.release();
}

/// Finish a bounded device poll without losing an interrupt that arrived while
/// the hardware source was masked. Returns true when another poll is owed.
fn complete_poll(endpoint: usize, ctrl: &Controller) -> bool {
    let ep = &ENDPOINTS[endpoint];
    if ctrl.read(regs::ICR) != 0 { return true; }
    // A cause arriving after the ICR read remains latched while masked. Clear
    // the software poll state first, so IMS delivery schedules a fresh poll.
    ep.polling.store(false, Ordering::Release);
    enable_interrupts(ctrl);
    false
}

fn poll_rx() {
    let devices: Vec<Arc<E1000NetDev>> = DEVICES.lock_bh::<sched::bh::SchedBh>().iter().map(|r| r.dev.clone()).collect();
    let stack = net::sock::stack();
    for dev in devices {
        if dev.removed.load(Ordering::Acquire) { continue; }
        let raw = dev.iface.load(Ordering::Acquire); if raw == 0 { continue; }
        let iface = net::NetIfaceId::from_raw(raw as u32);
        let generation = dev.generation.load(Ordering::Acquire);
        let (frames, more) = dev.ctrl.lock_bh::<sched::bh::SchedBh>().take_rx();
        for frame in frames {
            let mut pkt = net::Pkt::new_with_headroom(net::DEFAULT_HEADROOM, frame.len());
            pkt.data_mut().copy_from_slice(&frame);
            let _ = stack.netif_rx_ethernet(iface, generation, pkt, net::PacketRxMetadata::default());
        }
        if more { net::backlog::net_rx_schedule_ingress(); }
        else if complete_poll(dev.endpoint, &dev.ctrl.lock_bh::<sched::bh::SchedBh>()) {
            net::backlog::net_rx_schedule_ingress();
        }
    }
}

const INTEL_VENDOR: u16 = 0x8086;
const ETHERNET_CLASS: u32 = 0x02_00_00;
fn supported(dev: &drv::Device) -> bool {
    dev.bus == "pci" && dev.class == ETHERNET_CLASS && dev.vendor_id == INTEL_VENDOR
        && regs::LEGACY_PCI_IDS.contains(&dev.device_id)
}

fn remove_bdf(bdf: pci::Bdf) {
    let record = {
        let mut devices = DEVICES.lock_bh::<sched::bh::SchedBh>();
        let pos = match devices.iter().position(|r| r.bdf == bdf) { Some(pos) => pos, None => return };
        devices.remove(pos)
    };
    record.dev.removed.store(true, Ordering::Release);
    let iface = record.dev.iface.swap(0, Ordering::AcqRel);
    if iface != 0 { let _ = net::sock::stack().unregister_iface_current(net::NetIfaceId::from_raw(iface as u32)); }
    record.dev.ctrl.lock_bh::<sched::bh::SchedBh>().stop();
    release_irq(record.irq, record.endpoint);
    record.dev.ctrl.lock_bh::<sched::bh::SchedBh>().free();
    restore_bus_master(record.bdf, record.command_orig);
    if DEVICES.lock_bh::<sched::bh::SchedBh>().is_empty() && POLL_INSTALLED.swap(false, Ordering::AcqRel) {
        net::backlog::unregister_poll(poll_rx);
    }
}

pub struct E1000Driver;
impl drv::Driver for E1000Driver {
    fn name(&self) -> &'static str { "e1000" }
    fn matches(&self, dev: &drv::Device) -> bool { supported(dev) }
    fn probe(&self, parent: &Arc<drv::Device>) -> drv::KResult<()> {
        trace("[INFO]  e1000: probe begin\n");
        let bdf = pci::parse_bdf_addr(&parent.addr).ok_or(drv::Error::ProbeFailed)?;
        let command_orig = enable_bus_master(bdf).ok_or(drv::Error::ProbeFailed)?;
        let bars = decode_bars(bdf);
        let Some(resource) = parent.resources.iter().find(|resource| resource.bar == 0 && resource.flags & drv::IORESOURCE_MEM != 0) else { restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); };
        let bar = resource.start;
        let io_base = match bars[1] { pci::Bar::Io { port } => u16::try_from(port).ok(), _ => None };
        if bar == 0 { restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); }
        // SAFETY: BAR0 is owned by this successfully matched PCI function and maps its register file.
        // SAFETY: BAR0 comes from the matched PCI function and the driver takes exclusive ownership.
        let bytes = resource.end.checked_sub(resource.start).and_then(|bytes| bytes.checked_add(1)).ok_or(drv::Error::ProbeFailed)?;
        let pages = (bar & (PAGE - 1)).checked_add(bytes).and_then(|bytes| bytes.checked_add(PAGE - 1)).and_then(|bytes| bytes.checked_div(PAGE)).ok_or(drv::Error::ProbeFailed)?;
        let mmio = unsafe { mmio_map::map_owned(bar & !(PAGE - 1), pages) };
        let (controller, mac) = match configure_rings(mmio, io_base, bdf) { Some(value) => value, None => { restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); } };
        trace("[INFO]  e1000: rings ready\n");
        let endpoint = match endpoint_claim(controller.mmio.base_va()) { Some(endpoint) => endpoint, None => { let mut controller = controller; controller.free(); restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); } };
        // Linux permits an INTx fallback because ACPI _PRT supplies its exact
        // GSI routing. Oxide has no AML/_PRT interpreter, so pretending the
        // PCI interrupt-line byte is routable would deliver a vector to the
        // wrong pin on real firmware. Require PCI core MSI/MSI-X instead.
        let irq = parent.msi_allowed().then(|| bind_pci_message(bdf, endpoint, &controller)).flatten();
        let irq = match irq { Some(irq) => irq, None => { endpoint_release(endpoint); let mut controller = controller; controller.free(); restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); } };
        trace("[INFO]  e1000: irq ready\n");
        let dev = Arc::new(E1000NetDev {
            name: alloc::format!("eth{}", NEXT_NAME.fetch_add(1, Ordering::Relaxed)), mac,
            iface: AtomicU64::new(0), generation: AtomicU64::new(0), removed: AtomicBool::new(false),
            endpoint, ctrl: Spinlock::new(controller),
        });
        let stack = net::sock::stack();
        let namespace = net::net_ns::initial_namespace();
        let owner = dev.clone() as Arc<dyn net::NetDev>;
        let Some(reg) = stack.prepare_parented_iface(owner, parent.clone(), &namespace) else {
            release_irq(irq, endpoint); dev.ctrl.lock_bh::<sched::bh::SchedBh>().free(); restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed);
        };
        dev.iface.store(reg.id().raw() as u64, Ordering::Release); dev.generation.store(reg.generation(), Ordering::Release);
        if !stack.publish_iface(reg) {
            dev.iface.store(0, Ordering::Release); release_irq(irq, endpoint); dev.ctrl.lock_bh::<sched::bh::SchedBh>().free(); restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed);
        }
        if !POLL_INSTALLED.swap(true, Ordering::AcqRel) && !net::backlog::register_poll(poll_rx) {
            POLL_INSTALLED.store(false, Ordering::Release); let _ = stack.unregister_iface_current(net::NetIfaceId::from_raw(dev.iface.swap(0, Ordering::AcqRel) as u32)); release_irq(irq, endpoint); dev.ctrl.lock_bh::<sched::bh::SchedBh>().free(); restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed);
        }
        DEVICES.lock_bh::<sched::bh::SchedBh>().push(Record { bdf, command_orig, endpoint, irq, dev: dev.clone() });
        // `register_netdev` leaves IFF_UP clear. The NetDev lifecycle hook
        // performs the Linux ndo_open equivalent when userspace brings it up.
        trace("[INFO]  e1000: registered down\n");
        Ok(())
    }
    fn remove(&self, dev: &drv::Device) { if let Some(bdf) = pci::parse_bdf_addr(&dev.addr) { remove_bdf(bdf); } }
    fn shutdown(&self, dev: &drv::Device) { if let Some(bdf) = pci::parse_bdf_addr(&dev.addr) { remove_bdf(bdf); } }
}

pub static E1000_DRIVER: E1000Driver = E1000Driver;
