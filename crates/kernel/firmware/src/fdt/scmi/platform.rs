//! Aarch64 SCMI SMC shared-memory transport and cpufreq provider.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use ::fdt::{ScmiCompletionIrq, ScmiPerfProtocol, ScmiSmcTransport};
use sync::{Devices, Spinlock};
use vfs::{KResult, VfsError};

const STATUS: usize = 4;
const FLAGS: usize = 16;
const LENGTH: usize = 20;
const HEADER: usize = 24;
const PAYLOAD: usize = 28;
const CHANNEL_FREE: u32 = 1;
const CHANNEL_ERROR: u32 = 2;
const INTERRUPT_ENABLED: u32 = 1;
const TOKEN_MASK: u16 = 0x03ff;
const RESPONSE_TIMEOUT_NS: u64 = 30_000_000;
const CHANNEL_RELEASE_TIMEOUT_NS: u64 = RESPONSE_TIMEOUT_NS * 2;

struct Completion {
    active: bool,
    sent: bool,
    token: u16,
    protocol: u8,
    command: u8,
    rx: usize,
    rx_len: usize,
    outcome: Option<scmi::Result<usize>>,
}

impl Completion {
    const fn new() -> Self {
        Self { active: false, sent: false, token: 0, protocol: 0, command: 0, rx: 0, rx_len: 0, outcome: None }
    }
}

struct SmcTransport {
    _mapping: mmio_map::Mapping,
    base: u64,
    size: usize,
    physical_base: u64,
    smc_id: u64,
    form: ScmiSmcTransport,
    completion_irq: Option<ScmiCompletionIrq>,
    next_token: AtomicU16,
    poll_lock: Spinlock<(), Devices>,
    completion: Spinlock<Completion, Devices>,
    response_wait: sched::live::WaitList,
    idle_wait: sched::live::WaitList,
}

static A2P_TRANSPORTS: Spinlock<Vec<Arc<SmcTransport>>, Devices> = Spinlock::new(Vec::new());
static DRIVER: Spinlock<Option<Arc<Driver>>, Devices> = Spinlock::new(None);
static DEFERRED_READY: AtomicBool = AtomicBool::new(false);
static A2P_PENDING: AtomicBool = AtomicBool::new(false);
static A2P_QUEUED: AtomicBool = AtomicBool::new(false);

impl SmcTransport {
    fn new(record: &ScmiPerfProtocol) -> Option<Arc<Self>> {
        let size = usize::try_from(record.shmem.size).ok()?;
        if size < PAYLOAD || record.shmem.base_pa & 3 != 0 { return None; }
        let page = hal::PAGE_SIZE_BYTES;
        let page_base = record.shmem.base_pa & !(page - 1);
        let offset = record.shmem.base_pa.checked_sub(page_base)?;
        let mapped = offset.checked_add(record.shmem.size)?;
        let pages = mapped.checked_add(page - 1)?.checked_div(page)?;
        if pages == 0 { return None; }
        // SAFETY: FDT admitted an enabled arm,scmi-shmem resource. This
        // transport retains exclusive ownership of the resulting device map.
        let mapping = unsafe { mmio_map::map_owned(page_base, pages) };
        let base = mapping.base_va().checked_add(offset)?;
        (base != 0).then(|| Arc::new(Self {
            _mapping: mapping, base, size, physical_base: record.shmem.base_pa,
            smc_id: u64::from(record.smc_id), form: record.transport,
            completion_irq: record.completion_irq, next_token: AtomicU16::new(0),
            poll_lock: Spinlock::new(()), completion: Spinlock::new(Completion::new()),
            response_wait: sched::live::WaitList::new(), idle_wait: sched::live::WaitList::new(),
        }))
    }

    fn bind_completion(self: &Arc<Self>) -> bool {
        let Some(irq) = self.completion_irq else { return true; };
        A2P_TRANSPORTS.lock().push(Arc::clone(self));
        if super::install_completion_irq(irq) { return true; }
        A2P_TRANSPORTS.lock().retain(|transport| !Arc::ptr_eq(transport, self));
        false
    }

    fn next_token(&self) -> u16 { self.next_token.fetch_add(1, Ordering::Relaxed).wrapping_add(1) & TOKEN_MASK }

    fn arguments(&self) -> [u64; 8] {
        match self.form {
            ScmiSmcTransport::Direct => [self.smc_id, 0, 0, 0, 0, 0, 0, 0],
            ScmiSmcTransport::PageAndOffset => [self.smc_id, self.physical_base >> 12, self.physical_base & 0xfff, 0, 0, 0, 0, 0],
        }
    }

    fn invoke(&self) -> scmi::Result<()> {
        // SAFETY: the FDT SCMI SMC binding chose this conduit and function ID;
        // one channel owner prepared its shared-memory request beforehand.
        let result = unsafe { hal_aarch64::smccc::call(hal_aarch64::smccc::Conduit::Smc, self.arguments()) };
        (result.a0() == 0).then_some(()).ok_or(scmi::Error::Unsupported)
    }

    fn prepare(&self, token: u16, protocol: u8, command: u8, tx: &[u8], interrupt: bool) -> scmi::Result<()> {
        if tx.len().checked_add(PAYLOAD).filter(|bytes| *bytes <= self.size).is_none() { return Err(scmi::Error::NoMemory); }
        // A command that timed out can still be executing in platform
        // firmware.  Never reclaim its shared memory: wait for the firmware
        // to release the channel, as the SCMI SMC transport does, so the
        // previous response cannot be overwritten by a new request.
        let deadline = timekeeper::monotonic_ns().saturating_add(CHANNEL_RELEASE_TIMEOUT_NS);
        while self.read32(STATUS) & CHANNEL_FREE == 0 {
            if timekeeper::monotonic_ns() >= deadline { return Err(scmi::Error::Busy); }
            core::hint::spin_loop();
        }
        self.write32(STATUS, 0);
        self.write32(FLAGS, if interrupt { INTERRUPT_ENABLED } else { 0 });
        self.write32(LENGTH, u32::try_from(4usize.checked_add(tx.len()).ok_or(scmi::Error::Range)?).map_err(|_| scmi::Error::Range)?);
        self.write32(HEADER, header(protocol, command, token));
        self.write_bytes(PAYLOAD, tx);
        hal_aarch64::mmio_barrier();
        Ok(())
    }

    fn transfer_poll(&self, token: u16, protocol: u8, command: u8, tx: &[u8], rx: &mut [u8]) -> scmi::Result<usize> {
        self.prepare(token, protocol, command, tx, false)?;
        self.invoke()?;
        // An SMC transport's synchronous command has completed when the SMC
        // instruction returns.  The shared-memory response is ready now; no
        // second polling protocol is layered over that transport contract.
        hal_aarch64::mmio_barrier();
        self.response(token, protocol, command, self.read32(STATUS), rx)
    }

    fn transfer_irq(&self, token: u16, protocol: u8, command: u8, tx: &[u8], rx: &mut [u8]) -> scmi::Result<usize> {
        if !sched::live::runqueue_active() { return Err(scmi::Error::Busy); }
        loop {
            let mut completion = self.completion.lock_irqsave::<hal_aarch64::ArmIrqGate>();
            if !completion.active {
                completion.active = true;
                completion.sent = false;
                completion.outcome = None;
                drop(completion);
                break;
            }
            // SAFETY: completion excludes its IRQ waker until this task is
            // visible on idle_wait; the guard drops before schedule().
            unsafe { self.idle_wait.prepare_to_wait(); }
            drop(completion);
            // SAFETY: process context, a live runqueue, and no completion lock held.
            unsafe { sched::live::schedule(); }
            self.idle_wait.remove_current();
        }
        if let Err(error) = self.prepare(token, protocol, command, tx, true) {
            let mut completion = self.completion.lock_irqsave::<hal_aarch64::ArmIrqGate>();
            completion.active = false;
            completion.sent = false;
            drop(completion);
            self.idle_wait.wake_one();
            return Err(error);
        }
        {
            let mut completion = self.completion.lock_irqsave::<hal_aarch64::ArmIrqGate>();
            completion.token = token;
            completion.protocol = protocol;
            completion.command = command;
            completion.rx = rx.as_mut_ptr() as usize;
            completion.rx_len = rx.len();
            // The transfer is fully described before the doorbell can make an
            // a2p response observable to the interrupt handler.
            completion.sent = true;
        }
        if let Err(error) = self.invoke() {
            let mut completion = self.completion.lock_irqsave::<hal_aarch64::ArmIrqGate>();
            if completion.active && completion.token == token {
                completion.active = false;
                completion.sent = false;
                completion.outcome = None;
            }
            drop(completion);
            self.idle_wait.wake_one();
            return Err(error);
        }
        let deadline = timekeeper::monotonic_ns().saturating_add(RESPONSE_TIMEOUT_NS);
        loop {
            let mut completion = self.completion.lock_irqsave::<hal_aarch64::ArmIrqGate>();
            if let Some(outcome) = completion.outcome.take() {
                completion.active = false;
                completion.sent = false;
                drop(completion);
                self.idle_wait.wake_one();
                return outcome;
            }
            if timekeeper::monotonic_ns() >= deadline {
                completion.active = false;
                completion.sent = false;
                drop(completion);
                self.idle_wait.wake_one();
                return Err(scmi::Error::Communication);
            }
            // SAFETY: completion excludes the IRQ response until this task is
            // visible on response_wait; the timer wakes this exact park.
            unsafe { self.response_wait.prepare_to_wait_with_deadline(deadline); }
            drop(completion);
            // SAFETY: process context, a live runqueue, and no completion lock held.
            unsafe { sched::live::schedule(); }
            self.response_wait.remove_current();
        }
    }

    fn complete_from_irq(&self) {
        let mut completion = self.completion.lock_irqsave::<hal_aarch64::ArmIrqGate>();
        if !completion.active || !completion.sent || completion.outcome.is_some() { return; }
        hal_aarch64::mmio_barrier();
        let status = self.read32(STATUS);
        if status & (CHANNEL_FREE | CHANNEL_ERROR) == 0 { return; }
        let outcome = self.response_active(&completion, status);
        completion.outcome = Some(outcome);
        drop(completion);
        self.response_wait.wake_all();
    }

    fn response_active(&self, completion: &Completion, status: u32) -> scmi::Result<usize> {
        // SAFETY: transfer_irq stores this caller's mutable response slice
        // before enabling the interrupt and cannot return until this state is cleared.
        let rx = unsafe { core::slice::from_raw_parts_mut(completion.rx as *mut u8, completion.rx_len) };
        self.response(completion.token, completion.protocol, completion.command, status, rx)
    }

    fn response(&self, token: u16, protocol: u8, command: u8, status: u32, rx: &mut [u8]) -> scmi::Result<usize> {
        if status & CHANNEL_ERROR != 0 { return Err(scmi::Error::Communication); }
        let response_header = self.read32(HEADER);
        if response_header & 0x3ff != u32::from(command)
            || (response_header >> 10) & 0xff != u32::from(protocol)
            || (response_header >> 18) & u32::from(TOKEN_MASK) != u32::from(token) { return Err(scmi::Error::Protocol); }
        let length = usize::try_from(self.read32(LENGTH)).map_err(|_| scmi::Error::Range)?;
        if length < 8 || length > self.size.checked_sub(HEADER).ok_or(scmi::Error::Range)? { return Err(scmi::Error::Malformed); }
        let status = i32::from_le_bytes(self.read32(PAYLOAD).to_le_bytes());
        if status != 0 { return Err(status_error(status)); }
        let response = length - 8;
        if response > rx.len() { return Err(scmi::Error::NoMemory); }
        self.read_bytes(PAYLOAD + 4, &mut rx[..response]);
        Ok(response)
    }

    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: new maps size bytes and fixed SCMI header offsets are bounded.
        let value = unsafe { core::ptr::read_volatile((self.base as *const u8).add(offset).cast::<u32>()) };
        u32::from_le(value)
    }

    fn write32(&self, offset: usize, value: u32) {
        // SAFETY: new maps size bytes and callers write only SCMI header fields.
        unsafe { core::ptr::write_volatile((self.base as *mut u8).add(offset).cast::<u32>(), value.to_le()); }
    }

    fn write_bytes(&self, offset: usize, bytes: &[u8]) {
        for (index, byte) in bytes.iter().enumerate() {
            // SAFETY: prepare bounds the request to the mapped channel capacity.
            unsafe { core::ptr::write_volatile((self.base as *mut u8).add(offset + index), *byte); }
        }
    }

    fn read_bytes(&self, offset: usize, bytes: &mut [u8]) {
        for (index, byte) in bytes.iter_mut().enumerate() {
            // SAFETY: response bounds the payload to the mapped channel capacity.
            *byte = unsafe { core::ptr::read_volatile((self.base as *const u8).add(offset + index)) };
        }
    }
}

impl scmi::Transport for SmcTransport {
    fn call(&self, protocol: u8, command: u8, tx: &[u8], rx: &mut [u8]) -> scmi::Result<usize> {
        let token = self.next_token();
        if self.completion_irq.is_some() { return self.transfer_irq(token, protocol, command, tx, rx); }
        let _poll = self.poll_lock.lock();
        self.transfer_poll(token, protocol, command, tx, rx)
    }
}

struct Published { policy: Arc<cpufreq::Policy>, performance: Arc<scmi::Performance>, domain: scmi::Domain }
struct Driver { published: Spinlock<Vec<Published>, Devices> }

impl Driver {
    fn publish(&self, published: Published) -> bool {
        if cpufreq::register_policy(Arc::clone(&published.policy)).is_err() { return false; }
        self.published.lock().push(published);
        true
    }

    fn for_policy(&self, policy: &cpufreq::Policy) -> Option<(Arc<scmi::Performance>, scmi::Domain)> {
        self.published.lock().iter().find(|entry| core::ptr::eq(Arc::as_ptr(&entry.policy), policy))
            .map(|entry| (Arc::clone(&entry.performance), entry.domain.clone()))
    }

    fn for_cpu(&self, cpu: usize) -> Option<(Arc<scmi::Performance>, scmi::Domain)> {
        self.published.lock().iter().find(|entry| entry.policy.related_cpus.contains(&cpu))
            .map(|entry| (Arc::clone(&entry.performance), entry.domain.clone()))
    }
}

impl cpufreq::CpufreqOps for Driver {
    fn target_index(&self, policy: &cpufreq::Policy, index: usize) -> KResult<()> {
        let driver_data = policy.table.entries.get(index).ok_or(VfsError::Einval)?.driver_data;
        let (performance, domain) = self.for_policy(policy).ok_or(VfsError::Enodev)?;
        performance.set_index(&domain, usize::try_from(driver_data).map_err(|_| VfsError::Einval)?).map_err(scmi_error)
    }

    fn get(&self, cpu: usize) -> Option<u32> {
        let (performance, domain) = self.for_cpu(cpu)?;
        let hz = performance.frequency_hz(&domain).ok()?;
        (hz % cpufreq::limits::HZ_PER_KHZ == 0).then(|| u32::try_from(hz / cpufreq::limits::HZ_PER_KHZ).ok()).flatten()
    }
}

/// Probe polling SCMI channels and reserve this SCMI provider for any a2p channel. # C: O(FDT × SCMI)
pub(super) fn init() -> usize {
    let Some(tree) = super::super::blob() else { return 0; };
    let records = ::fdt::scmi_perf_protocols(tree);
    if records.is_empty() { return 0; }
    let Some(driver) = driver() else { return 0; };
    if records.iter().any(|record| record.completion_irq.is_some()) {
        A2P_PENDING.store(true, Ordering::Release);
    }
    probe(&records, &driver, false)
}

/// Schedule a2p-channel probe only after completion waits can run in a worker. # C: O(1)
pub(super) fn start_deferred() {
    DEFERRED_READY.store(true, Ordering::Release);
    if A2P_PENDING.load(Ordering::Acquire) { schedule_a2p_probe(); }
}

/// Dispatch an architecture-owned `a2p` completion line. # C: O(SCMI controllers)
pub(super) fn handle_completion_irq(intid: u32) -> bool {
    let transports = A2P_TRANSPORTS.lock();
    let mut owned = false;
    for transport in transports.iter().filter(|transport| transport.completion_irq.is_some_and(|irq| irq.intid == intid)) {
        owned = true;
        transport.complete_from_irq();
    }
    owned
}

fn schedule_a2p_probe() {
    if !DEFERRED_READY.load(Ordering::Acquire)
        || A2P_QUEUED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
    if !sched::live::workqueue::queue_work(probe_a2p, 0) {
        A2P_QUEUED.store(false, Ordering::Release);
    }
}

fn probe_a2p(_: usize) {
    A2P_PENDING.store(false, Ordering::Release);
    let Some(tree) = super::super::blob() else { A2P_QUEUED.store(false, Ordering::Release); return; };
    if let Some(driver) = DRIVER.lock().clone() { let _ = probe(&::fdt::scmi_perf_protocols(tree), &driver, true); }
    A2P_QUEUED.store(false, Ordering::Release);
    if A2P_PENDING.swap(false, Ordering::AcqRel) { schedule_a2p_probe(); }
}

fn driver() -> Option<Arc<Driver>> {
    if let Some(driver) = DRIVER.lock().clone() { return Some(driver); }
    if cpufreq::driver::driver().is_some() { return None; }
    let driver = Arc::new(Driver { published: Spinlock::new(Vec::new()) });
    if cpufreq::register_driver("scmi-cpufreq", driver.clone()).is_err() { return None; }
    *DRIVER.lock() = Some(Arc::clone(&driver));
    Some(driver)
}

fn probe(records: &[ScmiPerfProtocol], driver: &Arc<Driver>, a2p: bool) -> usize {
    let mut candidates = Vec::new();
    for record in records.iter().filter(|record| record.completion_irq.is_some() == a2p) {
        let Some(transport) = SmcTransport::new(record) else { continue; };
        if a2p && !transport.bind_completion() { continue; }
        let transport: Arc<dyn scmi::Transport> = transport;
        let Ok(performance) = scmi::Performance::open(transport) else { continue; };
        let performance = Arc::new(performance);
        candidates.extend(domains(record, &performance));
    }
    candidates.into_iter().filter(|candidate| candidate.policy.related_cpus.iter().all(|cpu| cpufreq::policy_for(*cpu).is_none()))
        .map(|candidate| driver.publish(candidate)).filter(|published| *published).count()
}

fn domains(record: &ScmiPerfProtocol, performance: &Arc<scmi::Performance>) -> Vec<Published> {
    let mut groups: Vec<(u32, Vec<usize>)> = Vec::new();
    for cpu_domain in &record.cpu_domains {
        let Some(cpu) = cpu::logical_id_for_hardware(cpu_domain.cpu_mpidr).and_then(|cpu| usize::try_from(cpu).ok()) else { continue; };
        if let Some((_, cpus)) = groups.iter_mut().find(|(domain, _)| *domain == cpu_domain.domain_id) { cpus.push(cpu); }
        else { groups.push((cpu_domain.domain_id, alloc::vec![cpu])); }
    }
    groups.into_iter().filter_map(|(id, cpus)| build_domain(Arc::clone(performance), id, cpus)).collect()
}

fn build_domain(performance: Arc<scmi::Performance>, id: u32, cpus: Vec<usize>) -> Option<Published> {
    let domain = performance.domain(id).ok()?;
    if !domain.can_set_level || cpus.is_empty() { return None; }
    let current = performance.frequency_hz(&domain).ok()?;
    if current % cpufreq::limits::HZ_PER_KHZ != 0 { return None; }
    let entries: Vec<_> = domain.opps.iter().enumerate().map(|(index, opp)| {
        let frequency = u32::try_from(opp.frequency_hz / cpufreq::limits::HZ_PER_KHZ).ok()?;
        (opp.frequency_hz % cpufreq::limits::HZ_PER_KHZ == 0 && frequency != 0).then_some(cpufreq::FreqEntry {
            frequency, driver_data: u32::try_from(index).ok()?, flags: opp.turbo.then_some(cpufreq::uapi::FLAG_BOOST).unwrap_or(0),
        })
    }).collect::<Option<_>>()?;
    let table = cpufreq::FreqTable::new(entries).ok()?;
    let current = u32::try_from(current / cpufreq::limits::HZ_PER_KHZ).ok()?;
    if !table.entries.iter().any(|entry| entry.frequency == current) { return None; }
    let latency = domain.transition_latency_ns.max(cpufreq::limits::DEFAULT_TRANSITION_LATENCY_NS);
    let policy = cpufreq::Policy::new(cpus, table, latency, current, cpufreq::governor::default_governor().name)?;
    Some(Published { policy, performance, domain })
}

fn header(protocol: u8, command: u8, token: u16) -> u32 {
    u32::from(command) | (u32::from(protocol) << 10) | (u32::from(token) << 18)
}

fn status_error(status: i32) -> scmi::Error {
    match status {
        -1 => scmi::Error::Unsupported, -2 => scmi::Error::Invalid, -3 => scmi::Error::Access,
        -4 => scmi::Error::NotFound, -5 => scmi::Error::Range, -6 => scmi::Error::Busy,
        -7 => scmi::Error::Communication, -8 => scmi::Error::Io, -9 => scmi::Error::RemoteIo,
        -10 => scmi::Error::Protocol, _ => scmi::Error::Protocol,
    }
}

fn scmi_error(error: scmi::Error) -> VfsError {
    match error { scmi::Error::Busy => VfsError::Ebusy, scmi::Error::Invalid | scmi::Error::Range => VfsError::Einval,
                  scmi::Error::NotFound => VfsError::Enodev, _ => VfsError::Eio }
}
