//! Production write-side hibernation backend.

use alloc::vec::Vec;
use core::convert::Infallible;
use core::sync::atomic::{AtomicPtr, Ordering};
use power::hibernate::backend::{Backend, FinishMode, ResumeKind, Side};
use power::hibernate::{format, identity, image, log, mode, notifier, restore, settings, snapshot};
use power::{Error, KResult};
use super::{enter_arch_restore, prepare_arch_restore, validate_arch_header, FrozenFilesystems,
    ImageStorage, PreparedArchRestore, PreparedSnapshotMemory, RestoreMemory, SnapshotMemory,
    SnapshotStream};

type Frame = pmm::setup::KernelHibernateFrame;
type SavedFrame = pmm::setup::KernelHibernateSavedFrame;
type PhysicalSnapshot = snapshot::Snapshot<Frame>;
const CAPTURE_ORIGINAL: u64 = 1;
const CAPTURE_FAILED: u64 = 2;

struct CaptureContext {
    snapshot: *mut PhysicalSnapshot,
    prepared: *mut Option<PreparedSnapshotMemory>,
    memory: *mut Option<SnapshotMemory>,
    state_pfn: u64,
    error: Option<Error>,
}

static CAPTURE: AtomicPtr<CaptureContext> = AtomicPtr::new(core::ptr::null_mut());
extern "C" fn capture_pages() -> u64 {
    let ptr = CAPTURE.load(Ordering::Acquire);
    if ptr.is_null() { return CAPTURE_FAILED; }
    // SAFETY: arch_snapshot_and_copy publishes its stack context only for the
    // synchronous architecture callback; one transition and one CPU exclude
    // concurrent access, and the pointers name disjoint retained fields.
    let context = unsafe { &mut *ptr };
    power::hibernate::log::snapshot_phase(power::hibernate::log::SnapshotPhase::Callback,
        power::hibernate::log::SnapshotBoundary::Begin, 0);
    // SAFETY: the publishing caller retains every owner until callback return.
    let result = unsafe {
        let prepared = (&mut *context.prepared).take().ok_or(Error::Nodata);
        prepared.and_then(|prepared| {
            power::hibernate::log::snapshot_phase(power::hibernate::log::SnapshotPhase::FinalFree,
                power::hibernate::log::SnapshotBoundary::Begin, 0);
            let (memory, admission) = prepared.finalize();
            *context.memory = Some(memory);
            admission?;
            power::hibernate::log::snapshot_phase(power::hibernate::log::SnapshotPhase::FinalFree,
                power::hibernate::log::SnapshotBoundary::End, 0);
            Ok(())
        }).and_then(|()| {
            let memory = (&mut *context.memory).as_mut().ok_or(Error::Nodata)?;
            power::hibernate::log::snapshot_phase(power::hibernate::log::SnapshotPhase::Select,
                power::hibernate::log::SnapshotBoundary::Begin, 0);
            snapshot::prepare_into(memory, &mut *context.snapshot)?;
            power::hibernate::log::snapshot_phase(power::hibernate::log::SnapshotPhase::Select,
                power::hibernate::log::SnapshotBoundary::End,
                (&*context.snapshot).image_pages() as u64);
            if !(&*context.snapshot).contains_original_pfn(context.state_pfn) {
                return Err(Error::Inval);
            }
            power::hibernate::log::snapshot_phase(power::hibernate::log::SnapshotPhase::Copy,
                power::hibernate::log::SnapshotBoundary::Begin,
                (&*context.snapshot).image_pages() as u64);
            snapshot::capture(&mut *context.snapshot,
                (&*context.memory).as_ref().ok_or(Error::Nodata)?)?;
            power::hibernate::log::snapshot_phase(power::hibernate::log::SnapshotPhase::Copy,
                power::hibernate::log::SnapshotBoundary::End,
                (&*context.snapshot).image_pages() as u64);
            Ok(())
        })
    };
    power::hibernate::log::snapshot_result(match result {
        Ok(_) => power::hibernate::log::SnapshotResult::Ok,
        Err(error) => error.into(),
    });
    power::hibernate::log::snapshot_phase(power::hibernate::log::SnapshotPhase::Callback,
        power::hibernate::log::SnapshotBoundary::End, 0);
    match result {
        Ok(()) => CAPTURE_ORIGINAL,
        Err(error) => { context.error = Some(error); CAPTURE_FAILED }
    }
}

/// Machine-owned state retained across one generic write transaction.
pub(super) struct MachineBackend {
    settings: settings::Settings,
    selected_mode: mode::Mode,
    storage: Option<ImageStorage>,
    filesystems: Option<FrozenFilesystems>,
    hotplug: Option<drv::model::HotplugGuard>,
    memory: Option<SnapshotMemory>,
    prepared_memory: Option<PreparedSnapshotMemory>,
    snapshot: Option<PhysicalSnapshot>,
    arch_state: Option<SavedFrame>,
    arch_data: [u8; 128],
    marker: Option<image::PreparedMarker>,
    prepared_restore: Option<PreparedArchRestore>,
    cpus_off: bool,
    poweroff_active: bool,
    test_restore_active: bool,
}

impl MachineBackend {
    /// Resolve installed policy without acquiring mutable machine state.
    /// # C: O(target bytes)
    pub(super) fn new() -> KResult<Self> {
        let settings = settings::get().ok_or(Error::Nodata)?;
        if !settings.hibernate_enabled() { return Err(Error::Perm); }
        if !restore_path_available() { return Err(Error::Opnotsupp); }
        Ok(Self { settings, selected_mode: mode::selected(), storage: None,
            filesystems: None, hotplug: None,
            memory: None, prepared_memory: None, snapshot: None,
            arch_state: None, arch_data: [0; 128],
            marker: None, prepared_restore: None,
            cpus_off: false, poweroff_active: false, test_restore_active: false })
    }

    fn storage_mut(&mut self) -> KResult<&mut ImageStorage> {
        self.storage.as_mut().ok_or(Error::Nodata)
    }

    fn prepare_snapshot(&mut self) -> KResult<()> {
        let pmm = pmm::setup::pmm_static().ok_or(Error::Nodata)?;
        let state = pmm.alloc_hibernate_saved_frame().map_err(|_| Error::Nomem)?;
        init_arch_state(&state);
        let (prepared, snapshot) = SnapshotMemory::preallocate(self.settings.image_size(),
            self.settings.reserved_size(), self.settings.compression())?;
        self.storage_mut()?.preallocate_payload_pages(prepared.max_payload_pages()).map_err(map_swap)?;
        let mut prepared = prepared;
        prepared.seal()?;
        self.arch_state = Some(state);
        self.prepared_memory = Some(prepared);
        self.snapshot = Some(snapshot);
        Ok(())
    }

    fn capture(&mut self) -> KResult<Side> {
        if !sched::flush_current_fpu_for_hibernate() { return Err(Error::Nodata); }
        let snapshot = self.snapshot.as_mut().ok_or(Error::Nodata)? as *mut _;
        let prepared = &mut self.prepared_memory as *mut _;
        let memory = &mut self.memory as *mut _;
        let state_pfn = self.arch_state.as_ref().ok_or(Error::Nodata)?.pfn().0;
        let mut context = CaptureContext { snapshot, prepared, memory, state_pfn, error: None };
        if CAPTURE.compare_exchange(core::ptr::null_mut(), &mut context,
            Ordering::AcqRel, Ordering::Acquire).is_err() { return Err(Error::Busy); }
        power::hibernate::log::arch_continuation(power::hibernate::log::ArchContinuation::CaptureBegin, 0);
        let result = capture_arch(self.arch_state.as_ref().ok_or(Error::Nodata)?);
        if matches!(result, Ok(0)) { pmm::setup::pmm_static().ok_or(Error::Nodata)?.hibernate_restore_free_lists(); }
        power::hibernate::log::arch_continuation(power::hibernate::log::ArchContinuation::CaptureEnd,
            result.as_ref().copied().unwrap_or(u64::MAX));
        CAPTURE.store(core::ptr::null_mut(), Ordering::Release);
        if let Some(error) = context.error { return Err(error); }
        match result? {
            0 => {
                // Reload canonical Task FP/SIMD at the first Rust boundary;
                // hardware still contains the restore kernel's state.
                if !sched::restore_current_fpu_after_hibernate() { return Err(Error::Nodata); }
                timekeeper::suspend::resume_from_hibernation();
                Ok(Side::Restored)
            }
            CAPTURE_ORIGINAL => {
                self.arch_data = arch_data(self.arch_state.as_ref().unwrap())?;
                let snapshot = self.snapshot.as_ref().ok_or(Error::Nodata)?;
                let stream = SnapshotStream::new(snapshot).map_err(map_image)?;
                log::counts(snapshot.image_pages() as u64, stream.info().stream_pages,
                    snapshot.image_pages() as u64, 0);
                Ok(Side::Original)
            }
            _ => Err(Error::Io),
        }
    }

    fn stage(&mut self) -> KResult<()> {
        let snapshot = self.snapshot.as_ref().ok_or(Error::Nodata)?;
        let stream = SnapshotStream::new(snapshot).map_err(map_image)?;
        let payload_pages = image::max_stored_pages(stream.info().stream_pages as usize,
            self.settings.compression()).map_err(map_image)?;
        self.storage.as_mut().ok_or(Error::Nodata)?
            .reserve_payload_pages(payload_pages).map_err(map_swap)?;
        let mut header = blank_header(snapshot.image_pages() as u64,
            snapshot.zero_pfns().len() as u64, self.arch_data);
        let identity = power::hibernate::identity::stamp(&mut header);
        power::hibernate::log::compatibility(&header, &identity, true);
        let storage = self.storage.as_mut().ok_or(Error::Nodata)?;
        let borrowed = storage.plan_payload(payload_pages).map_err(map_swap)?;
        let mut maps = Vec::new();
        maps.try_reserve_exact(borrowed.map_pages.len()).map_err(|_| Error::Nomem)?;
        maps.extend_from_slice(borrowed.map_pages);
        let mut data = Vec::new();
        data.try_reserve_exact(borrowed.data_pages.len()).map_err(|_| Error::Nomem)?;
        data.extend_from_slice(borrowed.data_pages);
        let plan = image::Plan { header_page: borrowed.header_page,
            map_pages: &maps, data_pages: &data };
        self.marker = Some(image::stage_image(storage, &plan, header, &stream,
            self.settings.compression()).map_err(map_image)?);
        Ok(())
    }

    fn unwind_poweroff(&mut self) {
        if !self.poweroff_active { return; }
        crate::kmain::suspend_wiring::devices_resume_noirq();
        crate::kmain::suspend_wiring::devices_resume_early();
        crate::kmain::suspend_wiring::devices_resume();
        crate::kmain::suspend_wiring::devices_complete();
        self.poweroff_active = false;
    }

    fn load_test_image(&mut self) -> KResult<()> {
        log::resume_phase(log::ResumePath::Test, log::ResumePhase::Marker);
        let header_page = self.storage.as_ref().ok_or(Error::Nodata)?.header_page();
        let storage = self.storage.as_mut().ok_or(Error::Nodata)?;
        let reader = match image::ImageReader::open(storage, header_page) {
            Ok(reader) => reader,
            Err(image::Error::Io) => self.halt_with_live_image(),
            Err(error) => return Err(map_image(error)),
        };
        let arch_data = reader.header.arch_data;
        let expected = identity::current();
        log::resume_phase(log::ResumePath::Test, log::ResumePhase::Admit);
        let admission = restore::admit(&reader, &expected, validate_arch_header)?;
        log::resume_phase(log::ResumePath::Test, log::ResumePhase::Load);
        let mut memory = RestoreMemory::capture()?;
        let loaded = restore::load(admission, storage, &mut memory)?;
        log::resume_phase(log::ResumePath::Test, log::ResumePhase::SafePlan);
        let safe = restore::prepare_safe(loaded, &mut memory, 0)?;
        let prepared = prepare_arch_restore(safe, memory, &arch_data)?;
        self.arch_data = arch_data;
        self.prepared_restore = Some(prepared);
        self.test_restore_active = true;
        Ok(())
    }
}

/// Install the one public hibernation entry only with a complete cold path.
/// # C: O(1)
pub fn install() {
    if restore_path_available() {
        power::hibernate::entry::set_machine_hooks(Some(
            power::hibernate::entry::MachineHooks::new(run_machine, resume_machine)));
    }
}

fn run_machine() -> KResult<()> {
    let claim = power::transition::try_claim().ok_or(Error::Busy)?;
    let mut backend = MachineBackend::new()?;
    power::hibernate::run::hibernate_claimed(&claim, &mut backend)
}

fn resume_machine() {
    let _outcome: super::ResumeOutcome = super::software_resume();
}

impl Backend for MachineBackend {
    fn lease_acquire(&mut self) -> KResult<()> {
        let target = self.settings.write_target()?;
        log::target(&target.name, target.offset, self.selected_mode.label());
        self.storage = Some(ImageStorage::begin_target(&target.name, target.offset).map_err(map_swap)?);
        Ok(())
    }
    fn lease_release(&mut self) { self.storage = None; }
    fn console_prepare(&mut self) -> KResult<()> {
        (power::suspend::wire::backend().console_suspend)(); Ok(())
    }
    fn console_restore(&mut self) { (power::suspend::wire::backend().console_resume)(); }
    fn notify_prepare(&mut self) -> KResult<()> { notifier::prepare() }
    fn notify_post(&mut self) { notifier::post(); }
    fn sync_filesystems(&mut self) -> KResult<()> { super::filesystems::sync_all() }
    fn filesystems_freeze(&mut self) -> KResult<()> {
        self.filesystems = Some(FrozenFilesystems::freeze()?); Ok(())
    }
    fn filesystems_thaw(&mut self) {
        if let Some(filesystems) = self.filesystems.take() { filesystems.thaw(); }
    }
    fn users_freeze(&mut self) -> KResult<()> { crate::kmain::suspend_wiring::users_freeze() }
    fn users_thaw(&mut self) { crate::kmain::suspend_wiring::users_thaw(); }
    fn helpers_disable(&mut self) -> KResult<()> { crate::kmain::suspend_wiring::helpers_disable() }
    fn helpers_enable(&mut self) { crate::kmain::suspend_wiring::helpers_enable(); }
    fn hotplug_lock(&mut self) -> KResult<()> {
        self.hotplug = Some(crate::kmain::suspend_wiring::hotplug_lock()); Ok(())
    }
    fn hotplug_unlock(&mut self) { self.hotplug = None; }
    fn kernel_threads_freeze(&mut self) -> KResult<()> {
        crate::kmain::suspend_wiring::kernel_threads_freeze()
    }
    fn kernel_threads_thaw(&mut self) { crate::kmain::suspend_wiring::kernel_threads_thaw(); }
    fn snapshot_prepare(&mut self) -> KResult<()> { self.prepare_snapshot() }
    fn snapshot_release(&mut self) {
        super::release::all(&mut self.snapshot, &mut self.memory,
            &mut self.prepared_memory, &mut self.arch_state);
    }
    fn devices_prepare(&mut self) -> KResult<()> {
        let transition = if self.test_restore_active { drv::PmTransition::Hibernate }
            else { drv::PmTransition::Freeze };
        crate::kmain::suspend_wiring::devices_prepare(transition)
    }
    fn devices_freeze(&mut self) -> KResult<()> { crate::kmain::suspend_wiring::devices_suspend() }
    fn devices_late(&mut self) -> KResult<()> { crate::kmain::suspend_wiring::devices_late() }
    fn devices_noirq(&mut self) -> KResult<()> { crate::kmain::suspend_wiring::devices_noirq() }
    fn devices_resume_noirq(&mut self, kind: ResumeKind) {
        drv::pm::dpm_set_transition(resume_transition(kind));
        crate::kmain::suspend_wiring::devices_resume_noirq();
    }
    fn devices_resume_early(&mut self, _kind: ResumeKind) {
        crate::kmain::suspend_wiring::devices_resume_early();
    }
    fn devices_resume(&mut self, _kind: ResumeKind) { crate::kmain::suspend_wiring::devices_resume(); }
    fn devices_complete(&mut self, _kind: ResumeKind) { crate::kmain::suspend_wiring::devices_complete(); }
    fn cpus_off(&mut self) -> KResult<()> {
        if cpu::smp::online_count() <= 1 { return Ok(()); }
        let off = power::suspend::wire::hooks().disable_secondary_cpus.ok_or(Error::Opnotsupp)?;
        off()?; self.cpus_off = true; Ok(())
    }
    fn cpus_on(&mut self) -> KResult<()> {
        if !self.cpus_off { return Ok(()); }
        let on = power::suspend::wire::hooks().enable_secondary_cpus.ok_or(Error::Opnotsupp)?;
        on(); if !cpu::smp::frozen_cpumask().is_empty() { return Err(Error::Io); }
        self.cpus_off = false; Ok(())
    }
    fn irqs_off(&mut self) -> u64 { (power::suspend::wire::backend().irqs_off)() }
    fn irqs_on(&mut self, state: u64) { super::irq_restore::restore(state); }
    fn syscore_suspend(&mut self) -> KResult<()> { power::suspend::syscore::syscore_suspend() }
    fn syscore_resume(&mut self) { power::suspend::syscore::syscore_resume(); }
    fn arch_snapshot_and_copy(&mut self) -> KResult<Side> { self.capture() }
    fn serialize_image(&mut self) -> KResult<()> {
        self.stage()?;
        log::durability(log::Durability::PayloadFlushed);
        Ok(())
    }
    fn commit_marker(&mut self) -> KResult<()> {
        let marker = self.marker.take().ok_or(Error::Nodata)?;
        image::commit_image(self.storage_mut()?, marker).map_err(map_image)?;
        log::durability(log::Durability::MarkerCommitted);
        Ok(())
    }
    fn unmark_image(&mut self) -> KResult<()> {
        let page = self.storage.as_ref().ok_or(Error::Nodata)?.header_page();
        image::unmark_image(self.storage_mut()?, page).map_err(map_image)?;
        log::durability(log::Durability::MarkerConsumed);
        Ok(())
    }
    fn finish_mode(&self) -> FinishMode {
        match self.selected_mode {
            mode::Mode::Suspend => FinishMode::Suspend,
            mode::Mode::TestResume => FinishMode::TestResume,
            _ => FinishMode::PowerDown,
        }
    }
    fn suspend_with_image(&mut self) -> KResult<()> {
        let state = power::suspend::tunables::mem_sleep_current();
        let result = power::suspend::run::suspend_devices_and_enter(state,
            &power::suspend::wire::backend(), power::suspend::platform::installed());
        if result.is_err() { self.selected_mode = mode::fallback_after_suspend_failure(false); }
        result
    }
    fn prepare_test_resume(&mut self) -> KResult<()> {
        log::resume_phase(log::ResumePath::Test, log::ResumePhase::Target);
        self.load_test_image()
    }
    fn enter_test_resume(&mut self) -> KResult<Infallible> {
        log::resume_phase(log::ResumePath::Test, log::ResumePhase::Quiesce);
        let prepared = self.prepared_restore.take().ok_or(Error::Nodata)?;
        log::resume_phase(log::ResumePath::Test, log::ResumePhase::Terminal);
        // SAFETY: generic test-resume sequencing has one CPU and IRQs off;
        // the retained owners cover all destinations, sources and controls.
        unsafe { enter_arch_restore(prepared) }
    }
    fn devices_poweroff(&mut self) -> KResult<()> {
        if !matches!(self.selected_mode, mode::Mode::Shutdown | mode::Mode::Reboot) {
            return Err(Error::Opnotsupp);
        }
        crate::kmain::suspend_wiring::devices_prepare(drv::PmTransition::Hibernate)?;
        if let Err(error) = crate::kmain::suspend_wiring::devices_suspend() {
            crate::kmain::suspend_wiring::devices_complete(); return Err(error);
        }
        if let Err(error) = crate::kmain::suspend_wiring::devices_late() {
            crate::kmain::suspend_wiring::devices_resume();
            crate::kmain::suspend_wiring::devices_complete(); return Err(error);
        }
        if let Err(error) = crate::kmain::suspend_wiring::devices_noirq() {
            crate::kmain::suspend_wiring::devices_resume_early();
            crate::kmain::suspend_wiring::devices_resume();
            crate::kmain::suspend_wiring::devices_complete(); return Err(error);
        }
        self.poweroff_active = true;
        Ok(())
    }
    fn terminal(&mut self, claim: &power::transition::Claim) -> KResult<Infallible> {
        match self.selected_mode {
            // SAFETY: the completed image is durable and device shutdown has
            // finished, so this transaction owns the irreversible endpoint.
            mode::Mode::Shutdown => unsafe {
                power::terminal_claimed(claim, power::TerminalCmd::PowerOff)
            },
            // SAFETY: the completed image is durable and device shutdown has
            // finished, so this transaction owns the irreversible endpoint.
            mode::Mode::Reboot => unsafe {
                power::terminal_claimed(claim, power::TerminalCmd::Restart)
            },
            _ => { self.unwind_poweroff(); Err(Error::Opnotsupp) }
        }
    }
    fn halt_with_live_image(&mut self) -> ! {
        // SAFETY: continuing mutation with a committed image is forbidden.
        unsafe { power::halt() }
    }
}

fn resume_transition(kind: ResumeKind) -> drv::PmTransition {
    match kind { ResumeKind::Thaw => drv::PmTransition::Freeze,
                 ResumeKind::Restore => drv::PmTransition::Hibernate }
}

pub(super) fn restore_path_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::hibernate::restore_path_available() }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::hibernate::restore_path_available() }
}

fn blank_header(image_pages: u64, zero_pages: u64, arch_data: [u8; 128]) -> format::Header {
    format::Header { flags: 0, checksum: 0, first_map: 0, image_pages, zero_pages,
        stream_pages: 0, arch: 0, cpu_count: 0, hardware_sig: 0,
        build_id: [0; 32], topology_id: [0; 32], cpu_id: [0; 32], arch_data,
        original_sig: [0; 10] }
}

fn map_swap(error: pmm::swap::SwapError) -> Error {
    match error {
        pmm::swap::SwapError::Busy => Error::Busy,
        pmm::swap::SwapError::Inval => Error::Inval,
        pmm::swap::SwapError::NoMem => Error::Nomem,
        pmm::swap::SwapError::NoSuchArea => Error::Nodata,
        pmm::swap::SwapError::Io => Error::Io,
        pmm::swap::SwapError::NoSpace => Error::Nospc,
    }
}

pub(super) fn map_image(error: image::Error) -> Error {
    match error {
        image::Error::Io => Error::Io,
        image::Error::NoImage => Error::Nodata,
        image::Error::Unsupported => Error::Opnotsupp,
        image::Error::SwapSignature | image::Error::Format | image::Error::Bounds |
        image::Error::Cycle | image::Error::Duplicate | image::Error::PrematureEnd |
        image::Error::TrailingEntry | image::Error::Checksum => Error::Inval,
    }
}

fn init_arch_state(frame: &SavedFrame) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: frame is exclusively owned, page-aligned, and larger than the state.
    unsafe { frame.as_mut_ptr().cast::<hal_x86_64::hibernate::HibernationCpuState>()
        .write(hal_x86_64::hibernate::HibernationCpuState::new()); }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: frame is exclusively owned, page-aligned, and larger than the state.
    unsafe { frame.as_mut_ptr().cast::<hal_aarch64::hibernate::HibernationCpuState>()
        .write(hal_aarch64::hibernate::HibernationCpuState::new()); }
}

fn capture_arch(frame: &SavedFrame) -> KResult<u64> {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: transaction has one CPU, IRQs off and canonical task FP saved;
    // the exclusively owned frame retains the complete state across capture.
    unsafe { Ok(hal_x86_64::hibernate::capture_image_continuation(
        &mut *frame.as_mut_ptr().cast(), capture_pages)) }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: same single-CPU contract; PFN supplies the stable physical
    // address and the boot identity table is the canonical resume mapping.
    unsafe { hal_aarch64::hibernate::capture_image_continuation(
        &mut *frame.as_mut_ptr().cast(), frame.pfn().0 * hal::PAGE_SIZE_BYTES,
        hal_aarch64::smp::identity_ttbr0_pa(), capture_pages).map_err(|_| Error::Io) }
}

fn arch_data(frame: &SavedFrame) -> KResult<[u8; 128]> {
    #[cfg(target_arch = "x86_64")]
    let words = {
        let (family, model, stepping) = hal_x86_64::cpuid_family_model();
        let signature = ((family as u64) << 32) | ((model as u64) << 16) | stepping as u64;
        // SAFETY: the frame retains the state written by capture_arch.
        let state = unsafe { &*frame.as_ptr().cast() };
        hal_x86_64::hibernate::header_from_captured_state(state,
            hal_x86_64::hibernate::restore_entry_va(),
            hal_x86_64::hibernate::restore_entry_pa().ok_or(Error::Nodata)?,
            hal_x86_64::xsave_xcr0(), signature, 4).map_err(|_| Error::Io)?.words()
    };
    #[cfg(target_arch = "aarch64")]
    let words = {
        // SAFETY: the frame retains the state written by capture_arch.
        let state = unsafe { &*frame.as_ptr().cast() };
        let kernel_load = pmm::setup::memory_topology().iter()
            .find(|region| region.kind == boot_info::BootMemKind::KernelImage)
            .map(|region| region.start.0 * hal::PAGE_SIZE_BYTES).ok_or(Error::Nodata)?;
        hal_aarch64::hibernate::header_from_captured_state(state, kernel_load)
            .map_err(|_| Error::Io)?.words()
    };
    let mut out = [0u8; 128];
    for (index, word) in words.iter().enumerate() {
        out[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    Ok(out)
}
