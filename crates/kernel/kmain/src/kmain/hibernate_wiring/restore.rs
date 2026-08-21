//! Cold-image safe planning and irreversible architecture transfer.

use alloc::vec::Vec;
use core::convert::Infallible;

use power::hibernate::restore::SafeRestore;
use power::{Error, KResult};

use super::snapshot::RestoreMemory;

type Frame = pmm::setup::KernelHibernateFrame;

#[cfg(target_arch = "x86_64")]
pub struct PreparedArchRestore {
    restore: SafeRestore<Frame>,
    memory: RestoreMemory,
    entry: hal_x86_64::hibernate::TerminalEntry,
    control_va: u64,
    root_pa: u64,
}

#[cfg(target_arch = "aarch64")]
pub struct PreparedArchRestore {
    restore: SafeRestore<Frame>,
    memory: RestoreMemory,
    header: hal_aarch64::hibernate::ArchHeader,
    safe: Vec<u64>,
    ttbr0_pa: u64,
    ttbr1_pa: u64,
    trampoline_pa: u64,
    arguments_pa: u64,
    collision_head_pa: u64,
    zero_page_pa: u64,
    identity_map: hal_aarch64::hibernate::PhysRange,
    linear_map: hal_aarch64::hibernate::LinearMap,
}

fn words<const N: usize>(bytes: &[u8; 128]) -> KResult<[u64; N]> {
    let used = N.checked_mul(core::mem::size_of::<u64>()).ok_or(Error::Inval)?;
    if used > bytes.len() || bytes[used..].iter().any(|byte| *byte != 0) {
        return Err(Error::Inval);
    }
    let mut words = [0u64; N];
    for (index, word) in words.iter_mut().enumerate() {
        *word = u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap());
    }
    Ok(words)
}

fn managed_pa(pa: u64) -> bool {
    if !pa.is_multiple_of(hal::PAGE_SIZE_BYTES) { return false; }
    let pfn = pa / hal::PAGE_SIZE_BYTES;
    pmm::setup::memory_topology().iter().any(|region|
        region.start.0 <= pfn && pfn < region.end.0 && matches!(region.kind,
            boot_info::BootMemKind::Usable | boot_info::BootMemKind::KernelImage |
            boot_info::BootMemKind::Initramfs))
}

/// Validate architecture and live CPU state before any destination is claimed.
/// # C: O(memory regions)
pub fn validate_arch_header(bytes: &[u8; 128]) -> KResult<()> {
    #[cfg(target_arch = "x86_64")]
    {
        use hal_x86_64::hibernate as arch;
        let header = arch::ArchHeader::from_words(words::<9>(bytes)?);
        let (family, model, stepping) = hal_x86_64::cpuid_family_model();
        let signature = ((family as u64) << 32) | ((model as u64) << 16) | stepping as u64;
        let current = arch::CurrentHeader { restore_entry_va: arch::restore_entry_va(),
            restore_entry_pa: arch::restore_entry_pa().ok_or(Error::Nodata)?,
            xsave_xcr0: hal_x86_64::xsave_xcr0(), cpu_signature: signature,
            paging_levels: 4 };
        arch::validate_current_header(&header, current).map_err(map_x86)?;
        let hhdm = pmm::setup::direct_map_base();
        let state_pa = header.cpu_state_va.checked_sub(hhdm).ok_or(Error::Inval)?;
        if hhdm == 0 || !managed_pa(state_pa) || !managed_pa(header.image_cr3_pa)
            || !managed_pa(header.restore_entry_pa & !(hal::PAGE_SIZE_BYTES - 1))
        { return Err(Error::Inval); }
    }
    #[cfg(target_arch = "aarch64")]
    {
        use hal_aarch64::hibernate as arch;
        let header = arch::ArchHeader::from_words(words::<12>(bytes)?);
        arch::validate_current_header(&header, arch::current_header())
            .map_err(map_arm)?;
        if !managed_pa(header.context_pa) || !managed_pa(header.image_ttbr1_pa)
            || !managed_pa(header.kernel_load_pa)
        { return Err(Error::Inval); }
    }
    Ok(())
}

fn control_pa(restore: &SafeRestore<Frame>, index: usize) -> KResult<u64> {
    restore.control_pfn(index).ok_or(Error::Nodata)?
        .checked_mul(hal::PAGE_SIZE_BYTES).ok_or(Error::Inval)
}

fn allocate(restore: &mut SafeRestore<Frame>, memory: &mut RestoreMemory) -> KResult<(usize, u64)> {
    let index = restore.allocate_control(memory)?;
    Ok((index, control_pa(restore, index)?))
}

fn safe_pages(restore: &SafeRestore<Frame>) -> KResult<Vec<u64>> {
    let mut pages = Vec::new();
    pages.try_reserve_exact(restore.safe_page_count()).map_err(|_| Error::Nomem)?;
    for index in 0..restore.safe_page_count() { pages.push(restore.safe_pa(index)?); }
    Ok(pages)
}

#[cfg(target_arch = "x86_64")]
fn plan_begin(phase: power::hibernate::log::RestorePlanPhase) {
    power::hibernate::log::restore_plan(phase, None);
}

#[cfg(target_arch = "x86_64")]
fn plan_result<T>(phase: power::hibernate::log::RestorePlanPhase, result: KResult<T>) -> KResult<T> {
    match result {
        Ok(value) => {
            power::hibernate::log::restore_plan(phase,
                Some(power::hibernate::log::SnapshotResult::Ok));
            Ok(value)
        }
        Err(error) => {
            power::hibernate::log::restore_plan(phase,
                Some(power::hibernate::log::SnapshotResult::from(error)));
            Err(error)
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn map_x86(error: hal_x86_64::hibernate::PlanError) -> Error {
    use hal_x86_64::hibernate::PlanError;
    use power::hibernate::log::RestorePlanReason;
    power::hibernate::log::restore_plan_reason(match error {
        PlanError::Header => RestorePlanReason::Header,
        PlanError::Alignment => RestorePlanReason::Alignment,
        PlanError::Range => RestorePlanReason::Range,
        PlanError::ControlCollision => RestorePlanReason::ControlCollision,
        PlanError::Duplicate => RestorePlanReason::Duplicate,
        PlanError::Unmapped => RestorePlanReason::Unmapped,
        PlanError::TooMany => RestorePlanReason::TooMany,
    });
    Error::Inval
}

#[cfg(target_arch = "x86_64")]
fn prepare(mut restore: SafeRestore<Frame>, mut memory: RestoreMemory,
        bytes: &[u8; 128]) -> KResult<PreparedArchRestore> {
    use hal_x86_64::hibernate as arch;
    let header = arch::ArchHeader::from_words(words::<9>(bytes)?);
    plan_begin(power::hibernate::log::RestorePlanPhase::Header);
    plan_result(power::hibernate::log::RestorePlanPhase::Header,
        arch::validate_header(&header).map_err(map_x86))?;
    let current_va = arch::restore_entry_va();
    let current_pa = arch::restore_entry_pa().ok_or(Error::Nodata)?;
    if header.restore_entry_va != current_va || header.restore_entry_pa != current_pa {
        return Err(Error::Inval);
    }
    plan_begin(power::hibernate::log::RestorePlanPhase::CollisionChain);
    plan_result(power::hibernate::log::RestorePlanPhase::CollisionChain,
        restore.prepare_collision_chain(&mut memory))?;
    plan_begin(power::hibernate::log::RestorePlanPhase::FixedControl);
    let (root_index, root_pa, trampoline_index, trampoline_pa, stack_pa, control_index) =
        plan_result(power::hibernate::log::RestorePlanPhase::FixedControl, (|| {
            let (root_index, root_pa) = allocate(&mut restore, &mut memory)?;
            let (trampoline_index, trampoline_pa) = allocate(&mut restore, &mut memory)?;
            let (_, stack_pa) = allocate(&mut restore, &mut memory)?;
            let (control_index, _) = allocate(&mut restore, &mut memory)?;
            Ok((root_index, root_pa, trampoline_index, trampoline_pa, stack_pa, control_index))
        })())?;
    let hhdm = memory.direct_map_base()?;
    let (start, end) = memory.physical_span()?;
    let direct = arch::PhysRange { start, end };
    let text = arch::TextMapping { va: current_va & !(hal::PAGE_SIZE_BYTES - 1),
        pa: current_pa & !(hal::PAGE_SIZE_BYTES - 1) };
    let mut allocation_error = None;
    // SAFETY: every root/table allocation is zeroed, exclusively pinned by
    // `restore`, HHDM mapped, and excluded from every image destination.
    plan_begin(power::hibernate::log::RestorePlanPhase::Tables);
    let tables = unsafe { arch::build_temporary_tables(&header, root_pa, hhdm, direct, text, || {
        match allocate(&mut restore, &mut memory) {
            Ok((_, pa)) => Some(pa),
            Err(error) => { allocation_error = Some(error); None }
        }
    }) };
    let tables = match allocation_error { Some(error) => Err(error), None => tables.map_err(map_x86) };
    plan_result(power::hibernate::log::RestorePlanPhase::Tables, tables)?;
    plan_begin(power::hibernate::log::RestorePlanPhase::CollisionView);
    let collisions = plan_result(power::hibernate::log::RestorePlanPhase::CollisionView, (|| {
        let mut collisions = Vec::new();
        collisions.try_reserve_exact(restore.collision_count()).map_err(|_| Error::Nomem)?;
        for index in 0..restore.collision_count() { collisions.push(restore.x86_collision(index)?); }
        Ok(collisions)
    })())?;
    let plan = arch::RestorePlan { collisions: &collisions, temporary_cr3_pa: root_pa,
        trampoline_pa, stack_pa, direct_map: direct, restored_text: text };
    plan_begin(power::hibernate::log::RestorePlanPhase::PlanValidation);
    power::hibernate::log::restore_plan_facts(root_pa, trampoline_pa, stack_pa,
        direct.start, direct.end);
    let validation = arch::validate_restore_plan(&header, &plan);
    if validation.is_err() {
        for (index, collision) in collisions.iter().enumerate() {
            let invalid_alignment = collision.source_pa == 0 || collision.destination_pa == 0
                || collision.source_pa % hal::PAGE_SIZE_BYTES != 0
                || collision.destination_pa % hal::PAGE_SIZE_BYTES != 0
                || collision.source_pa == collision.destination_pa;
            let control_collision = [root_pa, trampoline_pa, stack_pa]
                .contains(&collision.destination_pa);
            let unmapped = !direct.contains_page(collision.source_pa)
                || !direct.contains_page(collision.destination_pa);
            if invalid_alignment || control_collision || unmapped {
                power::hibernate::log::restore_plan_collision(index as u64,
                    collision.source_pa, collision.destination_pa);
                break;
            }
        }
    }
    plan_result(power::hibernate::log::RestorePlanPhase::PlanValidation,
        validation.map_err(map_x86))?;
    plan_begin(power::hibernate::log::RestorePlanPhase::SafeView);
    let safe = plan_result(power::hibernate::log::RestorePlanPhase::SafeView, safe_pages(&restore))?;
    // SAFETY: generic ownership pins every physical node/source and the HHDM
    // maps the admitted canonical RAM interval for this allocation-free walk.
    plan_begin(power::hibernate::log::RestorePlanPhase::ChainValidation);
    plan_result(power::hibernate::log::RestorePlanPhase::ChainValidation,
        unsafe { arch::validate_collision_chain(restore.collision_head_pa(), hhdm, direct, &safe) }
            .map_err(map_x86))?;
    plan_begin(power::hibernate::log::RestorePlanPhase::TerminalControl);
    let control = plan_result(power::hibernate::log::RestorePlanPhase::TerminalControl,
        arch::terminal_control(&header, restore.collision_head_pa(), hhdm).map_err(map_x86))?;
    let control_frame = restore.control(control_index).ok_or(Error::Nodata)?;
    // SAFETY: this zeroed pinned frame is the sole TerminalControl owner until entry.
    unsafe { core::ptr::write(control_frame.as_mut_ptr() as *mut arch::TerminalControl, control); }
    plan_begin(power::hibernate::log::RestorePlanPhase::TerminalInstall);
    let entry = plan_result(power::hibernate::log::RestorePlanPhase::TerminalInstall, (|| {
        let trampoline = restore.control(trampoline_index).ok_or(Error::Nodata)?;
        let trampoline_va = hhdm.checked_add(trampoline_pa).ok_or(Error::Inval)?;
        // SAFETY: the selected frame is writable, destination-safe and remains pinned forever on success.
        unsafe { arch::install_terminal(trampoline.as_mut_ptr(), trampoline_va, trampoline_pa) }
            .map_err(map_x86)
    })())?;
    let control_va = hhdm.checked_add(control_pa(&restore, control_index)?).ok_or(Error::Inval)?;
    let _ = root_index;
    Ok(PreparedArchRestore { restore, memory, entry, control_va, root_pa })
}

#[cfg(target_arch = "aarch64")]
fn map_arm(error: hal_aarch64::hibernate::PlanError) -> Error {
    use hal_aarch64::hibernate::PlanError;
    use power::hibernate::log::RestorePlanReason;
    power::hibernate::log::restore_plan_reason(match error {
        PlanError::Header => RestorePlanReason::Header,
        PlanError::Alignment => RestorePlanReason::Alignment,
        PlanError::Range => RestorePlanReason::Range,
        PlanError::ControlCollision => RestorePlanReason::ControlCollision,
        PlanError::Unmapped => RestorePlanReason::Unmapped,
        PlanError::MteUnsupported => RestorePlanReason::MteUnsupported,
        PlanError::DuplicateDestination => RestorePlanReason::Duplicate,
        PlanError::Capacity => RestorePlanReason::Capacity,
        PlanError::CurrentCpu => RestorePlanReason::CurrentCpu,
        PlanError::Continuation => RestorePlanReason::Continuation,
    });
    Error::Inval
}

#[cfg(target_arch = "aarch64")]
fn prepare(mut restore: SafeRestore<Frame>, mut memory: RestoreMemory,
        bytes: &[u8; 128]) -> KResult<PreparedArchRestore> {
    use hal_aarch64::hibernate as arch;
    const BLOCK_BYTES: u64 = 2 * 1024 * 1024;
    let header = arch::ArchHeader::from_words(words::<12>(bytes)?);
    arch::validate_header(&header).map_err(map_arm)?;
    restore.prepare_collision_chain(&mut memory)?;
    let (_, ttbr0_pa) = allocate(&mut restore, &mut memory)?;
    let (_, ttbr1_pa) = allocate(&mut restore, &mut memory)?;
    let (_, trampoline_pa) = allocate(&mut restore, &mut memory)?;
    let (_, arguments_pa) = allocate(&mut restore, &mut memory)?;
    let (_, zero_page_pa) = allocate(&mut restore, &mut memory)?;
    let hhdm = memory.direct_map_base()?;
    let (physical_start, physical_end) = memory.physical_span()?;
    let start = physical_start & !(BLOCK_BYTES - 1);
    let end = physical_end.checked_add(BLOCK_BYTES - 1).ok_or(Error::Inval)? & !(BLOCK_BYTES - 1);
    let linear = arch::LinearMap { physical: arch::PhysRange { start, end }, va_offset: hhdm };
    let mut allocation_error = None;
    // SAFETY: roots and callback pages are zeroed, exclusively pinned safe frames.
    let tables = unsafe { arch::build_temporary_tables(&header, ttbr0_pa, ttbr1_pa, hhdm,
        trampoline_pa, linear, || match allocate(&mut restore, &mut memory) {
            Ok((_, pa)) => Some(pa),
            Err(error) => { allocation_error = Some(error); None }
        }) };
    if let Some(error) = allocation_error { return Err(error); }
    tables.map_err(map_arm)?;
    let safe = safe_pages(&restore)?;
    let identity_start = core::cmp::min(trampoline_pa, header.context_pa);
    let identity_end = core::cmp::max(trampoline_pa, header.context_pa)
        .checked_add(hal::PAGE_SIZE_BYTES).ok_or(Error::Inval)?;
    let plan = arch::RestorePlan { safe_pages: &safe, temporary_ttbr0_pa: ttbr0_pa,
        temporary_ttbr1_pa: ttbr1_pa, trampoline_pa, arguments_pa,
        collision_head_pa: restore.collision_head_pa(), zero_page_pa,
        identity_map: arch::PhysRange { start: identity_start, end: identity_end }, linear_map: linear };
    arch::validate_restore_plan(&header, &plan).map_err(map_arm)?;
    let collision_head_pa = plan.collision_head_pa;
    let identity_map = plan.identity_map;
    let linear_map = plan.linear_map;
    Ok(PreparedArchRestore { restore, memory, header, safe, ttbr0_pa, ttbr1_pa,
        trampoline_pa, arguments_pa, collision_head_pa, zero_page_pa,
        identity_map, linear_map })
}

/// Build and validate every architecture restore operand before quiescing.
/// # C: O(image pages + mapped physical blocks)
/// # Ctx: blockable process context
pub fn prepare_arch_restore(restore: SafeRestore<Frame>, memory: RestoreMemory,
        arch_data: &[u8; 128]) -> KResult<PreparedArchRestore> {
    prepare(restore, memory, arch_data)
}

/// Enter one completely prepared, allocation-free terminal restore.
///
/// # Safety
/// Caller holds the sole hibernation transition with one CPU and interrupts
/// disabled; `restore` owns every loaded destination/source until terminal entry.
/// # C: O(image pages + mapped physical blocks)
/// # Ctx: IRQ-off, single CPU, terminal on success
pub unsafe fn enter_arch_restore(prepared: PreparedArchRestore) -> KResult<Infallible> {
    #[cfg(target_arch = "x86_64")]
    {
        let PreparedArchRestore { restore, memory, entry, control_va, root_pa } = prepared;
        let _owners = (restore, memory);
        // SAFETY: preparation completed every fallible/allocation-bearing step.
        unsafe { hal_x86_64::hibernate::enter_terminal(entry, control_va, root_pa) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let PreparedArchRestore { restore, memory, header, safe, ttbr0_pa, ttbr1_pa,
            trampoline_pa, arguments_pa, collision_head_pa, zero_page_pa,
            identity_map, linear_map } = prepared;
        let plan = hal_aarch64::hibernate::RestorePlan { safe_pages: &safe,
            temporary_ttbr0_pa: ttbr0_pa, temporary_ttbr1_pa: ttbr1_pa,
            trampoline_pa, arguments_pa, collision_head_pa, zero_page_pa,
            identity_map, linear_map };
        let _owners = (&restore, &memory);
        // SAFETY: preparation owns every page/array and terminal entry is allocation-free.
        unsafe { hal_aarch64::hibernate::restore(&header, &plan) }.map_err(map_arm)
    }
}
