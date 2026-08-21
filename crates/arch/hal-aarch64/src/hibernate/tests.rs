use super::*;
use alloc::boxed::Box;
use alloc::vec::Vec;

fn header() -> ArchHeader {
    ArchHeader { version: ARCH_HEADER_VERSION, continuation_va: 0xffff_0000_0012_3456,
        context_pa: 0x40_0000, image_ttbr1_pa: 0x50_0000, kernel_load_pa: 0x80_0000,
        boot_mpidr: 0x8000_0000, exception_level: EXCEPTION_LEVEL_1,
        mte_tag_pages: 0, cpu_signature: 0x410f_d0c0,
        mair_el1: 0xff44_0000, tcr_el1: 0x8080_3520, sctlr_el1: 0x30d0_0801 }
}

fn plan<'a>(collisions: &'a [Collision], safe_pages: &'a [u64]) -> RestorePlan<'a> {
    let _ = collisions;
    RestorePlan { safe_pages, temporary_ttbr0_pa: 0x30_0000,
        temporary_ttbr1_pa: 0x31_0000, trampoline_pa: 0x32_0000,
        arguments_pa: 0x34_0000, collision_head_pa: 0,
        zero_page_pa: 0x33_0000,
        identity_map: PhysRange { start: 0x30_0000, end: 0x41_0000 },
        linear_map: LinearMap { physical: PhysRange { start: 0x10_0000, end: 0x60_0000 },
            va_offset: 0xffff_0000_0000_0000 } }
}

#[test]
fn header_word_order_round_trips_every_saved_field() {
    let h = header();
    let words = h.words();
    assert_eq!(ArchHeader::from_words(words), h);
    assert_eq!(words, [ARCH_HEADER_VERSION, h.continuation_va, h.context_pa,
        h.image_ttbr1_pa, h.kernel_load_pa, h.boot_mpidr, h.exception_level,
        h.mte_tag_pages, h.cpu_signature, h.mair_el1, h.tcr_el1, h.sctlr_el1]);
    assert_eq!(core::mem::size_of::<ArchHeader>(), words.len() * core::mem::size_of::<u64>());
}

#[test]
fn header_offsets_are_the_persistent_field_order() {
    assert_eq!(core::mem::offset_of!(ArchHeader, version), 0x00);
    assert_eq!(core::mem::offset_of!(ArchHeader, continuation_va), 0x08);
    assert_eq!(core::mem::offset_of!(ArchHeader, context_pa), 0x10);
    assert_eq!(core::mem::offset_of!(ArchHeader, image_ttbr1_pa), 0x18);
    assert_eq!(core::mem::offset_of!(ArchHeader, kernel_load_pa), 0x20);
    assert_eq!(core::mem::offset_of!(ArchHeader, boot_mpidr), 0x28);
    assert_eq!(core::mem::offset_of!(ArchHeader, exception_level), 0x30);
    assert_eq!(core::mem::offset_of!(ArchHeader, mte_tag_pages), 0x38);
    assert_eq!(core::mem::offset_of!(ArchHeader, cpu_signature), 0x40);
    assert_eq!(core::mem::offset_of!(ArchHeader, mair_el1), 0x48);
    assert_eq!(core::mem::offset_of!(ArchHeader, tcr_el1), 0x50);
    assert_eq!(core::mem::offset_of!(ArchHeader, sctlr_el1), 0x58);
}

#[test]
fn current_cpu_admission_checks_every_runtime_field() {
    let h = header();
    let current = CurrentHeader { continuation_va: h.continuation_va,
        boot_mpidr: h.boot_mpidr, exception_level: h.exception_level, cpu_signature: h.cpu_signature,
        mair_el1: h.mair_el1, tcr_el1: h.tcr_el1, sctlr_el1: h.sctlr_el1,
        mte_supported: false };
    assert_eq!(validate_current_header(&h, current), Ok(()));
    let mut relocated_image = h;
    relocated_image.kernel_load_pa += PAGE_BYTES;
    assert_eq!(validate_current_header(&relocated_image, current), Ok(()));
    for index in 0..7 {
        let mut changed = current;
        match index {
            0 => changed.continuation_va ^= 1,
            1 => changed.boot_mpidr ^= 1,
            2 => changed.exception_level = EXCEPTION_LEVEL_2,
            3 => changed.cpu_signature ^= 1,
            4 => changed.mair_el1 ^= 1,
            5 => changed.tcr_el1 ^= 1,
            _ => changed.sctlr_el1 ^= 1,
        }
        assert_eq!(validate_current_header(&h, changed), Err(PlanError::CurrentCpu));
    }
    let mut tagged_cpu = current;
    tagged_cpu.mte_supported = true;
    assert_eq!(validate_current_header(&h, tagged_cpu), Err(PlanError::MteUnsupported));
}

#[test]
fn every_collision_is_covered_and_control_pages_survive() {
    let h = header();
    let collisions = [
        Collision { source_pa: 0x10_0000, destination_pa: 0x20_0000 },
        Collision { source_pa: 0x11_0000, destination_pa: 0x21_0000 },
        Collision { source_pa: 0x12_0000, destination_pa: 0x22_0000 },
    ];
    let safe = [0x30_0000, 0x31_0000, 0x32_0000, 0x33_0000, 0x34_0000, 0x35_0000];
    let p = plan(&collisions, &safe);
    assert_eq!(validate_restore_plan(&h, &p), Ok(()));
}

#[test]
fn tagged_memory_is_refused_until_tags_have_a_persistent_owner() {
    let mut h = header();
    h.mte_tag_pages = 1;
    assert_eq!(validate_header(&h), Err(PlanError::MteUnsupported));
}

#[test]
fn mte_capable_restore_cpu_is_refused_without_a_tag_stream() {
    let h = header();
    let current = CurrentHeader { continuation_va: h.continuation_va,
        boot_mpidr: h.boot_mpidr, exception_level: h.exception_level, cpu_signature: h.cpu_signature,
        mair_el1: h.mair_el1, tcr_el1: h.tcr_el1, sctlr_el1: h.sctlr_el1,
        mte_supported: true };
    assert_eq!(validate_current_header(&h, current), Err(PlanError::MteUnsupported));
}

#[test]
fn mte_refuses_the_architecture_before_machine_hook_advertisement() {
    assert!(restore_path_available_for(false));
    assert!(!restore_path_available_for(true));
}

#[test]
fn el2_is_not_admitted_without_a_hypervisor_state_owner() {
    let mut h = header();
    h.exception_level = EXCEPTION_LEVEL_2;
    assert_eq!(validate_header(&h), Err(PlanError::Header));
}

#[test]
fn restore_order_cleans_before_switching_to_the_image_tables() {
    let copy = RESTORE_ORDER.iter().position(|s| *s == RestoreStep::CopyCollisions).unwrap();
    let clean = RESTORE_ORDER.iter().position(|s| *s == RestoreStep::CleanDestinationsToPou).unwrap();
    let image = RESTORE_ORDER.iter().position(|s| *s == RestoreStep::BreakBeforeMakeImageTtbr1).unwrap();
    let icache = RESTORE_ORDER.iter().position(|s| *s == RestoreStep::InvalidateInstructionCache).unwrap();
    let state = RESTORE_ORDER.iter().position(|s| *s == RestoreStep::RestoreProcessorState).unwrap();
    assert!(copy < clean && clean < image && image < icache && icache < state);
    assert!(RESTORE_PATH_COMPLETE,
        "the installed machine hook may advertise disk only with this complete terminal path");
}

#[test]
fn hibernation_uses_the_existing_cpu_state_owner() {
    assert_eq!(core::mem::size_of::<HibernationCpuState>(),
        core::mem::size_of::<crate::cpu_suspend_ctx::SuspendCtx>());
}

#[test]
fn a_destination_cannot_overwrite_any_safe_control_page() {
    let collisions = [Collision { source_pa: 0x10_0000, destination_pa: 0x34_0000 }];
    let mut node = Box::new(CollisionPage { next_pa: 0, count: 1,
        entries: [Collision { source_pa: 0, destination_pa: 0 }; COLLISIONS_PER_PAGE] });
    node.entries[0] = collisions[0];
    let node_pa = (&*node as *const CollisionPage) as u64;
    let safe = [0x10_0000, 0x30_0000, 0x31_0000, 0x32_0000, 0x33_0000, 0x34_0000, node_pa];
    let mut p = plan(&[], &safe);
    p.collision_head_pa = node_pa;
    p.linear_map = LinearMap { physical: PhysRange { start: 0x10_0000,
        end: node_pa.checked_add(PAGE_BYTES).unwrap() }, va_offset: 0 };
    // SAFETY: boxed aligned node remains exclusively pinned for this walk.
    assert_eq!(unsafe { validate_collision_chain(&p) }, Err(PlanError::ControlCollision));
}

#[test]
fn duplicate_destinations_are_rejected_before_terminal_entry() {
    let collisions = [Collision { source_pa: 0x10_0000, destination_pa: 0x20_0000 },
        Collision { source_pa: 0x11_0000, destination_pa: 0x20_0000 }];
    let mut node = Box::new(CollisionPage { next_pa: 0, count: 2,
        entries: [Collision { source_pa: 0, destination_pa: 0 }; COLLISIONS_PER_PAGE] });
    node.entries[..2].copy_from_slice(&collisions);
    let node_pa = (&*node as *const CollisionPage) as u64;
    let safe = [0x10_0000, 0x11_0000, 0x30_0000, 0x31_0000, 0x32_0000,
        0x33_0000, 0x34_0000, node_pa];
    let mut p = plan(&[], &safe);
    p.collision_head_pa = node_pa;
    p.linear_map = LinearMap { physical: PhysRange { start: 0x10_0000,
        end: node_pa.checked_add(PAGE_BYTES).unwrap() }, va_offset: 0 };
    // SAFETY: boxed aligned node remains exclusively pinned for this walk.
    assert_eq!(unsafe { validate_collision_chain(&p) }, Err(PlanError::DuplicateDestination));
}

#[test]
fn physical_collision_chain_restores_frame_zero() {
    let mut node = Box::new(CollisionPage { next_pa: 0, count: 1,
        entries: [Collision { source_pa: 0, destination_pa: 0 }; COLLISIONS_PER_PAGE] });
    node.entries[0] = Collision { source_pa: 0x10_0000, destination_pa: 0 };
    let node_pa = (&*node as *const CollisionPage) as u64;
    let safe = [0x10_0000, node_pa];
    let mut p = plan(&[], &safe);
    p.collision_head_pa = node_pa;
    p.linear_map = LinearMap { physical: PhysRange { start: 0,
        end: node_pa.checked_add(PAGE_BYTES).unwrap() }, va_offset: 0 };
    // SAFETY: boxed aligned node remains exclusively pinned for this walk.
    assert_eq!(unsafe { validate_collision_chain(&p) }, Ok(1));
}

#[test]
fn collision_storage_capacity_is_checked_without_rounding_overflow() {
    let node = Box::new(CollisionPage { next_pa: 0, count: COLLISIONS_PER_PAGE as u64 + 1,
        entries: [Collision { source_pa: 0, destination_pa: 0 }; COLLISIONS_PER_PAGE] });
    let node_pa = (&*node as *const CollisionPage) as u64;
    let safe = [0x30_0000, 0x31_0000, 0x32_0000, 0x33_0000, 0x34_0000, node_pa];
    let mut p = plan(&[], &safe);
    p.collision_head_pa = node_pa;
    p.linear_map = LinearMap { physical: PhysRange { start: 0x10_0000,
        end: node_pa.checked_add(PAGE_BYTES).unwrap() }, va_offset: 0 };
    // SAFETY: boxed aligned node remains exclusively pinned for this walk.
    assert_eq!(unsafe { validate_collision_chain(&p) }, Err(PlanError::Capacity));
}

const RESTORE_SRC: &str = include_str!("restore.rs");
const CPU_SUSPEND_SRC: &str = include_str!("../cpu_suspend.rs");

#[test]
fn terminal_loop_has_two_bbm_switches_and_required_cache_order() {
    assert_eq!(RESTORE_SRC.matches("msr ttbr1_el1, x21").count(), 2,
        "both TTBR1 replacements must break through the zero page");
    assert!(RESTORE_SRC.contains("dc cvau, x13"));
    assert!(RESTORE_SRC.contains("ic ialluis"));
    assert!(RESTORE_SRC.contains("msr mair_el1, x28"));
    assert!(RESTORE_SRC.contains("msr tcr_el1, x17"));
    assert!(RESTORE_SRC.contains("msr sctlr_el1, x16"));
    let mair = RESTORE_SRC.find("msr mair_el1, x28").unwrap();
    let temporary = RESTORE_SRC.find("msr ttbr1_el1, x19").unwrap();
    let copy = RESTORE_SRC.find("stp x8, x9, [x1], #16").unwrap();
    let clean = RESTORE_SRC.find("dc cvau, x13").unwrap();
    let image = RESTORE_SRC.rfind("msr ttbr1_el1, x20").unwrap();
    let icache = RESTORE_SRC.find("ic ialluis").unwrap();
    let branch = RESTORE_SRC.find("br x26").unwrap();
    let sctlr = RESTORE_SRC.find("msr sctlr_el1, x16").unwrap();
    assert!(mair < temporary && copy < clean && clean < image && image < sctlr
        && sctlr < icache && icache < branch);
}

#[test]
fn terminal_loop_maps_each_physical_collision_link_before_dereference() {
    let load = RESTORE_SRC.find("ldr x22, [x22]").unwrap();
    let map = RESTORE_SRC[load..].find("add x22, x22, x24").unwrap() + load;
    let next = RESTORE_SRC[map..].find("b 1b").unwrap() + map;
    assert!(load < map && map < next,
        "a physical next_pa must regain the temporary linear-map offset before the next node");
}

#[test]
fn hibernate_branches_to_the_single_existing_context_restore_body() {
    assert!(CPU_SUSPEND_SRC.contains(".global oxide_arm_resume_high"));
    assert!(CPU_SUSPEND_SRC.contains("pub fn hibernate_continuation_va()"));
    assert!(RESTORE_SRC.contains("continuation_va: h.continuation_va"));
    assert!(RESTORE_SRC.contains("oxide_arm_cpu_suspend_enter(state)"));
    assert!(RESTORE_SRC.contains("state.ttbr1_el1 & crate::PTE_PHYS_MASK"));
    assert!(!RESTORE_SRC.contains("msr vbar_el1"),
        "hibernate must not duplicate the shared saved-context restore body");
    assert!(RESTORE_SRC.contains("restore_cpu_extensions_after_reset"),
        "feature-gated per-CPU controls must be restored after the asm continuation");
}

#[test]
fn terminal_loop_is_stackless_and_calls_no_overwritable_code() {
    let asm = RESTORE_SRC.split("core::arch::global_asm!(").nth(1).unwrap()
        .split("extern \"C\"").next().unwrap();
    assert!(!asm.contains(" bl "));
    assert!(!asm.contains(" sp,"));
    assert!(!asm.contains("[sp"));
}

#[repr(align(4096))]
struct TestPage([u8; 4096]);

#[test]
fn temporary_tables_consume_only_caller_owned_safe_pages() {
    const TEST_HHDM: u64 = 0x1000_0000;
    let h = header();
    let linear = LinearMap { physical: PhysRange { start: 0x20_0000, end: 0x60_0000 },
        va_offset: 0xffff_0000_0000_0000 };
    let mut root0 = Box::new(TestPage([0; 4096]));
    let mut root1 = Box::new(TestPage([0; 4096]));
    let root0_pa = root0.0.as_mut_ptr() as u64 - TEST_HHDM;
    let root1_pa = root1.0.as_mut_ptr() as u64 - TEST_HHDM;
    let mut pages: Vec<Box<TestPage>> = (0..12).map(|_| Box::new(TestPage([0; 4096]))).collect();
    let mut next = 0;
    let mut alloc = || { let page = pages.get_mut(next)?; next += 1;
        Some(page.0.as_mut_ptr() as u64 - TEST_HHDM) };
    // SAFETY: every boxed page is aligned, zeroed, exclusive and translated back by TEST_HHDM.
    assert_eq!(unsafe { build_temporary_tables(&h, root0_pa, root1_pa, TEST_HHDM,
        0x32_0000, linear, &mut alloc) }, Ok(()));

    let mut empty0 = Box::new(TestPage([0; 4096]));
    let mut empty1 = Box::new(TestPage([0; 4096]));
    let empty0_pa = empty0.0.as_mut_ptr() as u64 - TEST_HHDM;
    let empty1_pa = empty1.0.as_mut_ptr() as u64 - TEST_HHDM;
    // SAFETY: roots have identical ownership; refusal is the positive control for missing safe tables.
    assert_eq!(unsafe { build_temporary_tables(&h, empty0_pa, empty1_pa, TEST_HHDM,
        0x32_0000, linear, || None) }, Err(PlanError::Capacity));
}
