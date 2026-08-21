use super::*;
extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

fn header() -> ArchHeader {
    ArchHeader { version: ARCH_HEADER_VERSION, continuation_va: 0xffff_8000_0012_3456,
        cpu_state_va: 0xffff_8000_0020_0080, restore_entry_va: 0xffff_8000_0040_0123,
        restore_entry_pa: 0x40_0123, image_cr3_pa: 0x60_0000, xsave_xcr0: 7,
        cpu_signature: 0x306a9, paging_levels: 4 }
}

#[test]
fn header_word_order_round_trips_every_saved_field() {
    let h = header();
    let words = h.words();
    assert_eq!(ArchHeader::from_words(words), h);
    assert_eq!(words, [ARCH_HEADER_VERSION, h.continuation_va, h.cpu_state_va,
        h.restore_entry_va, h.restore_entry_pa, h.image_cr3_pa, h.xsave_xcr0,
        h.cpu_signature, h.paging_levels]);
    assert_eq!(core::mem::size_of::<ArchHeader>(), words.len() * core::mem::size_of::<u64>());
}

#[test]
fn header_offsets_are_the_persistent_field_order() {
    assert_eq!(core::mem::offset_of!(ArchHeader, version), 0x00);
    assert_eq!(core::mem::offset_of!(ArchHeader, continuation_va), 0x08);
    assert_eq!(core::mem::offset_of!(ArchHeader, cpu_state_va), 0x10);
    assert_eq!(core::mem::offset_of!(ArchHeader, restore_entry_va), 0x18);
    assert_eq!(core::mem::offset_of!(ArchHeader, restore_entry_pa), 0x20);
    assert_eq!(core::mem::offset_of!(ArchHeader, image_cr3_pa), 0x28);
    assert_eq!(core::mem::offset_of!(ArchHeader, xsave_xcr0), 0x30);
    assert_eq!(core::mem::offset_of!(ArchHeader, cpu_signature), 0x38);
    assert_eq!(core::mem::offset_of!(ArchHeader, paging_levels), 0x40);
}

#[test]
fn every_collision_is_covered_and_control_pages_survive() {
    let h = header();
    let collisions = [
        Collision { source_pa: 0x10_0000, destination_pa: 0x20_0000 },
        Collision { source_pa: 0x11_0000, destination_pa: 0x21_0000 },
        Collision { source_pa: 0x12_0000, destination_pa: 0x22_0000 },
    ];
    let p = RestorePlan { collisions: &collisions, temporary_cr3_pa: 0x30_0000,
        trampoline_pa: 0x31_0000, stack_pa: 0x32_0000,
        direct_map: PhysRange { start: 0x10_0000, end: 0x33_0000 },
        restored_text: TextMapping { va: h.restore_entry_va & !(PAGE_BYTES - 1),
            pa: h.restore_entry_pa & !(PAGE_BYTES - 1) } };
    assert_eq!(validate_restore_plan(&h, &p), Ok(()));
}

#[test]
fn physical_frame_zero_is_a_valid_restore_destination_not_a_null_control() {
    let h = header();
    let collisions = [Collision { source_pa: 0x10_0000, destination_pa: 0 }];
    let p = RestorePlan { collisions: &collisions, temporary_cr3_pa: 0x30_0000,
        trampoline_pa: 0x31_0000, stack_pa: 0x32_0000,
        direct_map: PhysRange { start: 0, end: 0x33_0000 },
        restored_text: TextMapping { va: h.restore_entry_va & !(PAGE_BYTES - 1),
            pa: h.restore_entry_pa & !(PAGE_BYTES - 1) } };
    assert_eq!(validate_restore_plan(&h, &p), Ok(()));
}

#[test]
fn a_destination_overwriting_restore_control_is_rejected() {
    let h = header();
    let collisions = [Collision { source_pa: 0x10_0000, destination_pa: 0x31_0000 }];
    let p = RestorePlan { collisions: &collisions, temporary_cr3_pa: 0x30_0000,
        trampoline_pa: 0x31_0000, stack_pa: 0x32_0000,
        direct_map: PhysRange { start: 0x10_0000, end: 0x33_0000 },
        restored_text: TextMapping { va: h.restore_entry_va & !(PAGE_BYTES - 1),
            pa: h.restore_entry_pa & !(PAGE_BYTES - 1) } };
    assert_eq!(validate_restore_plan(&h, &p), Err(PlanError::ControlCollision));
}

#[test]
fn restore_order_switches_to_safe_code_before_copy_and_image_tables_after() {
    let safe = RESTORE_ORDER.iter().position(|s| *s == RestoreStep::EnterSafeCode).unwrap();
    let copy = RESTORE_ORDER.iter().position(|s| *s == RestoreStep::CopyCollisions).unwrap();
    let image = RESTORE_ORDER.iter().position(|s| *s == RestoreStep::InstallImageCr3).unwrap();
    let state = RESTORE_ORDER.iter().position(|s| *s == RestoreStep::RestoreProcessorState).unwrap();
    assert!(safe < copy && copy < image && image < state);
    assert!(RESTORE_PATH_COMPLETE,
        "the installed machine hook may advertise disk only with this complete terminal path");
    assert!(restore_path_available());
}

#[test]
fn hibernation_uses_the_existing_cpu_state_owner() {
    assert_eq!(core::mem::size_of::<HibernationCpuState>(),
        core::mem::size_of::<crate::suspend::SavedCpuState>());
}

#[test]
fn captured_continuation_runs_the_canonical_full_processor_restore() {
    let src = include_str!("save.rs");
    let lowlevel = src.find("suspend_lowlevel(state, image)").unwrap();
    let restore = src.find("restore_processor_state(state)").unwrap();
    assert!(lowlevel < restore, "full CPU-global restore must follow the asm continuation");
}

#[test]
fn collision_and_terminal_pages_have_one_persistent_layout() {
    assert_eq!(core::mem::size_of::<CollisionPage>(), PAGE_BYTES as usize);
    assert_eq!(core::mem::align_of::<CollisionPage>(), PAGE_BYTES as usize);
    assert_eq!(core::mem::offset_of!(CollisionPage, next_pa), 0);
    assert_eq!(core::mem::offset_of!(CollisionPage, count), 8);
    assert_eq!(core::mem::offset_of!(CollisionPage, entries), 16);
    assert_eq!(core::mem::size_of::<TerminalControl>(), 6 * core::mem::size_of::<u64>());
}

#[repr(align(4096))]
struct TestPage([u8; 4096]);

#[test]
fn temporary_tables_need_safe_pages_and_accept_them_when_supplied() {
    const TEST_HHDM: u64 = BLOCK_BYTES;
    let h = header();
    let direct = PhysRange { start: 0x10_0000, end: 0x33_0000 };
    let text = TextMapping { va: h.restore_entry_va & !(PAGE_BYTES - 1),
        pa: h.restore_entry_pa & !(PAGE_BYTES - 1) };
    let mut root = Box::new(TestPage([0; 4096]));
    let root_va = root.0.as_mut_ptr() as u64;
    let root_pa = root_va - TEST_HHDM;
    let mut pages: Vec<Box<TestPage>> = (0..8).map(|_| Box::new(TestPage([0; 4096]))).collect();
    let mut next = 0;
    let mut alloc = || {
        let p = pages.get_mut(next)?;
        next += 1;
        Some(p.0.as_mut_ptr() as u64 - TEST_HHDM)
    };
    // SAFETY: every boxed page is aligned, zeroed, exclusively held and the
    // synthetic HHDM translates each synthetic PA back to its allocation.
    assert_eq!(unsafe { build_temporary_tables(&h, root_pa, TEST_HHDM, direct, text, &mut alloc) }, Ok(()));

    let mut empty_root = Box::new(TestPage([0; 4096]));
    let empty_pa = empty_root.0.as_mut_ptr() as u64 - TEST_HHDM;
    // SAFETY: the root has the same ownership; the empty allocator is the
    // deterministic negative control for incomplete safe-page allocation.
    assert_eq!(unsafe { build_temporary_tables(&h, empty_pa, TEST_HHDM, direct, text, || None) },
        Err(PlanError::TooMany));
}

#[test]
fn terminal_asm_never_uses_the_stack_while_copying() {
    let src = include_str!("terminal.rs");
    let start = src.find("\"oxide_hibernate_terminal_start:\"").unwrap();
    let end = src.find("\"oxide_hibernate_terminal_end:\"").unwrap();
    let body = &src[start..end];
    assert!(!body.contains("push"));
    assert!(!body.contains("pop"));
    assert!(!body.contains("call"));
    assert!(!body.contains("rsp"));
    let temporary = body.find("\"    mov  cr3, rsi\"").unwrap();
    let copy = body.find("\"    rep  movsq\"").unwrap();
    let restored = body.find("\"    jmp  r11\"").unwrap();
    assert!(temporary < copy && copy < restored);
}

#[test]
fn terminal_control_is_derived_from_the_admitted_header() {
    let h = header();
    let c = terminal_control(&h, 0x70_0000, 0xffff_8000_0000_0000).unwrap();
    assert_eq!(c.collision_head_pa, 0x70_0000);
    assert_eq!(c.image_cr3_pa, h.image_cr3_pa);
    assert_eq!(c.restore_entry_va, h.restore_entry_va);
    assert_eq!(c.continuation_va, h.continuation_va);
    assert_eq!(c.cpu_state_va, h.cpu_state_va);
}

#[test]
fn physical_collision_chain_positive_control_admits_only_safe_destinations() {
    let mut node = Box::new(CollisionPage { next_pa: 0, count: 2,
        entries: [Collision::default(); COLLISIONS_PER_PAGE] });
    node.entries[0] = Collision { source_pa: 0x10_0000, destination_pa: 0x20_0000 };
    node.entries[1] = Collision { source_pa: 0x11_0000, destination_pa: 0x21_0000 };
    let node_pa = 0x30_0000;
    let hhdm = (&*node as *const CollisionPage as u64) - node_pa;
    let safe = [node_pa, 0x31_0000, 0x32_0000, 0x33_0000, 0x10_0000, 0x11_0000];
    let direct = PhysRange { start: 0x10_0000, end: 0x34_0000 };
    // SAFETY: the synthetic HHDM resolves `node_pa` to this pinned boxed node;
    // the other safe pages are compared as addresses but never dereferenced.
    assert_eq!(unsafe { validate_collision_chain(node_pa, hhdm, direct, &safe) }, Ok(2));

    node.entries[1].destination_pa = safe[2];
    // SAFETY: same mapping; mutation completed before this second read-only walk.
    assert_eq!(unsafe { validate_collision_chain(node_pa, hhdm, direct, &safe) },
        Err(PlanError::ControlCollision));

    node.entries[1].destination_pa = 0x21_0000;
    node.entries[1].source_pa = node.entries[0].source_pa;
    // SAFETY: same mapping; this is the duplicate-source negative control.
    assert_eq!(unsafe { validate_collision_chain(node_pa, hhdm, direct, &safe) },
        Err(PlanError::Duplicate));
}

#[test]
fn physical_collision_chain_restores_frame_zero() {
    let mut node = Box::new(CollisionPage { next_pa: 0, count: 1,
        entries: [Collision::default(); COLLISIONS_PER_PAGE] });
    node.entries[0] = Collision { source_pa: 0x10_0000, destination_pa: 0 };
    let node_pa = 0x30_0000;
    let hhdm = (&*node as *const CollisionPage as u64) - node_pa;
    let safe = [node_pa, 0x10_0000];
    let direct = PhysRange { start: 0, end: 0x31_0000 };
    // SAFETY: the synthetic HHDM resolves the pinned boxed node for this read-only walk.
    assert_eq!(unsafe { validate_collision_chain(node_pa, hhdm, direct, &safe) }, Ok(1));
}

extern "C" fn hosted_image_callback() -> u64 { 0x51ee_0001 }

#[test]
fn image_callback_runs_inside_the_canonical_suspend_continuation() {
    let mut state = HibernationCpuState::new();
    // SAFETY: hosted fallback performs no privileged access and the state stays local and stable.
    let result = unsafe { capture_image_continuation(&mut state, hosted_image_callback) };
    assert_eq!(result, 0x51ee_0001);
    assert_eq!(state.enter_result, result);
    assert!(!state.armed());
}

#[test]
fn captured_header_uses_the_same_continuation_state_and_cr3() {
    let mut state = HibernationCpuState::new();
    state.resume_rip = 0xffff_8000_0012_3456;
    state.cr3 = 0x60_0a5a;
    let h = header_from_captured_state(&state, 0xffff_8000_0040_0123, 0x40_0123,
        7, 0x306a9, 4).unwrap();
    assert_eq!(h.continuation_va, state.resume_rip);
    assert_eq!(h.cpu_state_va, &state as *const HibernationCpuState as u64);
    assert_eq!(h.image_cr3_pa, 0x60_0000);
}

#[test]
fn current_cpu_admission_checks_every_runtime_field() {
    let h = header();
    let current = CurrentHeader { restore_entry_va: h.restore_entry_va,
        restore_entry_pa: h.restore_entry_pa, xsave_xcr0: h.xsave_xcr0,
        cpu_signature: h.cpu_signature, paging_levels: h.paging_levels };
    assert_eq!(validate_current_header(&h, current), Ok(()));
    for index in 0..5 {
        let mut changed = current;
        match index {
            0 => changed.restore_entry_va ^= 1,
            1 => changed.restore_entry_pa ^= 1,
            2 => changed.xsave_xcr0 ^= 1,
            3 => changed.cpu_signature ^= 1,
            _ => changed.paging_levels = 5,
        }
        assert_eq!(validate_current_header(&h, changed), Err(PlanError::Header));
    }
}
