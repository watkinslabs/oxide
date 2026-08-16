// Layout, field-set and restore-order tests for the saved EL1 context.
//
// These read the text of `cpu_suspend.rs` and check the asm against the layout
// declared next door. A hosted run cannot execute an aarch64 resume entry, but
// it can prove that the entry loads the slot each system register is stored to,
// that nothing saved is left unrestored, and that the translation tables are in
// place before `SCTLR_EL1` turns the MMU back on — the three ways this file
// goes wrong that produce a machine which never wakes up.

use super::*;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::mem::{align_of, offset_of, size_of};

const ASM_SRC: &str = include_str!("../cpu_suspend.rs");

/// The instruction text of one labelled block, one line per element.
fn block(start: &str, end: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in ASM_SRC.lines() {
        let t = line.trim();
        if !inside {
            if t.contains(start) { inside = true; }
            continue;
        }
        if t.contains(end) { return out; }
        // Keep only assembler text: the quoted payload of a string literal.
        let Some(open) = t.find('"') else { continue };
        let rest = &t[open + 1..];
        let Some(close) = rest.rfind('"') else { continue };
        let insn = rest[..close].trim();
        if !insn.is_empty() { out.push(insn.to_string()); }
    }
    out
}

fn save_block() -> Vec<String> { block("\"oxide_arm_cpu_suspend_enter:\"", "save-block end") }
fn resume_block() -> Vec<String> { block("\"oxide_arm_resume_entry:\"", "resume-entry end") }

/// Parse `#0xNN]` out of a `[x0, #0xNN]` addressing operand.
fn offset_of_operand(insn: &str) -> Option<usize> {
    let at = insn.find("[x0, #")? + "[x0, #".len();
    let rest = &insn[at..];
    let close = rest.find(']')?;
    let digits = rest[..close].trim();
    let hex = digits.strip_prefix("0x")?;
    usize::from_str_radix(hex, 16).ok()
}

/// `(system register, slot offset)` pairs the save stub writes, in order.
fn saved_pairs() -> Vec<(String, usize)> {
    let b = save_block();
    let mut out = Vec::new();
    for i in 0..b.len().saturating_sub(1) {
        let Some(reg) = b[i].strip_prefix("mrs x1, ") else { continue };
        let st = &b[i + 1];
        assert!(st.starts_with("str x1, "), "mrs of {reg} is not followed by its store: {st}");
        out.push((reg.trim().to_string(), offset_of_operand(st).expect("store offset")));
    }
    out
}

/// `(system register, slot offset)` pairs the resume entry writes, in order.
fn restored_pairs() -> Vec<(String, usize)> {
    let b = resume_block();
    let mut out = Vec::new();
    for i in 0..b.len().saturating_sub(1) {
        let Some(off) = b[i].strip_prefix("ldr x3, ").and_then(offset_of_operand) else { continue };
        let Some(reg) = b[i + 1].strip_prefix("msr ") else { continue };
        let reg = reg.split(',').next().unwrap().trim();
        out.push((reg.to_string(), off));
    }
    out
}

/// Index of the first instruction satisfying `pred`.
fn find_at(b: &[String], pred: impl Fn(&str) -> bool) -> usize {
    b.iter().position(|l| pred(l)).expect("instruction not found in the resume entry")
}

#[test]
fn layout_matches_offsets() {
    assert_eq!(offset_of!(SuspendCtx, magic),             OFF_MAGIC);
    assert_eq!(offset_of!(SuspendCtx, self_pa),           OFF_SELF_PA);
    assert_eq!(offset_of!(SuspendCtx, self_va),           OFF_SELF_VA);
    assert_eq!(offset_of!(SuspendCtx, ttbr0_identity_pa), OFF_TTBR0_IDENTITY);
    assert_eq!(offset_of!(SuspendCtx, mair_el1),          OFF_MAIR_EL1);
    assert_eq!(offset_of!(SuspendCtx, tcr_el1),           OFF_TCR_EL1);
    assert_eq!(offset_of!(SuspendCtx, ttbr1_el1),         OFF_TTBR1_EL1);
    assert_eq!(offset_of!(SuspendCtx, sctlr_el1),         OFF_SCTLR_EL1);
    assert_eq!(offset_of!(SuspendCtx, ttbr0_el1),         OFF_TTBR0_EL1);
    assert_eq!(offset_of!(SuspendCtx, vbar_el1),          OFF_VBAR_EL1);
    assert_eq!(offset_of!(SuspendCtx, tpidr_el1),         OFF_TPIDR_EL1);
    assert_eq!(offset_of!(SuspendCtx, mdscr_el1),         OFF_MDSCR_EL1);
    assert_eq!(offset_of!(SuspendCtx, cpacr_el1),         OFF_CPACR_EL1);
    assert_eq!(offset_of!(SuspendCtx, contextidr_el1),    OFF_CONTEXTIDR_EL1);
    assert_eq!(offset_of!(SuspendCtx, tpidr_el0),         OFF_TPIDR_EL0);
    assert_eq!(offset_of!(SuspendCtx, tpidrro_el0),       OFF_TPIDRRO_EL0);
    assert_eq!(offset_of!(SuspendCtx, sp_el0),            OFF_SP_EL0);
    assert_eq!(offset_of!(SuspendCtx, x18),               OFF_X18);
    assert_eq!(offset_of!(SuspendCtx, sp),                OFF_SP);
    assert_eq!(offset_of!(SuspendCtx, lr),                OFF_LR);
    assert_eq!(offset_of!(SuspendCtx, fp),                OFF_FP);
    assert_eq!(offset_of!(SuspendCtx, x19),               OFF_X19);
    assert_eq!(offset_of!(SuspendCtx, x28),               OFF_X28);
    assert_eq!(align_of::<SuspendCtx>(), 16);
    assert_eq!(size_of::<SuspendCtx>() % 16, 0);
    assert!(size_of::<SuspendCtx>() > OFF_X28);
}

#[test]
fn a_fresh_context_carries_the_magic_and_nothing_else() {
    let c = SuspendCtx::new();
    assert!(c.magic_ok());
    assert_eq!(c.sctlr_el1, 0);
    assert_eq!(c.ttbr1_el1, 0);
    let mut bad = c;
    bad.magic ^= 1;
    assert!(!bad.magic_ok());
}

#[test]
fn the_save_stub_stores_every_declared_system_register_at_its_slot() {
    let got = saved_pairs();
    assert_eq!(got.len(), SAVED_SYSREGS.len(),
        "save stub covers {} system registers, layout declares {}", got.len(), SAVED_SYSREGS.len());
    for (name, off) in SAVED_SYSREGS {
        let hit = got.iter().find(|(r, _)| r == name);
        assert!(hit.is_some(), "{} is never saved", name);
        assert_eq!(hit.unwrap().1, off, "{} saved to the wrong slot", name);
    }
}

#[test]
fn every_saved_system_register_is_restored_from_the_same_slot() {
    let restored = restored_pairs();
    for (name, off) in SAVED_SYSREGS {
        // TTBR0 is written twice: the identity table across the MMU enable,
        // then the saved kernel value. Only the second reads the saved slot.
        let hits: Vec<usize> = restored.iter().filter(|(r, _)| r == name).map(|(_, o)| *o).collect();
        assert!(!hits.is_empty(), "{name} is saved but never restored");
        assert!(hits.contains(&off), "{name} restored from {hits:?}, not its slot {off:#x}");
    }
    // Nothing is restored that was never saved.
    for (name, _) in &restored {
        assert!(SAVED_SYSREGS.iter().any(|(n, _)| n == name),
            "{name} is restored from a slot the save stub never fills");
    }
}

#[test]
fn ttbr0_takes_the_identity_table_first_and_the_saved_value_after() {
    let restored = restored_pairs();
    let hits: Vec<usize> = restored.iter().filter(|(r, _)| r == "ttbr0_el1").map(|(_, o)| *o).collect();
    assert_eq!(hits, alloc::vec![OFF_TTBR0_IDENTITY, OFF_TTBR0_EL1],
        "the MMU-enable window must run on the identity table, the kernel table only after the branch");
}

#[test]
fn translation_state_is_installed_before_the_mmu_is_enabled() {
    let b = resume_block();
    let sctlr = find_at(&b, |l| l.starts_with("msr sctlr_el1"));
    for name in PRE_MMU_SYSREGS {
        let at = find_at(&b, |l| l.starts_with(&alloc::format!("msr {name}")));
        assert!(at < sctlr, "{name} is written after SCTLR_EL1 enables the MMU");
    }
}

#[test]
fn tlb_maintenance_and_barriers_sit_between_the_tables_and_the_mmu_enable() {
    let b = resume_block();
    let ttbr1 = find_at(&b, |l| l.starts_with("msr ttbr1_el1"));
    let tlbi  = find_at(&b, |l| l.starts_with("tlbi vmalle1"));
    let sctlr = find_at(&b, |l| l.starts_with("msr sctlr_el1"));
    assert!(ttbr1 < tlbi && tlbi < sctlr, "tlbi must follow the table install and precede the enable");
    assert!(b[tlbi - 1].starts_with("dsb"), "the tlbi needs a dsb ahead of it");
    assert!(b[tlbi + 1].starts_with("dsb"), "the tlbi needs a dsb behind it");
    assert!(b[tlbi + 2].starts_with("isb"), "the table install needs an isb before the enable");
    assert!(b[sctlr + 1].starts_with("isb"), "the MMU enable needs an isb behind it");
}

#[test]
fn the_rest_of_el1_state_is_restored_only_after_the_branch_to_the_kernel_half() {
    let b = resume_block();
    let high = find_at(&b, |l| l.starts_with("oxide_arm_resume_high:"));
    for name in POST_MMU_SYSREGS {
        let at = b.iter().rposition(|l| l.starts_with(&alloc::format!("msr {name}"))).expect(name);
        assert!(at > high, "{name} is restored before the MMU is on");
    }
    let sp = find_at(&b, |l| l.starts_with("mov sp,"));
    assert!(sp > high, "the stack pointer is reloaded before the MMU is on");
}

#[test]
fn the_magic_check_precedes_every_system_register_write() {
    let b = resume_block();
    let branch = find_at(&b, |l| l.starts_with("b.ne oxide_arm_resume_bad_magic"));
    let first_msr = find_at(&b, |l| l.starts_with("msr "));
    assert!(branch < first_msr, "a bad-magic resume would write system registers before stopping");
    assert!(b.iter().any(|l| l.starts_with("oxide_arm_resume_bad_magic:")),
        "the bad-magic branch has no landing pad");
    // The pad must not fall through into the restore path.
    let pad = find_at(&b, |l| l.starts_with("oxide_arm_resume_bad_magic:"));
    assert!(b[pad + 1..].iter().any(|l| l.starts_with("b oxide_arm_resume_bad_magic")),
        "the bad-magic pad falls through instead of parking");
}

#[test]
fn callee_saved_registers_round_trip_through_the_same_slots() {
    let save = save_block();
    let resume = resume_block();
    let regs = ["x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28",
                "x29", "x30"];
    for r in regs {
        let s = save.iter().find(|l| l.starts_with(&alloc::format!("str {r}, ")));
        let l = resume.iter().find(|l| l.starts_with(&alloc::format!("ldr {r}, ")));
        assert!(s.is_some(), "{} is never saved", r);
        assert!(l.is_some(), "{} is never restored", r);
        assert_eq!(offset_of_operand(s.unwrap()), offset_of_operand(l.unwrap()),
            "{} save/restore slots disagree", r);
    }
    // Stack pointer travels through OFF_SP in both directions.
    let sp_store = save.iter().find(|l| l.starts_with("str x1, ") && offset_of_operand(l) == Some(OFF_SP));
    assert!(sp_store.is_some(), "sp is never saved");
}

#[test]
fn the_two_paths_are_distinguishable_by_return_value() {
    let save = save_block();
    let resume = resume_block();
    assert!(save.iter().any(|l| l == "mov x0, #1"), "the save path must return nonzero");
    assert!(resume.iter().any(|l| l == "mov x0, #0"), "the resume path must return zero");
    assert_eq!(save.last().map(|s| s.as_str()), Some("ret"));
}

#[test]
fn the_magic_immediate_lanes_match_the_constant() {
    let b = resume_block();
    let lanes = [
        (OXIDE_SUSPEND_CTX_MAGIC & 0xffff, "movz x2, "),
        ((OXIDE_SUSPEND_CTX_MAGIC >> 16) & 0xffff, "movk x2, "),
        ((OXIDE_SUSPEND_CTX_MAGIC >> 32) & 0xffff, "movk x2, "),
        ((OXIDE_SUSPEND_CTX_MAGIC >> 48) & 0xffff, "movk x2, "),
    ];
    for (v, mnemonic) in lanes {
        let want = alloc::format!("{mnemonic}#{v:#06x}");
        assert!(b.iter().any(|l| l.starts_with(&want)),
            "no instruction builds magic lane {v:#06x} (looked for {want})");
    }
    let magic_load = find_at(&b, |l| l.starts_with("ldr x1, "));
    assert_eq!(offset_of_operand(&b[magic_load]), Some(OFF_MAGIC));
}
