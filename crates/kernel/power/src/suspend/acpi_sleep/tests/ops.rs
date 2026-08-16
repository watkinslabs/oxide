// The table itself: every member the sequence walks is present, the resume
// vector round-trips through its "zero means none" encoding, and `valid`
// answers from the published facts rather than from a constant.

use super::*;

#[test]
fn the_table_supplies_every_member_the_sequence_consults() {
    // A missing `enter` makes every state invalid however permissive `valid`
    // is (`32a§4`), and a missing `begin`/`end` pair silently skips the
    // platform's own bracket.
    assert!(ACPI_SUSPEND_OPS.valid.is_some());
    assert!(ACPI_SUSPEND_OPS.begin.is_some());
    assert!(ACPI_SUSPEND_OPS.prepare.is_some());
    assert!(ACPI_SUSPEND_OPS.prepare_late.is_some());
    assert!(ACPI_SUSPEND_OPS.enter.is_some());
    assert!(ACPI_SUSPEND_OPS.wake.is_some());
    assert!(ACPI_SUSPEND_OPS.finish.is_some());
    assert!(ACPI_SUSPEND_OPS.end.is_some());
    // Deliberately absent: ACPI has no repeat-the-enter hook, and nothing to
    // unwind before the registers are touched.
    assert!(ACPI_SUSPEND_OPS.suspend_again.is_none());
    assert!(ACPI_SUSPEND_OPS.recover.is_none());
}

#[test]
fn no_resume_vector_is_published_before_the_stub_is_placed() {
    // Zero is a real physical address, so the encoding must distinguish it
    // from "none": publishing zero resumes the machine into the first page.
    assert_eq!(resume_vector(), None);
    set_resume_vector(0);
    assert_eq!(resume_vector(), Some(0));
    set_resume_vector(0x9000);
    assert_eq!(resume_vector(), Some(0x9000));
}

#[test]
fn valid_refuses_mem_while_the_facts_do_not_support_it() {
    // Hosted, no ACPI tables are published at all, so nothing is admitted —
    // which is exactly the answer a machine with no `_Sx` must give.
    let facts = platform_facts();
    assert!(!facts.s1_action);
    assert!(!facts.s3_action);
    assert!(facts.state_save, "the processor-context record is unconditional on this arch");
    assert!(!valid(SuspendState::Mem));
    assert!(!valid(SuspendState::Standby));
}
