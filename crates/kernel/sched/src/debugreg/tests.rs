// Hosted proof that a task's debug-register shadow is STORED, INSTALLABLE and
// CONSUMED — the ptrace-visible index map, the arming gate the context switch
// reads, and (on x86) the validation ladder a POKEUSER goes through.

use super::*;
use crate::task::{SchedClass, Task};

fn task() -> Task { Task::new(4001, "dbg", SchedClass::Normal { weight: 1024 }) }

#[test]
fn u_debugreg_indices_map_onto_the_shadow_including_the_hardware_aliases() {
    assert_eq!(slot_of_u_debugreg(0), Some(0));
    assert_eq!(slot_of_u_debugreg(3), Some(3));
    assert_eq!(slot_of_u_debugreg(6), Some(STATUS));
    assert_eq!(slot_of_u_debugreg(7), Some(CONTROL));
    // There are NO DR4/DR5 registers — they are not aliases of DR6/DR7.
    assert_eq!(slot_of_u_debugreg(4), None);
    assert_eq!(slot_of_u_debugreg(5), None);
    assert_eq!(slot_of_u_debugreg(8), None);
    assert!(is_status(6) && !is_status(4) && !is_status(7));
    assert!(is_control(7) && !is_control(5) && !is_control(6));
}

#[test]
fn a_fresh_task_is_unarmed_and_reads_zero() {
    let t = task();
    assert!(!armed(&t), "no breakpoint is set on a task nobody traced");
    for idx in [0usize, 1, 2, 3, 6, 7] { assert_eq!(get(&t, idx), 0, "u_debugreg[{idx}]"); }
    // A nonexistent index reads as zero rather than failing.
    for idx in [4usize, 5, 9] { assert_eq!(get(&t, idx), 0, "u_debugreg[{idx}]"); }
}

#[test]
fn a_stored_breakpoint_is_read_back_and_arms_the_task() {
    let t = task();
    put(&t, 0, 0x4000);
    assert_eq!(get(&t, 0), 0x4000);
    assert!(!armed(&t), "an address alone arms nothing — DR7 does");
    // L0 enable.
    put(&t, CONTROL, DR7_ENABLE_MASK & 1);
    assert!(armed(&t), "the context-switch gate must see the task as armed");
    assert_eq!(get(&t, 7), DR7_ENABLE_MASK & 1);
    // DR5 is not an alias of DR7 — it does not exist and reads as zero.
    assert_eq!(get(&t, 5), 0);
}

#[test]
fn clear_disarms_every_slot() {
    let t = task();
    put(&t, 0, 0x4000);
    put(&t, 1, 0x5000);
    put(&t, CONTROL, 0x0009_0401);
    assert!(armed(&t));
    clear(&t);
    assert!(!armed(&t), "execve must not inherit a breakpoint into the new image");
    assert_eq!(addrs(&t), [0; NR_ADDR]);
}

#[test]
fn a_db_cause_accumulates_into_the_status_shadow() {
    let t = task();
    record_status(&t, 0b0001);
    record_status(&t, 0b0100);
    assert_eq!(get(&t, 6), 0b0101, "a tracer reads WHY each trap fired");
}

// The validation ladder is x86-only: aarch64 has no `struct user` debug window.
#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::*;
    use crate::debugreg::x86 as bridge;

    /// A 4-byte data watchpoint on slot 0: L0 | GE | reserved-one, RW0=WRITE,
    /// LEN0=4.
    const DR7_W4_SLOT0: u64 = (0b11 << 18) | (0b01 << 16) | (1 << 10) | (1 << 9) | 1;

    #[test]
    fn a_valid_user_watchpoint_is_accepted_and_installed() {
        let t = task();
        bridge::set_addr(&t, 0, 0x4000).expect("an aligned user address is installable");
        bridge::set_control(&t, DR7_W4_SLOT0).expect("a 4-byte write watchpoint is legal");
        assert!(armed(&t));
        assert_eq!(get(&t, 0), 0x4000);
    }

    #[test]
    fn a_kernel_breakpoint_address_is_refused() {
        let t = task();
        // The whole point of validating: a tracer must not be able to make the
        // kernel trap on its own code.
        assert!(bridge::set_addr(&t, 0, 0xffff_ffff_8000_0000).is_err());
        assert_eq!(get(&t, 0), 0, "a refused write stores nothing");
    }

    #[test]
    fn a_misaligned_watchpoint_is_refused_and_leaves_the_task_unarmed() {
        let t = task();
        bridge::set_addr(&t, 0, 0x4001).expect("the address alone is only range-checked");
        assert!(bridge::set_control(&t, DR7_W4_SLOT0).is_err(),
                "a 4-byte watchpoint needs a 4-byte-aligned address");
        assert!(!armed(&t), "a refused DR7 must not arm the slot");
    }

    #[test]
    fn the_general_detect_bit_is_masked_off_but_the_write_succeeds() {
        let t = task();
        bridge::set_control(&t, DR7_W4_SLOT0 | (1 << 13))
            .expect("general detect does not invalidate the whole write");
        assert!(armed(&t), "the rest of the DR7 still took effect");
        assert_eq!(hal_x86_64::debugreg::programmable(get(&t, 7)) & (1 << 13), 0,
                   "hardware never receives general detect");
    }

    #[test]
    fn the_virtual_status_register_round_trips_any_value() {
        // DR6 as a tracer sees it is per-task and never loaded into hardware,
        // so the write always succeeds and reads back verbatim.
        let t = task();
        for v in [0u64, 0xffff_0ff0, 0b1111, u64::MAX] {
            bridge::set_status(&t, v);
            assert_eq!(bridge::status(&t), v, "DR6 write of {v:#x} must read back");
        }
    }

    #[test]
    fn the_unarmed_control_value_is_the_architectural_reset_value() {
        assert_eq!(bridge::empty_control() & DR7_ENABLE_MASK, 0);
        assert_eq!(bridge::empty_control(), 1 << 10, "bit 10 reads as one");
    }
}
