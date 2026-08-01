// POR_EL0 field arithmetic and the FEAT_S1POE ID decode. The system-register
// accesses need a CPU; every DECISION built on them is here.

use super::*;

// Key 0 starts fully open — it is the key every ordinary page carries, so
// closing it would fault a thread on its own stack — and every other key
// starts closed, so a thread cloned before a pkey_alloc cannot inherit access
// to what that key later protects.
#[test]
fn the_init_value_opens_key_zero_and_closes_every_other_key() {
    assert_eq!(por_perm(POR_EL0_INIT, 0), POE_RWX);
    assert!(por_allows_read(POR_EL0_INIT, 0));
    assert!(por_allows_write(POR_EL0_INIT, 0));
    assert!(por_allows_exec(POR_EL0_INIT, 0));
    for pkey in 1..MAX_PKEY {
        assert_eq!(por_perm(POR_EL0_INIT, pkey), POE_NONE, "key {pkey} must start closed");
        assert!(!por_allows_read(POR_EL0_INIT, pkey));
        assert!(!por_allows_write(POR_EL0_INIT, pkey));
        assert!(!por_allows_exec(POR_EL0_INIT, pkey));
    }
}

// A permission set is positive: the encodings compose from independent R/W/X
// bits, which is what lets the overlay express rights PKRU cannot.
#[test]
fn the_permission_encodings_are_independent_rwx_bits() {
    assert_eq!(POE_NONE, 0);
    assert_eq!(POE_RX, POE_R | POE_X);
    assert_eq!(POE_RW, POE_R | POE_W);
    assert_eq!(POE_WX, POE_W | POE_X);
    assert_eq!(POE_RWX, POE_R | POE_W | POE_X);
}

// Each key owns four adjacent bits, key n at bit 4n. An off-by-one here aims
// every rights change at the neighbouring key.
#[test]
fn each_key_owns_four_adjacent_bits() {
    assert_eq!(por_shift(0), 0);
    assert_eq!(por_shift(1), 4);
    assert_eq!(por_shift(MAX_PKEY - 1), 28);
    assert_eq!(por_perm_prep(3, POE_RWX), POE_RWX << 12);
    assert_eq!(por_perm(POE_RW << 8, 2), POE_RW);
}

// DISABLE_WRITE leaves read and execute alone.
#[test]
fn disable_write_leaves_read_and_execute() {
    let por = por_set_pkey_access(0, 2, false, true, false, false);
    assert!(por_allows_read(por, 2));
    assert!(!por_allows_write(por, 2));
    assert!(por_allows_exec(por, 2));
}

// DISABLE_ACCESS clears read AND write but NOT execute — the two are
// independent on this arch, so a key can be execute-only. Encoding it as
// "clear everything" would silently break an execute-only mapping.
#[test]
fn disable_access_clears_read_and_write_but_not_execute() {
    let por = por_set_pkey_access(0, 2, true, false, false, false);
    assert!(!por_allows_read(por, 2));
    assert!(!por_allows_write(por, 2));
    assert!(por_allows_exec(por, 2));
    assert_eq!(por_perm(por, 2), POE_X);
}

// DISABLE_READ and DISABLE_EXECUTE are the two rights x86's PKRU cannot
// express, and they act independently of the other two.
#[test]
fn read_and_execute_can_be_revoked_independently() {
    let no_read = por_set_pkey_access(0, 4, false, false, true, false);
    assert!(!por_allows_read(no_read, 4));
    assert!(por_allows_write(no_read, 4));
    assert!(por_allows_exec(no_read, 4));

    let no_exec = por_set_pkey_access(0, 4, false, false, false, true);
    assert!(por_allows_read(no_exec, 4));
    assert!(por_allows_write(no_exec, 4));
    assert!(!por_allows_exec(no_exec, 4));
}

// Every right disabled leaves the key with no access at all.
#[test]
fn disabling_everything_closes_the_key() {
    assert_eq!(por_perm(por_set_pkey_access(0, 5, true, true, true, true), 5), POE_NONE);
}

// Asking for nothing gives full access — the starting point the rights are
// subtracted from.
#[test]
fn disabling_nothing_opens_the_key_fully() {
    let por = por_set_pkey_access(POR_EL0_INIT, 6, false, false, false, false);
    assert_eq!(por_perm(por, 6), POE_RWX);
}

// Setting one key must not disturb any other key's field: the whole register
// is rewritten, so a bad mask silently opens or closes unrelated keys.
#[test]
fn setting_one_key_leaves_every_other_key_untouched() {
    let before = POR_EL0_INIT;
    let after = por_set_pkey_access(before, 3, true, false, false, false);
    for pkey in 0..MAX_PKEY {
        if pkey == 3 { continue; }
        assert_eq!(por_perm(after, pkey), por_perm(before, pkey), "key {pkey} field changed");
    }
}

// The top key's field must stay inside the register.
#[test]
fn the_last_key_fits_in_the_register() {
    let por = por_set_pkey_access(0, MAX_PKEY - 1, false, false, false, false);
    assert_eq!(por, POE_RWX << 28);
}

// FEAT_S1POE needs FEAT_TCR2 as well: TCR2_EL1.E0POE is the only switch that
// turns the overlay on, so reporting S1POE alone leaves it unusable.
#[test]
fn the_overlay_needs_both_s1poe_and_tcr2() {
    let s1poe = 1u64 << MMFR3_S1POE_SHIFT;
    let tcrx = 1u64 << MMFR3_TCRX_SHIFT;
    assert!(mmfr3_has_poe(s1poe | tcrx));
    assert!(!mmfr3_has_poe(s1poe), "S1POE without TCR2 cannot be enabled");
    assert!(!mmfr3_has_poe(tcrx));
    assert!(!mmfr3_has_poe(0));
}

// An ID field is 4 bits and a higher value is a higher capability level, so
// any non-zero value counts as implemented.
#[test]
fn a_higher_id_field_level_still_counts_as_implemented() {
    assert!(mmfr3_has_poe((2u64 << MMFR3_S1POE_SHIFT) | (3u64 << MMFR3_TCRX_SHIFT)));
    assert_eq!(id_field(0xF0, 4), 0xF);
    assert_eq!(id_field(u64::MAX, MMFR3_S1POE_SHIFT), 0xF);
}

// The two enable bits are distinct registers with distinct positions, and
// setting either must preserve whatever else the boot path put there.
#[test]
fn the_enable_bits_preserve_the_rest_of_their_registers() {
    assert_eq!(TCR2_EL1_E0POE, 1 << 2);
    assert_eq!(CPACR_EL1_E0POE, 1 << 29);
    let tcr2 = 0b1010u64;
    assert_eq!(tcr2_with_e0poe(tcr2), tcr2 | (1 << 2));
    // CPACR_EL1.FPEN, which fpu_enable set, must survive.
    let cpacr = 0x3u64 << 20;
    assert_eq!(cpacr_with_e0poe(cpacr), cpacr | (1 << 29));
    assert_eq!(cpacr_with_e0poe(cpacr) & (0x3 << 20), 0x3 << 20);
}

// Without the overlay the key space collapses to key 0 and every register
// access is inert — nothing is denied.
#[test]
fn the_overlay_is_inert_when_unsupported() {
    assert!(!poe_enabled(), "hosted tests never enable the overlay");
    assert_eq!(arch_max_pkey(), 1);
    assert_eq!(read_por(), 0);
    write_por(u64::MAX);
    assert_eq!(read_por(), 0);
    assert_eq!(id_aa64mmfr3_el1(), 0);
}

// The default is settable, but never to a value that would close key 0.
#[test]
fn the_default_cannot_close_key_zero() {
    assert_eq!(set_por_init_value(0), Err(()));
    assert_eq!(set_por_init_value(POE_RW), Err(()), "key 0 must keep execute too");
    assert_eq!(por_init_value(), POR_EL0_INIT, "a refused write changes nothing");
}

// A legal default is accepted and read back. Restored so test order cannot
// matter.
#[test]
fn a_legal_default_round_trips() {
    let want = por_set_pkey_access(POR_EL0_INIT, 7, false, true, false, false);
    assert_eq!(set_por_init_value(want), Ok(()));
    assert_eq!(por_init_value(), want);
    assert_eq!(set_por_init_value(POR_EL0_INIT), Ok(()));
}
