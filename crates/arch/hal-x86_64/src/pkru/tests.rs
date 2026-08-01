// PKRU bit arithmetic and the CPUID/CR4 decode. The instructions themselves
// need a CPU; every DECISION built on them is here.

use super::*;

// The default must leave key 0 fully open — it is the key every ordinary page
// carries, so denying it would fault a thread on its own stack — and deny
// every other key, so a thread cloned before a `pkey_alloc` cannot inherit
// access to what that key later protects.
#[test]
fn the_init_value_opens_key_zero_and_closes_every_other_key() {
    assert!(pkru_allows_read(INIT_PKRU_VALUE, 0));
    assert!(pkru_allows_write(INIT_PKRU_VALUE, 0));
    for pkey in 1..MAX_PKEY_OSPKE {
        assert!(!pkru_allows_read(INIT_PKRU_VALUE, pkey), "key {pkey} must start denied");
        assert!(!pkru_allows_write(INIT_PKRU_VALUE, pkey), "key {pkey} must start denied");
    }
}

// The default sets only AD bits, never WD: a key is closed outright rather
// than left readable.
#[test]
fn the_init_value_sets_access_disable_only() {
    for pkey in 1..MAX_PKEY_OSPKE {
        assert_eq!(INIT_PKRU_VALUE & (PKRU_AD_BIT << pkru_shift(pkey)), PKRU_AD_BIT << pkru_shift(pkey));
        assert_eq!(INIT_PKRU_VALUE & (PKRU_WD_BIT << pkru_shift(pkey)), 0);
    }
}

// Access-disable denies writes as well as reads: a write needs BOTH bits
// clear. Getting this wrong would let a thread write through a key it cannot
// even read.
#[test]
fn access_disable_denies_writes_too() {
    let pkru = pkru_set_pkey_access(0, 3, true, false);
    assert!(!pkru_allows_read(pkru, 3));
    assert!(!pkru_allows_write(pkru, 3));
}

// Write-disable leaves reads alone — the read-only case.
#[test]
fn write_disable_leaves_reads_permitted() {
    let pkru = pkru_set_pkey_access(0, 3, false, true);
    assert!(pkru_allows_read(pkru, 3));
    assert!(!pkru_allows_write(pkru, 3));
}

// Clearing both bits restores full access.
#[test]
fn clearing_both_bits_restores_access() {
    let closed = pkru_set_pkey_access(INIT_PKRU_VALUE, 7, true, true);
    let open = pkru_set_pkey_access(closed, 7, false, false);
    assert!(pkru_allows_read(open, 7));
    assert!(pkru_allows_write(open, 7));
}

// Setting one key's rights must not disturb any other key's field — the whole
// register is rewritten by WRPKRU, so a bad mask silently opens or closes
// unrelated keys.
#[test]
fn setting_one_key_leaves_every_other_key_untouched() {
    let before = INIT_PKRU_VALUE;
    let after = pkru_set_pkey_access(before, 5, false, false);
    for pkey in 0..MAX_PKEY_OSPKE {
        if pkey == 5 { continue; }
        assert_eq!(
            after & pkru_mask(pkey), before & pkru_mask(pkey),
            "key {pkey} field changed while setting key 5",
        );
    }
    assert!(pkru_allows_write(after, 5));
}

// Each key owns two adjacent bits, key n at bit 2n. An off-by-one here aims
// every rights change at the neighbouring key.
#[test]
fn each_key_owns_two_adjacent_bits() {
    assert_eq!(pkru_shift(0), 0);
    assert_eq!(pkru_shift(1), 2);
    assert_eq!(pkru_shift(15), 30);
    assert_eq!(pkru_mask(0), 0b11);
    assert_eq!(pkru_mask(15), 0b11 << 30);
}

// The top key's field must fit in the register.
#[test]
fn the_last_key_fits_in_the_register() {
    let pkru = pkru_set_pkey_access(0, MAX_PKEY_OSPKE - 1, true, true);
    assert_eq!(pkru, 0b11u32 << 30);
    assert!(!pkru_allows_read(pkru, MAX_PKEY_OSPKE - 1));
}

// PKU is CPUID.(7,0):ECX bit 3, OSPKE is bit 4. OSPKE reports the OS's
// enablement, not the CPU's capability, so a CPU with PKU and no CR4.PKE
// reports one and not the other.
#[test]
fn pku_and_ospke_are_distinct_cpuid_bits() {
    assert!(cpuid_has_pku(CPUID7_ECX_PKU));
    assert!(!cpuid_has_ospke(CPUID7_ECX_PKU));
    assert!(cpuid_has_ospke(CPUID7_ECX_OSPKE));
    assert!(!cpuid_has_pku(CPUID7_ECX_OSPKE));
    assert!(!cpuid_has_pku(0));
    assert!(!cpuid_has_ospke(0));
}

// CR4.PKE is bit 22, and setting it must not disturb the other CR4 bits the
// boot path already established (OSFXSR, OSXMMEXCPT, OSXSAVE).
#[test]
fn cr4_pke_is_bit_22_and_preserves_other_bits() {
    assert_eq!(CR4_PKE, 1 << 22);
    let before = (1u64 << 9) | (1 << 10) | (1 << 18);
    let after = cr4_with_pke(before);
    assert_eq!(after, before | (1 << 22));
    assert_eq!(cr4_with_pke(after), after, "setting an already-set bit is idempotent");
}

// Without OSPKE the key space is key 0 alone — the implicit key every PTE
// carries — so `pkey_alloc` has nothing to hand out.
#[test]
fn the_key_space_collapses_to_key_zero_without_ospke() {
    assert!(!ospke_enabled(), "hosted tests never enable PKU");
    assert_eq!(arch_max_pkey(), MAX_PKEY_NO_OSPKE);
    assert_eq!(MAX_PKEY_NO_OSPKE, 1);
}

// With PKU off, the register reads as zero (nothing is denied) and writes are
// dropped rather than faulting on an instruction that would #UD.
#[test]
fn pkru_access_is_inert_without_ospke() {
    assert_eq!(read_pkru(), 0);
    write_pkru(0xFFFF_FFFF);
    assert_eq!(read_pkru(), 0);
}

// The default is settable, but never to a value that would deny key 0 — that
// would fault every thread on its own stack the moment it took effect.
#[test]
fn the_default_cannot_be_set_to_deny_key_zero() {
    assert_eq!(set_pkru_init_value(PKRU_AD_BIT), Err(()));
    assert_eq!(set_pkru_init_value(PKRU_WD_BIT), Err(()));
    assert_eq!(set_pkru_init_value(PKRU_AD_BIT | PKRU_WD_BIT), Err(()));
    assert_eq!(pkru_init_value(), INIT_PKRU_VALUE, "a refused write changes nothing");
}

// A legal default is accepted and read back. Restored afterwards so test order
// cannot matter.
#[test]
fn a_legal_default_round_trips() {
    let want = pkru_set_pkey_access(INIT_PKRU_VALUE, 9, false, true);
    assert_eq!(set_pkru_init_value(want), Ok(()));
    assert_eq!(pkru_init_value(), want);
    assert_eq!(set_pkru_init_value(INIT_PKRU_VALUE), Ok(()));
}
