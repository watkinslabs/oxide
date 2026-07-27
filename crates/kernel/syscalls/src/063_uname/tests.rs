// uname(2) field-layout + personality-override tests. Covers the exact
// `struct new_utsname` geometry (6 × 65 bytes, every field NUL-terminated),
// the domainname field being populated, and Linux's two post-copy overrides.

use super::*;
use sched::personality::{ADDR_NO_RANDOMIZE, PER_LINUX, PER_LINUX32, UNAME26};

fn field(img: &[u8], idx: usize) -> &[u8] {
    &img[idx * UTSNAME_FIELD_LEN..(idx + 1) * UTSNAME_FIELD_LEN]
}

fn text(img: &[u8], idx: usize) -> &str {
    let f = field(img, idx);
    let end = f.iter().position(|&b| b == 0).unwrap();
    core::str::from_utf8(&f[..end]).unwrap()
}

fn img(personality: u32) -> alloc::vec::Vec<u8> {
    build_utsname(b"oxide", b"lan.example", b"#1 SMP PREEMPT oxide", personality)
}

#[test]
fn struct_new_utsname_is_six_65_byte_fields() {
    assert_eq!(UTSNAME_FIELD_LEN, 65, "__NEW_UTS_LEN + 1");
    assert_eq!(UTSNAME_TOTAL_LEN, 390);
    assert_eq!(img(PER_LINUX).len(), UTSNAME_TOTAL_LEN);
}

#[test]
fn every_field_is_nul_terminated_and_zero_padded() {
    let b = img(PER_LINUX);
    for idx in 0..6 {
        let f = field(&b, idx);
        let end = f.iter().position(|&x| x == 0).expect("field must contain a NUL");
        assert!(f[end..].iter().all(|&x| x == 0), "field {idx} tail must be zero-padded");
    }
}

#[test]
fn fields_land_in_linux_declaration_order() {
    let b = img(PER_LINUX);
    assert_eq!(text(&b, IDX_SYSNAME), "Linux");
    assert_eq!(text(&b, IDX_NODENAME), "oxide");
    assert_eq!(text(&b, IDX_RELEASE), UTS_RELEASE);
    assert_eq!(text(&b, IDX_VERSION), "#1 SMP PREEMPT oxide");
    assert_eq!(text(&b, IDX_MACHINE), UTS_MACHINE);
    assert_eq!(text(&b, IDX_DOMAINNAME), "lan.example");
}

#[test]
fn domainname_field_is_populated_not_left_blank() {
    // The NIS/YP domainname is a real utsname field; leaving it empty makes
    // `uname -n`-adjacent tooling and `getdomainname(2)` report nothing.
    let b = img(PER_LINUX);
    assert_ne!(field(&b, IDX_DOMAINNAME)[0], 0);
    // An unset domain reports Linux's `init_uts_ns` seed, not an empty string.
    let d = build_utsname(b"oxide", UTS_NONE, b"v", PER_LINUX);
    assert_eq!(text(&d, IDX_DOMAINNAME), "(none)");
}

#[test]
fn an_oversized_field_truncates_to_64_bytes_plus_nul() {
    let long = [b'x'; 200];
    let packed = pack_field(&long);
    assert_eq!(packed.len(), UTSNAME_FIELD_LEN);
    assert_eq!(packed[UTSNAME_FIELD_LEN - 1], 0, "field must stay NUL-terminated");
    assert!(packed[..UTSNAME_FIELD_LEN - 1].iter().all(|&b| b == b'x'));
}

#[test]
fn uname26_rewrites_the_release_to_the_2_6_series() {
    // Linux `override_release`: "2.6.<PATCHLEVEL + 60>" + the tail past the
    // version numbers. 5.15.0-oxide → patchlevel 15 → 2.6.75-oxide.
    assert_eq!(override_release("5.15.0-oxide"), "2.6.75-oxide");
    let b = img(UNAME26);
    assert_eq!(text(&b, IDX_RELEASE), "2.6.75-oxide");
    // Everything else is untouched by UNAME26.
    assert_eq!(text(&b, IDX_MACHINE), UTS_MACHINE);
    assert_eq!(text(&b, IDX_SYSNAME), "Linux");
}

#[test]
fn override_release_scan_stops_at_the_third_dot_or_first_non_version_char() {
    // Third dot terminates the scan even with no alphabetic tail.
    assert_eq!(override_release("5.15.0.7"), "2.6.75.7");
    // A release with no tail keeps none.
    assert_eq!(override_release("5.15.0"), "2.6.75");
    // The tail begins at the first non-digit, non-dot character.
    assert_eq!(override_release("5.15-rc1"), "2.6.75-rc1");
}

#[test]
fn per_linux32_reports_the_compat_machine() {
    let b = img(PER_LINUX32);
    assert_eq!(text(&b, IDX_MACHINE), COMPAT_UTS_MACHINE);
    assert_ne!(COMPAT_UTS_MACHINE, UTS_MACHINE);
    // The release is untouched by PER_LINUX32 alone.
    assert_eq!(text(&b, IDX_RELEASE), UTS_RELEASE);
}

#[test]
fn the_two_overrides_are_independent_and_compose() {
    let b = img(PER_LINUX32 | UNAME26);
    assert_eq!(text(&b, IDX_MACHINE), COMPAT_UTS_MACHINE);
    assert_eq!(text(&b, IDX_RELEASE), "2.6.75-oxide");
    // An unrelated personality flag changes neither.
    let n = img(ADDR_NO_RANDOMIZE);
    assert_eq!(text(&n, IDX_MACHINE), UTS_MACHINE);
    assert_eq!(text(&n, IDX_RELEASE), UTS_RELEASE);
}

#[test]
fn compat_machine_is_the_arch_specific_linux_value() {
    #[cfg(target_arch = "x86_64")]
    {
        assert_eq!(UTS_MACHINE, "x86_64");
        assert_eq!(COMPAT_UTS_MACHINE, "i686");
    }
    #[cfg(target_arch = "aarch64")]
    {
        assert_eq!(UTS_MACHINE, "aarch64");
        assert_eq!(COMPAT_UTS_MACHINE, "armv8l");
    }
}
