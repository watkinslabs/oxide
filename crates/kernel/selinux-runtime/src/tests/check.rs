use super::*;
use selinux::uapi::classmap::{class_by_name, perm_bit};

fn verdict(allowed: bool, denied: u32, permissive: bool) -> Verdict {
    Verdict { allowed, denied, permissive, audit: true }
}

#[test]
fn permission_names_lists_only_the_bits_the_mask_sets() {
    let file = class_by_name("file").unwrap();
    let mask = perm_bit(file, "read").unwrap() | perm_bit(file, "open").unwrap();
    let names = permission_names(file, mask);
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"read") && names.contains(&"open"));
    assert!(!names.contains(&"write"));
}

#[test]
fn permission_names_are_listed_in_bit_order_not_request_order() {
    let file = class_by_name("file").unwrap();
    let mask = perm_bit(file, "open").unwrap() | perm_bit(file, "ioctl").unwrap();
    assert_eq!(permission_names(file, mask), alloc::vec!["ioctl", "open"],
               "a stable order is what makes a record comparable across boots");
}

#[test]
fn an_empty_mask_names_no_permissions() {
    let file = class_by_name("file").unwrap();
    assert!(permission_names(file, 0).is_empty());
}

#[test]
fn an_unknown_class_names_no_permissions_rather_than_guessing() {
    assert!(permission_names(0, u32::MAX).is_empty());
    assert!(permission_names(u16::MAX, u32::MAX).is_empty());
}

#[test]
fn a_denial_record_names_the_denied_permissions_and_the_class() {
    let file = class_by_name("file").unwrap();
    let mask = perm_bit(file, "write").unwrap();
    let body = record_body(1, 2, file, &verdict(false, mask, false));
    assert!(body.contains("denied"), "{body}");
    assert!(body.contains("{ write }"), "{body}");
    assert!(body.contains("tclass=file"), "{body}");
    assert!(!body.contains("permissive=1"), "{body}");
}

#[test]
fn a_permissive_record_says_so() {
    let file = class_by_name("file").unwrap();
    let body = record_body(1, 2, file, &verdict(true, perm_bit(file, "read").unwrap(), true));
    assert!(body.contains("permissive=1"),
            "a permissive denial that does not say it is permissive reads as a grant: {body}");
}

#[test]
fn a_record_carries_both_contexts_even_when_they_cannot_be_rendered() {
    let file = class_by_name("file").unwrap();
    let body = record_body(1, 2, file, &verdict(false, 1, false));
    assert!(body.contains("scontext="), "{body}");
    assert!(body.contains("tcontext="), "{body}");
}

#[test]
fn a_granted_record_reads_as_a_grant() {
    let file = class_by_name("file").unwrap();
    let body = record_body(1, 2, file, &verdict(true, 0, false));
    assert!(body.contains("granted"), "{body}");
    assert!(!body.contains("denied"), "{body}");
}

#[test]
fn with_no_server_installed_every_check_allows() {
    // The bootstrap window: no server, no policy, nothing to decide.
    assert_eq!(has_perm(1, 2, 7, u32::MAX), Ok(()));
    assert!(has_perm_noaudit(1, 2, 7, u32::MAX).allowed);
}
