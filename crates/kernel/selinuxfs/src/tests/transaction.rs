// The write-then-read-back query nodes.

use vfs::VfsError;

use crate::fake::{FakeOps, BAD_CONTEXT};
use crate::nodes::transaction::{required_permission, transact, TxKind, TRANSACTION_LIMIT,
                                PERM_CHECK_CONTEXT,
                                PERM_COMPUTE_AV, PERM_COMPUTE_CREATE, PERM_COMPUTE_MEMBER,
                                PERM_COMPUTE_RELABEL};

#[test]
fn a_decision_query_answers_with_the_rendered_decision() {
    let mut ops = FakeOps::allow_all();
    ops.avd = selinux::avc::AvDecision { allowed: 0x1, auditallow: 0x2, auditdeny: 0x4,
                                         seqno: 7, flags: 0x8 };
    let answer = transact(&mut ops, TxKind::Access, b"scon tcon 6").unwrap();
    assert_eq!(answer, "1 ffffffff 2 4 7 8");
    assert!(ops.was_checked(PERM_COMPUTE_AV));
}

#[test]
fn a_context_query_answers_with_the_canonical_rendering() {
    let mut ops = FakeOps::allow_all();
    assert_eq!(transact(&mut ops, TxKind::Context, b"u:r:t:s0\n").unwrap(), "canon:u:r:t:s0");
    assert!(ops.was_checked(PERM_CHECK_CONTEXT));
}

#[test]
fn a_create_query_carries_the_decoded_name() {
    let mut ops = FakeOps::allow_all();
    let answer = transact(&mut ops, TxKind::Create, b"scon tcon 6 two%20words").unwrap();
    assert_eq!(answer, "create:scon:tcon:6");
    assert_eq!(ops.last_name.as_deref(), Some("two words"));
    assert!(ops.was_checked(PERM_COMPUTE_CREATE));
}

#[test]
fn an_answer_larger_than_the_transaction_page_is_refused_whole() {
    let mut ops = FakeOps::allow_all();
    ops.new_context_answer = Some("x".repeat(TRANSACTION_LIMIT + 1));
    assert_eq!(transact(&mut ops, TxKind::Create, b"scon tcon 6 name").err(),
               Some(VfsError::Erange));
    ops.new_context_answer = Some("x".repeat(TRANSACTION_LIMIT));
    assert_eq!(transact(&mut ops, TxKind::Create, b"scon tcon 6 name").unwrap().len(),
               TRANSACTION_LIMIT);
}

#[test]
fn relabel_and_member_ask_their_own_questions() {
    let mut ops = FakeOps::allow_all();
    assert_eq!(transact(&mut ops, TxKind::Relabel, b"s t 6").unwrap(), "relabel:s:t:6");
    assert_eq!(transact(&mut ops, TxKind::Member, b"s t 6").unwrap(), "member:s:t:6");
    assert!(ops.was_checked(PERM_COMPUTE_RELABEL));
    assert!(ops.was_checked(PERM_COMPUTE_MEMBER));
}

#[test]
fn transaction_queries_ignore_fields_after_their_consumed_prefix() {
    let mut ops = FakeOps::allow_all();
    assert_eq!(transact(&mut ops, TxKind::Access, b"s t 6 ignored tail").unwrap(),
               "0 ffffffff 0 ffffffff 0 0");
    assert_eq!(transact(&mut ops, TxKind::Create, b"s t 6 name ignored tail").unwrap(),
               "create:s:t:6");
    assert_eq!(ops.last_name.as_deref(), Some("name"));
    assert_eq!(transact(&mut ops, TxKind::Relabel, b"s t 6 ignored tail").unwrap(),
               "relabel:s:t:6");
    assert_eq!(transact(&mut ops, TxKind::Member, b"s t 6 ignored tail").unwrap(),
               "member:s:t:6");
}

#[test]
fn the_compatibility_node_answers_without_a_check() {
    let mut ops = FakeOps::allow_all();
    assert_eq!(transact(&mut ops, TxKind::User, b"anything").unwrap(), "0");
    assert!(ops.checked.is_empty());
    assert_eq!(required_permission(TxKind::User), None);
}

#[test]
fn a_denial_answers_nothing_and_parses_nothing() {
    for (kind, permission) in [(TxKind::Access, PERM_COMPUTE_AV),
                               (TxKind::Create, PERM_COMPUTE_CREATE),
                               (TxKind::Relabel, PERM_COMPUTE_RELABEL),
                               (TxKind::Member, PERM_COMPUTE_MEMBER),
                               (TxKind::Context, PERM_CHECK_CONTEXT)] {
        let mut ops = FakeOps::denying(permission);
        assert_eq!(transact(&mut ops, kind, b"s t 6").err(), Some(VfsError::Eacces));
        assert!(ops.was_checked(permission));
    }
}

#[test]
fn a_malformed_request_is_refused_by_every_query() {
    let mut ops = FakeOps::allow_all();
    assert_eq!(transact(&mut ops, TxKind::Access, b"s t").err(), Some(VfsError::Einval));
    assert_eq!(transact(&mut ops, TxKind::Access, b"s t file").err(), Some(VfsError::Einval));
    assert_eq!(transact(&mut ops, TxKind::Access, b"s t 0").err(), Some(VfsError::Einval));
    assert_eq!(transact(&mut ops, TxKind::Create, b"s t 6 a%").err(), Some(VfsError::Einval));
    assert_eq!(transact(&mut ops, TxKind::Context, b"a b").err(), Some(VfsError::Einval));
}

#[test]
fn a_context_the_policy_cannot_interpret_is_refused() {
    let mut ops = FakeOps::allow_all();
    assert_eq!(transact(&mut ops, TxKind::Context, BAD_CONTEXT.as_bytes()).err(),
               Some(VfsError::Einval));
    assert_eq!(transact(&mut ops, TxKind::Access, b"bad t 6").err(), Some(VfsError::Einval));
}
