use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublishFailure;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RollbackFailure;

#[test]
fn injected_publish_failure_runs_real_policy_rollback() {
    let mut rolled_back = false;
    let result = publish_or_rollback(
        || Err(PublishFailure),
        || { rolled_back = true; Ok::<(), RollbackFailure>(()) },
    );
    assert_eq!(result, Err(TransactionError::Publish(PublishFailure)));
    assert!(rolled_back);
}

#[test]
fn injected_rollback_failure_is_preserved() {
    let result = publish_or_rollback(
        || Err(PublishFailure),
        || Err::<(), _>(RollbackFailure),
    );
    assert_eq!(result, Err(TransactionError::Rollback(RollbackFailure)));
}

#[test]
fn successful_publish_does_not_rollback() {
    let mut rolled_back = false;
    let result = publish_or_rollback(
        || Ok::<(), PublishFailure>(()),
        || { rolled_back = true; Ok::<(), RollbackFailure>(()) },
    );
    assert_eq!(result, Ok(()));
    assert!(!rolled_back);
}

#[test]
fn failed_publication_clears_projection_before_canonical_owner() {
    let mut projection_live = true;
    let mut canonical_live = true;
    let result = publish_or_rollback(
        || Err(PublishFailure),
        || {
            assert!(projection_live);
            projection_live = false;
            assert!(canonical_live);
            canonical_live = false;
            Ok::<(), RollbackFailure>(())
        },
    );
    assert_eq!(result, Err(TransactionError::Publish(PublishFailure)));
    assert!(!projection_live);
    assert!(!canonical_live);
}
