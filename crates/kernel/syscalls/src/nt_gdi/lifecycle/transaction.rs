//! Ungated lifecycle transaction policy. The kernel lifecycle module supplies
//! the real projection and canonical-owner closures; this policy is hosted
//! testable and contains no target-specific types.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionError<Publish, Rollback> {
    Publish(Publish),
    Rollback(Rollback),
}

pub fn publish_or_rollback<Publish, Rollback, P, R>(
    publish: P,
    rollback: R,
) -> Result<(), TransactionError<Publish, Rollback>>
where
    P: FnOnce() -> Result<(), Publish>,
    R: FnOnce() -> Result<(), Rollback>,
{
    if let Err(error) = publish() {
        rollback().map_err(TransactionError::Rollback)?;
        return Err(TransactionError::Publish(error));
    }
    Ok(())
}

#[cfg(test)]
#[path = "transaction/tests.rs"]
mod tests;
