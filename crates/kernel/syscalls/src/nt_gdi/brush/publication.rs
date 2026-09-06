//! Projection transaction decisions; caller retains the sleepable lifetime gate.

pub(super) fn publish_created<E>(handle: u32, publish: impl FnOnce(u32) -> Result<(), E>,
    rollback: impl FnOnce(u32) -> Result<(), E>) -> Result<u32, E> {
    if let Err(error) = publish(handle) { rollback(handle)?; return Err(error); }
    Ok(handle)
}

pub(super) fn finish_selection<E>(previous: u32, still_live: bool,
    clear: impl FnOnce(u32) -> Result<(), E>) -> Result<u32, E> {
    if !still_live { clear(previous)?; }
    Ok(previous)
}

#[cfg(test)]
#[path = "tests/publication.rs"]
mod tests;
