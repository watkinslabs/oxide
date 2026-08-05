/// Per-handler execution-context accounting supplied by the caller.
///
/// Dispatch lives below the scheduler, so the generic contract lets the
/// scheduler snapshot and repair its canonical state without a dependency
/// cycle or a second registry.
pub trait HandlerAccounting {
    type Snapshot: Copy;

    /// Capture context immediately before one handler. # C: O(1)
    fn before() -> Self::Snapshot;
    /// Verify and repair context immediately after that handler. # C: O(1)
    fn after(snapshot: Self::Snapshot);
}

/// Dispatch without caller-owned context accounting.
pub struct Unaccounted;

impl HandlerAccounting for Unaccounted {
    type Snapshot = ();

    fn before() {}
    fn after(_: ()) {}
}
