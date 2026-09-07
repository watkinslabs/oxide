//! Order in which one raw BeginPaint takes its window and its device context.

/// Steps one paint open performs. The owner supplies the live resources; this
/// module owns only the order they are taken and undone in.
pub(crate) trait PaintOpen {
    /// Consume the window's pending damage into a paint session.
    fn reserve(&mut self) -> bool;
    /// Release a session whose device context could not be built.
    fn release(&mut self);
    /// Window-sized backing store for the painted pixels.
    fn backing(&mut self) -> bool;
    /// Fresh compatible device context; zero when none could be created.
    fn create_dc(&mut self) -> u64;
    /// Publish the window's current pixels into that device context.
    fn seed(&mut self, dc: u64) -> bool;
    /// Bind the device context to the window's paint lease.
    fn bind(&mut self, dc: u64) -> bool;
    fn delete_dc(&mut self, dc: u64);
}

/// The window's update region is validated into a paint session before any
/// device context exists, so a window whose paint could not be equipped still
/// owes no further paint: a device-context failure returns no HDC instead of
/// leaving damage that offers the same paint message forever.
/// # C: O(owner work)
pub(crate) fn open<O: PaintOpen>(owner: &mut O) -> Option<u64> {
    if !owner.reserve() { return None; }
    if !owner.backing() { owner.release(); return None; }
    let dc = owner.create_dc();
    if dc == 0 { owner.release(); return None; }
    if !owner.seed(dc) { owner.delete_dc(dc); owner.release(); return None; }
    if !owner.bind(dc) { owner.delete_dc(dc); owner.release(); return None; }
    Some(dc)
}

#[cfg(test)]
#[path = "tests/paint_open.rs"]
mod tests;
