use ipc::win32_window::{PaintRegion, WindowRect};
/// A canonical HRGN snapshot takes precedence; never dereference an ignored RECT. # C: O(region)
pub(crate) fn read_region(rect: u64, hrgn: u64,
    read: impl FnOnce(&mut [u8], u64) -> Result<(), ()>,
    snapshot: impl FnOnce(u64) -> Result<PaintRegion, ()>) -> Result<Option<PaintRegion>, ()> {
    if hrgn != 0 { return snapshot(hrgn).map(Some); }
    read_rect(rect, read)
}
/// Copy and order a raw RECT before any owner mutation. # C: O(1)
pub(crate) fn read_rect(address: u64, read: impl FnOnce(&mut [u8], u64) -> Result<(), ()>) -> Result<Option<PaintRegion>, ()> {
    if address == 0 { return Ok(None); }
    address.checked_add(15).ok_or(())?;
    let mut bytes = [0; 16]; read(&mut bytes, address)?;
    let field = |at: usize| i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let (left, top, right, bottom) = (field(0), field(4), field(8), field(12));
    PaintRegion::from_rect(WindowRect { left: left.min(right), top: top.min(bottom), right: left.max(right), bottom: top.max(bottom) })
        .map(Some).map_err(|_| ())
}
