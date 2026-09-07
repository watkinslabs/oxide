//! Address-space and memory operations the allocator asks of its owner.

/// Reservation, commit and body access for one process address space. The
/// allocator performs no address-space work outside these calls, so a hosted
/// test can count exactly how many mappings a workload costs.
pub trait HeapBackend {
    /// Reserve `size` bytes of address space without committing them.
    fn reserve(&mut self, size: usize) -> Option<u64>;
    /// Commit `size` bytes at `base` inside an existing reservation.
    fn commit(&mut self, base: u64, size: usize) -> bool;
    /// Release a whole reservation.
    fn release(&mut self, base: u64, size: usize) -> bool;
    /// Read committed bytes.
    fn read(&self, addr: u64, out: &mut [u8]) -> bool;
    /// Write committed bytes.
    fn write(&mut self, addr: u64, data: &[u8]) -> bool;
    /// Fill committed bytes with one byte value.
    fn fill(&mut self, addr: u64, len: usize, byte: u8) -> bool;
}
