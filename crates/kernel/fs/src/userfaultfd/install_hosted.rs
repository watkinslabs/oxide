// Hosted counterpart of `install.rs`. The live install needs the PMM and a
// per-arch page-table walker, neither of which exists under `cargo test`, so
// the hosted build reports a full install. Everything a test cares about —
// range validation, the destination-VMA ladder, the wake/DONTWAKE decision and
// the `copy`/`zeropage` return protocol — happens around this call, in
// `policy.rs`, and is exercised for real.

use hal::PageFlags;
use syscall::errno::Errno;

/// # C: O(1)
pub fn install_pages(_mm: &vmm::AddressSpace, _dst0: u64, _src0: Option<u64>, len: u64, _flags: PageFlags)
    -> (u64, Option<Errno>) {
    (len, None)
}
