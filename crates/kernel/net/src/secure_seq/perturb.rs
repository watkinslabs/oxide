// Linux `table_perturb`.
//
// The connect-time port offset is a pure function of the 4-tuple, so two
// sockets connecting to the SAME destination would start their scans on the
// same port and collide on every attempt. Linux adds a per-bucket counter that
// advances by however far the last scan had to walk, spreading concurrent
// connects to one destination without making the offset predictable to anyone
// who cannot already see the local port.

use sync::{NetSecret as NetSecretClass, Spinlock};

/// Linux `CONFIG_INET_TABLE_PERTURB_ORDER`; upstream defaults to 16 (256 KiB).
/// A smaller table only increases how often two unrelated destinations share a
/// bucket, which costs a little contention spread and no secrecy — the offset
/// is still the keyed hash plus this counter.
const TABLE_ORDER: u32 = 8;
const TABLE_SIZE: usize = 1 << TABLE_ORDER;
const INDEX_MASK: u64 = TABLE_SIZE as u64 - 1;

/// Linux `get_random_u32_below(8)` — jitter added to the recorded walk length
/// so the next scan of this bucket does not resume at a fixed distance.
const ADVANCE_JITTER: u64 = 8;

/// Linux `step` for a socket that has not set its own local port range: the
/// connect scan visits one parity at a time (`secure_seq::scan::Parity`).
const PARITY_STEP: u32 = 2;

/// Seeded from the CSPRNG on first use, like Linux's
/// `get_random_sleepable_once(table_perturb, ...)`.
static TABLE: Spinlock<Option<[u32; TABLE_SIZE]>, NetSecretClass> = Spinlock::new(None);

/// Fill an unseeded table in place from the CSPRNG. # C: O(TABLE_SIZE)
fn seed(table: &mut [u32; TABLE_SIZE]) {
    for word in table.iter_mut() { *word = crng::next_u64() as u32; }
}

/// Bucket index and starting offset for one connect-time scan. Linux
/// `index = port_offset & (SIZE - 1); offset = table_perturb[index] +
/// (port_offset >> 32);` # C: O(1) amortized
pub(crate) fn connect_offset(port_offset: u64) -> (usize, u32) {
    let index = (port_offset & INDEX_MASK) as usize;
    let mut slot = TABLE.lock();
    if slot.is_none() {
        let mut table = [0u32; TABLE_SIZE];
        seed(&mut table);
        *slot = Some(table);
    }
    let table = slot.as_ref().expect("table seeded above");
    (index, table[index].wrapping_add((port_offset >> 32) as u32))
}

/// Advance a bucket by how far its scan actually walked, plus jitter — Linux
/// `i = max_t(int, i, get_random_u32_below(8) * step);
/// table_perturb[index] += i + step;` # C: O(1)
pub(crate) fn record_scan(index: usize, walked: u32) {
    let jitter = (crng::next_u64() % ADVANCE_JITTER) as u32 * PARITY_STEP;
    let advance = walked.max(jitter).wrapping_add(PARITY_STEP);
    let mut slot = TABLE.lock();
    if let Some(table) = slot.as_mut() {
        table[index] = table[index].wrapping_add(advance);
    }
}

/// Drop the seeded table so the next scan re-draws. Test-only. # C: O(1)
#[cfg(test)]
pub(crate) fn reset_for_test() { *TABLE.lock() = None; }
