// User→user byte relocation for `mremap`'s copy arms, with fault recovery.
//
// The reference does NOT copy bytes for a move: it relocates page-table
// entries under the mm write lock, so no user access happens at all and
// there is nothing to fault on. Oxide's VMA layer cannot reach the page
// tables (they live in the PMM crate), so the move is emulated by reading
// the source and writing the destination through user addresses. That
// emulation must therefore survive a concurrent thread tearing either
// range down mid-transfer — which the reference gets for free.
//
// Nothing here dereferences user memory itself. The transfer is expressed
// against `UserXfer` so the chunking, the fault split and the
// bytes-relocated accounting are ordinary logic that a hosted test can
// drive, per the phantom-test rule (`CLAUDE.md`).

/// Bytes moved per bounce-buffer round trip.
///
/// Sized to keep the buffer off the kernel stack's budget while still
/// amortising the two range checks each transfer performs.
pub const CHUNK_BYTES: usize = 512;

/// A pair of fault-recovering user accesses.
///
/// Both directions report **bytes NOT transferred**, the contract the
/// exception-table copy routines already use: `0` is a complete transfer,
/// anything else means the access faulted at that offset and the fault was
/// absorbed rather than delivered.
pub trait UserXfer {
    /// Read into `buf` from user address `src`. Returns bytes not read.
    /// # C: O(len + page faults)
    fn read(&mut self, src: u64, buf: &mut [u8]) -> usize;
    /// Write `buf` to user address `dst`. Returns bytes not written.
    /// # C: O(len + page faults)
    fn write(&mut self, dst: u64, buf: &[u8]) -> usize;
}

/// Move `len` bytes from user `src` to user `dst`.
///
/// `Err(n)` reports that a user access faulted after `n` bytes had reached
/// the destination — the caller owns the rollback, since only it knows
/// which of the two ranges it created. A faulting chunk contributes only
/// the prefix the destination actually received: a short *read* has written
/// nothing of that chunk, a short *write* has written its prefix.
/// # C: O(len)
pub fn relocate(src: u64, dst: u64, len: usize, x: &mut impl UserXfer) -> Result<(), usize> {
    let mut buf = [0u8; CHUNK_BYTES];
    let mut done = 0usize;
    while done < len {
        let n = core::cmp::min(CHUNK_BYTES, len - done);
        let chunk = &mut buf[..n];
        let off = done as u64;
        if x.read(src + off, chunk) != 0 { return Err(done); }
        let missed = x.write(dst + off, chunk);
        if missed != 0 { return Err(done + (n - missed)); }
        done += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// A transfer pair over two byte arrays, either of which can be made to
    /// fault from a chosen offset onward — the sibling-thread unmap the
    /// reference never has to survive.
    struct Fake {
        src: Vec<u8>,
        dst: Vec<u8>,
        read_faults_at: Option<usize>,
        write_faults_at: Option<usize>,
        reads: usize,
    }

    impl Fake {
        fn new(len: usize) -> Self {
            let src = (0..len).map(|i| (i % 251) as u8).collect();
            Fake { src, dst: vec![0u8; len], read_faults_at: None, write_faults_at: None, reads: 0 }
        }
    }

    // Addresses are plain indexes into the two arrays: this exercises the
    // loop's arithmetic, not any mapping.
    impl UserXfer for Fake {
        fn read(&mut self, src: u64, buf: &mut [u8]) -> usize {
            self.reads += 1;
            let at = src as usize;
            let ok = match self.read_faults_at {
                Some(f) if f <= at => 0,
                Some(f) if f < at + buf.len() => f - at,
                _ => buf.len(),
            };
            buf[..ok].copy_from_slice(&self.src[at..at + ok]);
            buf.len() - ok
        }
        fn write(&mut self, dst: u64, buf: &[u8]) -> usize {
            let at = dst as usize;
            let ok = match self.write_faults_at {
                Some(f) if f <= at => 0,
                Some(f) if f < at + buf.len() => f - at,
                _ => buf.len(),
            };
            self.dst[at..at + ok].copy_from_slice(&buf[..ok]);
            buf.len() - ok
        }
    }

    /// A transfer with no fault delivers every byte at the right offset. A
    /// chunked loop that drifts by a chunk still "succeeds" while relocating
    /// the wrong bytes, so the content is the assertion, not the count.
    #[test]
    fn an_unobstructed_relocation_delivers_every_byte_in_order() {
        let len = CHUNK_BYTES * 3 + 37;
        let mut f = Fake::new(len);
        assert_eq!(relocate(0, 0, len, &mut f), Ok(()));
        assert_eq!(f.dst, f.src);
        assert_eq!(f.reads, 4, "the tail is one short chunk, not one byte at a time");
    }

    /// A transfer shorter than one chunk is one round trip, not zero.
    #[test]
    fn a_sub_chunk_relocation_still_moves_its_bytes() {
        let mut f = Fake::new(9);
        assert_eq!(relocate(0, 0, 9, &mut f), Ok(()));
        assert_eq!(f.dst, f.src);
        assert_eq!(f.reads, 1);
    }

    /// A zero-length transfer touches user memory not at all.
    #[test]
    fn a_zero_length_relocation_performs_no_user_access() {
        let mut f = Fake::new(16);
        assert_eq!(relocate(0, 0, 0, &mut f), Ok(()));
        assert_eq!(f.reads, 0);
    }

    /// The source vanishing mid-transfer is reported, not fatal, and the
    /// count names only what reached the destination. Without recovery this
    /// is the kernel fault the row describes.
    #[test]
    fn a_source_that_vanishes_mid_transfer_is_reported_at_the_last_whole_chunk() {
        let len = CHUNK_BYTES * 4;
        let mut f = Fake::new(len);
        f.read_faults_at = Some(CHUNK_BYTES * 2 + 8);
        // The chunk that faults on its READ put nothing in the destination.
        assert_eq!(relocate(0, 0, len, &mut f), Err(CHUNK_BYTES * 2));
        assert!(f.dst[CHUNK_BYTES * 2..].iter().all(|&b| b == 0));
        assert_eq!(&f.dst[..CHUNK_BYTES * 2], &f.src[..CHUNK_BYTES * 2]);
    }

    /// The destination vanishing mid-transfer credits the prefix that landed
    /// before the fault — a read succeeded, so the two directions do not
    /// report the same count for the same chunk.
    #[test]
    fn a_destination_that_vanishes_mid_transfer_credits_the_prefix_that_landed() {
        let len = CHUNK_BYTES * 4;
        let mut f = Fake::new(len);
        f.write_faults_at = Some(CHUNK_BYTES * 2 + 8);
        assert_eq!(relocate(0, 0, len, &mut f), Err(CHUNK_BYTES * 2 + 8));
        assert_eq!(&f.dst[..CHUNK_BYTES * 2 + 8], &f.src[..CHUNK_BYTES * 2 + 8]);
        assert!(f.dst[CHUNK_BYTES * 2 + 8..].iter().all(|&b| b == 0));
    }

    /// A range unmapped before the first byte moves relocates nothing.
    #[test]
    fn a_range_already_gone_relocates_nothing() {
        let mut f = Fake::new(CHUNK_BYTES);
        f.read_faults_at = Some(0);
        assert_eq!(relocate(0, 0, CHUNK_BYTES, &mut f), Err(0));
        assert!(f.dst.iter().all(|&b| b == 0));
    }

    /// Source and destination are independent addresses: the loop must apply
    /// its running offset to both, not read the destination's.
    #[test]
    fn source_and_destination_advance_independently() {
        let len = CHUNK_BYTES + 4;
        let mut f = Fake::new(len * 2);
        assert_eq!(relocate(0, len as u64, len, &mut f), Ok(()));
        assert_eq!(&f.dst[len..len * 2], &f.src[..len]);
        assert!(f.dst[..len].iter().all(|&b| b == 0));
    }
}
