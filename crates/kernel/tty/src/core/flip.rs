// Linux `drivers/tty/tty_buffer.c` — the flip buffer that separates the
// device interrupt from the line discipline.
//
// Linux's serial ISR does NOT run the ldisc. `serial8250_handle_irq` reads the
// FIFO into `uart_insert_char` -> `tty_insert_flip_char`, calls
// `tty_flip_buffer_push`, and returns; `flush_to_ldisc` then runs
// `receive_buf` from a WORKQUEUE, in process context, where echo transmission,
// wakeups and allocation are all legal.
//
// This port ran the whole pipeline — `n_tty_receive_buf`, the inline echo
// (which polls the UART's THRE up to 100 000 times PER BYTE), `wake_all` (which
// builds a `Vec<Arc<Task>>` and takes runqueue locks) and the poll fan-out —
// directly in the UART interrupt handler, on the 16 KiB per-CPU hardirq stack.
// That stack's measured peak was already 14.5 KiB during a net-RX softirq
// drain, and the drain deliberately re-enables interrupts on that same stack
// (`arch-irq/src/lapic/dispatch.rs`, `hal-x86_64/src/irq.rs`'s nested-entry
// arm), so a keystroke arriving during a drain stacked the whole RX chain on
// top of it. `#PF` has no IST entry (`hal-x86_64/src/tss.rs`), so touching the
// guard page turned straight into the `#DF` observed while typing at the debug
// shell — attributed to `sched::diag::emit::sysrq_rx` only because that is the
// first non-inlined call after the byte leaves the RBR.
//
// The ring is the whole fix: the ISR does a memcpy under an irqsave spinlock
// and returns.
//
// No target gate — every rule here is `cargo test`-provable.

use alloc::collections::VecDeque;

/// Bytes buffered per port before input is dropped. Linux's per-port default
/// is `tty_buffer_space_avail`'s 64 KiB, sized for multi-megabit serial links;
/// a 115200-baud console produces ~11.5 KB/s, so 4 KiB is a third of a second
/// of continuous input — orders of magnitude more than a workqueue round trip,
/// and small enough to sit inline in every `TtyStruct` (ptys included).
pub const FLIP_CAPACITY: usize = 4096;

/// Linux `struct tty_bufhead`: the staging area between the device interrupt
/// and `flush_to_ldisc`.
pub struct FlipRing {
    buf: VecDeque<u8>,
    /// Linux counts these as silent FIFO overruns. Surfaced rather than
    /// swallowed so a saturating console is visible instead of "characters go
    /// missing sometimes".
    dropped: u64,
}

impl FlipRing {
    /// Pre-reserve the whole ring, because the producer is an interrupt
    /// handler and must never allocate. # C: O(FLIP_CAPACITY)
    pub fn new() -> Self {
        Self { buf: VecDeque::with_capacity(FLIP_CAPACITY), dropped: 0 }
    }

    /// Linux `tty_insert_flip_string`: stage `input`, returning how many bytes
    /// were accepted. A short return means the ring was full and the remainder
    /// is lost — the same outcome as a UART FIFO overrun, and Linux's when
    /// `tty_buffer_alloc` fails.
    /// # C: O(len)
    /// # Ctx: any, including hard IRQ — copies only, never allocates
    pub fn insert(&mut self, input: &[u8]) -> usize {
        let room = FLIP_CAPACITY - self.buf.len();
        let take = if input.len() <= room { input.len() } else { room };
        for &b in &input[..take] { self.buf.push_back(b); }
        self.dropped += (input.len() - take) as u64;
        take
    }

    /// Linux `flush_to_ldisc`'s copy step: move up to `out.len()` staged bytes
    /// out for the line discipline. Zero means the ring is empty.
    /// # C: O(n)
    pub fn drain(&mut self, out: &mut [u8]) -> usize {
        let n = if self.buf.len() < out.len() { self.buf.len() } else { out.len() };
        for slot in out.iter_mut().take(n) {
            // `n <= self.buf.len()`, so every pop yields a byte.
            *slot = self.buf.pop_front().unwrap_or(0);
        }
        n
    }

    /// Staged bytes awaiting `flush_to_ldisc`. # C: O(1)
    pub fn pending(&self) -> usize { self.buf.len() }

    /// Bytes refused because the ring was full, since boot. # C: O(1)
    pub fn dropped(&self) -> u64 { self.dropped }

    /// TCFLSH `TCIFLUSH` must discard what is staged as well as what the ldisc
    /// already cooked, or a flush leaves input that arrives moments later.
    /// # C: O(1)
    pub fn clear(&mut self) { self.buf.clear(); }
}

impl Default for FlipRing {
    fn default() -> Self { Self::new() }
}

/// One `flush_to_ldisc` copy chunk. Sized so a full ring drains in a handful
/// of ldisc calls without putting `FLIP_CAPACITY` bytes on the worker's stack.
pub const FLUSH_CHUNK: usize = 256;

#[cfg(test)]
#[path = "flip/tests.rs"] mod tests;
