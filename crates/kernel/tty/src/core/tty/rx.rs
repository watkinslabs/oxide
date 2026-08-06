// RX half of `TtyStruct` — Linux `tty_insert_flip_string` /
// `tty_flip_buffer_push` (the device-interrupt entry) and `flush_to_ldisc`
// (the workqueue entry that actually cooks). Split out of `core/tty.rs` per
// `08§7`; the ring itself is `core/flip.rs`.

use crate::core::api::TtyDriver;
use crate::ldisc::LdiscOps;
use crate::core::flip;
use crate::core::tty::{PortInner, TtyStruct, TxCollector};
use crate::wait::TtyWait;

impl<D: TtyDriver, W: TtyWait> TtyStruct<D, W> {
    /// Linux `tty_insert_flip_string` + `tty_flip_buffer_push`: the INTERRUPT
    /// half of the RX path. Stages `input` and returns — no line discipline, no
    /// echo transmission, no wakeup, no allocation. Returns the number of bytes
    /// accepted; a short return is a FIFO overrun (the ring is full because the
    /// consumer has not run).
    ///
    /// The caller schedules `flush_to_ldisc` on a workqueue, exactly as Linux's
    /// `tty_flip_buffer_push` queues `buf->work`.
    /// # C: O(len)
    /// # Ctx: any, including hard IRQ
    /// # Sleeps: no
    pub fn insert_flip(&self, input: &[u8]) -> usize {
        self.flip.lock_irqsave::<W::Irq>().insert(input)
    }

    /// Bytes refused because the flip ring was full, since boot — Linux's
    /// silent buffer-overrun count, made visible. # C: O(1)
    pub fn flip_dropped(&self) -> u64 { self.flip.lock_irqsave::<W::Irq>().dropped() }

    /// Staged bytes still owed to the line discipline. The flush worker checks
    /// this after clearing its pending flag, so a byte staged mid-drain — which
    /// saw the flag set and therefore queued nothing — is not stranded until
    /// the next keystroke. # C: O(1)
    pub fn flip_pending(&self) -> usize { self.flip.lock_irqsave::<W::Irq>().pending() }

    /// Linux `flush_to_ldisc` (`drivers/tty/tty_buffer.c`, the `buf->work`
    /// callback): drain everything `insert_flip` staged into the line
    /// discipline, in PROCESS context. Loops until the ring is empty so a byte
    /// inserted mid-drain is not stranded waiting for the next keystroke.
    ///
    /// The CALLER must guarantee only one flush runs at a time — Linux gets
    /// that free, because the workqueue core never runs one `work_struct`
    /// concurrently with itself. Two concurrent drains would each take a chunk
    /// and could hand them to the ldisc out of order, which is byte
    /// reordering, not just a missed wakeup.
    /// # C: O(staged bytes)
    /// # Ctx: process
    /// # Sleeps: yes — the ldisc echo transmits, and the wake takes rq locks
    pub fn flush_to_ldisc(&self) {
        loop {
            let mut chunk = [0u8; flip::FLUSH_CHUNK];
            let n = self.flip.lock_irqsave::<W::Irq>().drain(&mut chunk);
            if n == 0 { return; }
            self.receive_from_driver(&chunk[..n]);
        }
    }

    /// RX path: device delivered `input` (UART RX / kbd). Runs the ldisc
    /// receive pipeline (cook/echo/ISIG) UNDER the port lock, emits any echo
    /// through the separate output owner AFTER releasing that irqsave lock,
    /// then wakes parked readers. The under-lock queue + release-then-wake is
    /// the producer half of the lost-wakeup-free protocol (module header).
    /// # C: O(N) input bytes + O(W) waiters
    pub fn receive_from_driver(&self, input: &[u8]) {
        let Some(sink) = D::detached_sink() else {
            let mut g = self.inner.lock_irqsave::<W::Irq>();
            let PortInner { ldisc, driver } = &mut *g;
            ldisc.receive_buf(driver, input);
            drop(g);
            self.wake_rx();
            return;
        };
        // Same lock order as write: output owner before port state. This is
        // the local equivalent of N_TTY's output_lock and prevents a program
        // write from overtaking an echo collected from earlier input.
        let _tx = self.tx.lock();
        let pending = {
            let mut g = self.inner.lock_irqsave::<W::Irq>();
            let PortInner { ldisc, driver } = &mut *g;
            let mut tx = TxCollector { drv: driver, buf: alloc::vec::Vec::new() };
            ldisc.receive_buf(&mut tx, input);
            tx.buf
        };
        // Port guard dropped and IRQ state restored before device submission.
        if !pending.is_empty() { sink(&pending); }
        drop(_tx);
        self.wake_rx();
    }

    /// Publish an RX readability transition after the port owner released.
    /// # C: O(W) parked readers + poll subscribers
    fn wake_rx(&self) {
        // Wake AFTER dropping the lock: a reader that enqueued under the
        // lock (park_prepare) and then re-checked is guaranteed visible to
        // wake_all here, because its enqueue serialized with our queue
        // above on the same port lock.
        self.wait.wake_all();
        // The RX byte queue just flipped POLLIN readable: wake ONLY the tasks
        // polling THIS tty (poll/select/ppoll/epoll subscribed to our
        // `PollSubscribers` via the fd inode's `poll_subscribers()`). Per-fd,
        // targeted — the Linux `->poll` wait-queue wake. Outside the port lock
        // (same as the reader wake); level-triggered, so spurious wakes safe.
        // Keyed POLLIN, like Linux `n_tty_receive_buf` →
        // `wake_up_interruptible_poll(&tty->read_wait, EPOLLIN | EPOLLRDNORM)`.
        self.subs.notify_mask(vfs::POLL_IN);
    }
}
