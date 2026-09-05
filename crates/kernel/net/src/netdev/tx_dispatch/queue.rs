use super::*;

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
macro_rules! tx_lock { ($lock:expr) => { $lock.lock_irqsave::<hal_x86_64::X86IrqGate>() }; }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
macro_rules! tx_lock { ($lock:expr) => { $lock.lock_irqsave::<hal_aarch64::ArmIrqGate>() }; }
#[cfg(not(target_os = "oxide-kernel"))]
macro_rules! tx_lock { ($lock:expr) => { $lock.lock() }; }

impl TxQueue {
    pub(super) const fn new() -> Self {
        Self { draining: false, head: [0; super::super::tx_band::TX_BANDS],
            len: [0; super::super::tx_band::TX_BANDS], jobs: Vec::new() }
    }

    /// A band is full on its own; a low-priority flood cannot take the slots a
    /// higher-priority one would use.
    pub(super) fn full(&self, band: usize) -> bool { self.len[band] == super::TX_BAND_CAPACITY }

    fn ensure_slots(&mut self) {
        if self.jobs.is_empty() {
            self.jobs.resize_with(super::TX_QUEUE_CAPACITY, || None);
        }
    }

    pub(super) fn push(&mut self, band: usize, job: TxJob) {
        self.ensure_slots();
        let tail = band * super::TX_BAND_CAPACITY
            + (self.head[band] + self.len[band]) % super::TX_BAND_CAPACITY;
        self.jobs[tail] = Some(job);
        self.len[band] += 1;
    }

    pub(super) fn pop(&mut self) -> Option<TxJob> {
        let band = (0..super::super::tx_band::TX_BANDS).find(|band| self.len[*band] != 0)?;
        // A nonzero length implies `push` ran, so the slots are materialised.
        // Within a transmit band, Linux's departure-time qdisc consumes the
        // earliest requested timestamp first. Zero is the immediate-send
        // value and therefore sorts before timestamped packets. The ring is
        // retained for equal timestamps so FIFO remains the tie-breaker.
        let mut selected = self.head[band];
        let mut selected_time = u64::MAX;
        for offset in 0..self.len[band] {
            let slot = (self.head[band] + offset) % super::TX_BAND_CAPACITY;
            let job = self.jobs[band * super::TX_BAND_CAPACITY + slot].as_ref()
                .expect("a nonempty transmit band has materialised jobs");
            let time = job.transmit_time();
            if time < selected_time {
                selected = slot;
                selected_time = time;
            }
        }
        let job = self.jobs[band * super::TX_BAND_CAPACITY + selected].take();
        // Remove from the ring while preserving its FIFO order for the
        // remaining entries. This is bounded by the per-band queue capacity.
        let mut cursor = selected;
        for _ in 0..self.len[band] - 1 {
            let next = (cursor + 1) % super::TX_BAND_CAPACITY;
            self.jobs[band * super::TX_BAND_CAPACITY + cursor] =
                self.jobs[band * super::TX_BAND_CAPACITY + next].take();
            cursor = next;
        }
        self.jobs[band * super::TX_BAND_CAPACITY + cursor] = None;
        self.len[band] -= 1;
        job
    }
}

impl TxCompletion {
    pub(super) fn complete(&self, result: NetResult<()>) { *tx_lock!(self.result) = Some(result); }

    pub(super) fn wait(&self) -> NetResult<()> {
        loop {
            if let Some(result) = *tx_lock!(self.result) { return result; }
            sync::relax();
        }
    }
}
