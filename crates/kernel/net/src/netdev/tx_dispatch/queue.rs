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
        let job = self.jobs[band * super::TX_BAND_CAPACITY + self.head[band]].take();
        self.head[band] = (self.head[band] + 1) % super::TX_BAND_CAPACITY;
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
