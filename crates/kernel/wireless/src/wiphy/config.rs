// The writable half of a radio's state, and the validation a `SET_WIPHY`
// must pass before any of it changes.
//
// Two conventions here are ABI and not style: a threshold of `u32::MAX` means
// the mechanism is off (there is no separate enable flag), and a retry limit
// of zero is not "no retries" but an invalid request.

use syscall::errno::Errno;

/// Sentinel meaning a fragmentation or RTS threshold is disabled.
pub const THRESHOLD_DISABLED: u32 = u32::MAX;
/// Smallest fragmentation threshold the standard allows.
pub const FRAG_THRESHOLD_MIN: u32 = 256;
/// Largest fragmentation threshold the standard allows.
pub const FRAG_THRESHOLD_MAX: u32 = 2346;
/// Largest RTS threshold that is not the disabled sentinel.
pub const RTS_THRESHOLD_MAX: u32 = 2347;
/// Retry limits are one to this, inclusive.
pub const RETRY_LIMIT_MIN: u8 = 1;
pub const RETRY_LIMIT_MAX: u8 = 255;
/// Largest coverage class, which sets the air-propagation slot allowance.
pub const COVERAGE_CLASS_MAX: u32 = 255;

/// `NL80211_TX_POWER_*` transmit-power setting modes.
pub mod tx_power_setting {
    pub const AUTOMATIC: u32 = 0;
    pub const LIMITED: u32 = 1;
    pub const FIXED: u32 = 2;
    pub const MAX: u32 = FIXED;
}

/// The radio configuration userspace can change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WiphyConfig {
    pub retry_short: u8,
    pub retry_long: u8,
    pub frag_threshold: u32,
    pub rts_threshold: u32,
    pub coverage_class: u32,
    pub tx_power_setting: u32,
    /// Transmit power in millibel-milliwatts, meaningful when the setting is
    /// not automatic.
    pub tx_power_mbm: i32,
    /// Antenna masks currently in use.
    pub antenna_tx: u32,
    pub antenna_rx: u32,
    /// Whether power save is on for the radio's client interfaces.
    pub power_save: bool,
    /// Transmit-queue byte and packet limits, and the fair-queue quantum.
    pub txq_limit: u32,
    pub txq_memory_limit: u32,
    pub txq_quantum: u32,
}

impl Default for WiphyConfig {
    fn default() -> Self {
        Self {
            retry_short: 7, retry_long: 4,
            frag_threshold: THRESHOLD_DISABLED, rts_threshold: THRESHOLD_DISABLED,
            coverage_class: 0,
            tx_power_setting: tx_power_setting::AUTOMATIC, tx_power_mbm: 0,
            antenna_tx: 0, antenna_rx: 0, power_save: false,
            txq_limit: 0, txq_memory_limit: 0, txq_quantum: 0,
        }
    }
}

/// One field a `SET_WIPHY` asks to change. Requests arrive as a set and are
/// validated as a set, because a request that changes four fields and fails
/// on the fourth must change none of them.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConfigRequest {
    pub retry_short: Option<u8>,
    pub retry_long: Option<u8>,
    pub frag_threshold: Option<u32>,
    pub rts_threshold: Option<u32>,
    pub coverage_class: Option<u32>,
    pub tx_power: Option<(u32, i32)>,
    pub antenna: Option<(u32, u32)>,
    pub txq_limit: Option<u32>,
    pub txq_memory_limit: Option<u32>,
    pub txq_quantum: Option<u32>,
}

impl ConfigRequest {
    /// Whether the request asks for nothing. # C: O(1)
    pub fn is_empty(&self) -> bool {
        self.retry_short.is_none() && self.retry_long.is_none()
            && self.frag_threshold.is_none() && self.rts_threshold.is_none()
            && self.coverage_class.is_none() && self.tx_power.is_none()
            && self.antenna.is_none() && self.txq_limit.is_none()
            && self.txq_memory_limit.is_none() && self.txq_quantum.is_none()
    }

    /// Check every requested field against the standard's ranges and against
    /// what the radio advertised. Nothing is applied. # C: O(1)
    pub fn validate(&self, avail_tx: u32, avail_rx: u32) -> Result<(), Errno> {
        if let Some(v) = self.retry_short {
            if !(RETRY_LIMIT_MIN..=RETRY_LIMIT_MAX).contains(&v) { return Err(Errno::Einval); }
        }
        if let Some(v) = self.retry_long {
            if !(RETRY_LIMIT_MIN..=RETRY_LIMIT_MAX).contains(&v) { return Err(Errno::Einval); }
        }
        if let Some(v) = self.frag_threshold {
            if v != THRESHOLD_DISABLED
                && !(FRAG_THRESHOLD_MIN..=FRAG_THRESHOLD_MAX).contains(&v)
            { return Err(Errno::Einval); }
        }
        if let Some(v) = self.rts_threshold {
            if v != THRESHOLD_DISABLED && v > RTS_THRESHOLD_MAX { return Err(Errno::Einval); }
        }
        if let Some(v) = self.coverage_class {
            if v > COVERAGE_CLASS_MAX { return Err(Errno::Einval); }
        }
        if let Some((setting, _)) = self.tx_power {
            if setting > tx_power_setting::MAX { return Err(Errno::Einval); }
        }
        if let Some((tx, rx)) = self.antenna {
            // A radio that advertised no antenna mask cannot have one set.
            if avail_tx == 0 || avail_rx == 0 { return Err(Errno::Eopnotsupp); }
            if tx & !avail_tx != 0 || rx & !avail_rx != 0 { return Err(Errno::Einval); }
            if tx == 0 || rx == 0 { return Err(Errno::Einval); }
        }
        Ok(())
    }

    /// Apply a request that has already validated. # C: O(1)
    pub fn apply(&self, cfg: &mut WiphyConfig) {
        if let Some(v) = self.retry_short { cfg.retry_short = v; }
        if let Some(v) = self.retry_long { cfg.retry_long = v; }
        if let Some(v) = self.frag_threshold { cfg.frag_threshold = v; }
        if let Some(v) = self.rts_threshold { cfg.rts_threshold = v; }
        if let Some(v) = self.coverage_class { cfg.coverage_class = v; }
        if let Some((setting, mbm)) = self.tx_power {
            cfg.tx_power_setting = setting;
            cfg.tx_power_mbm = if setting == tx_power_setting::AUTOMATIC { 0 } else { mbm };
        }
        if let Some((tx, rx)) = self.antenna { cfg.antenna_tx = tx; cfg.antenna_rx = rx; }
        if let Some(v) = self.txq_limit { cfg.txq_limit = v; }
        if let Some(v) = self.txq_memory_limit { cfg.txq_memory_limit = v; }
        if let Some(v) = self.txq_quantum { cfg.txq_quantum = v; }
    }
}
