// Bit flags: what a radio advertises, what a key was installed with, what a
// transmit request asks for, and what a driver reports about a received
// frame.

/// What the hardware can do. A driver sets these once, at registration, and
/// the transmit and receive chains branch on them: a bit set for hardware
/// that does not have the behaviour produces frames the peer discards.
pub mod hw {
    /// The radio reports signal strength in dBm rather than an arbitrary unit.
    pub const SIGNAL_DBM: u32 = 1 << 0;
    /// The radio reports an unspecified-unit signal.
    pub const SIGNAL_UNSPEC: u32 = 1 << 1;
    /// The radio assigns its own sequence numbers to data frames, so the
    /// software counter must not.
    pub const HAS_RATE_CONTROL: u32 = 1 << 2;
    /// The driver wants whole aggregated MSDUs delivered rather than split.
    pub const AMSDU_TO_MSDU: u32 = 1 << 3;
    /// The radio can fragment a frame itself.
    pub const SUPPORTS_TX_FRAG: u32 = 1 << 4;
    /// The radio buffers frames for sleeping stations itself.
    pub const AP_LINK_PS: u32 = 1 << 5;
    /// The radio runs its own connection monitor, so beacon loss is its call.
    pub const CONNECTION_MONITOR: u32 = 1 << 6;
    /// The radio needs its own dynamic power-save timer driven by software.
    pub const SUPPORTS_DYNAMIC_PS: u32 = 1 << 7;
    /// The radio reorders block-ack frames itself.
    pub const RX_REORDER: u32 = 1 << 8;
    /// The radio does its own duplicate detection.
    pub const RX_DEDUP: u32 = 1 << 9;
    /// The radio can scan without software driving the channel walk.
    pub const HW_SCAN: u32 = 1 << 10;
    /// The radio reports transmit status per frame.
    pub const REPORTS_TX_ACK_STATUS: u32 = 1 << 11;
    /// The radio runs the access-point management exchange in its own
    /// firmware, so the software responder must not also answer.
    pub const AP_SME: u32 = 1 << 12;
    /// The radio wants the whole 802.11 frame, header included, on transmit.
    pub const WANTS_FULL_FRAME: u32 = 1 << 13;
    /// The radio has hardware cipher engines and takes keys.
    pub const SUPPORTS_HW_CRYPTO: u32 = 1 << 14;
}

/// Per-key state a driver or the software cipher path needs.
pub mod key {
    /// The key was accepted by the hardware, so software must not also
    /// encrypt with it.
    pub const UPLOADED: u32 = 1 << 0;
    /// The key is the pairwise key of one peer.
    pub const PAIRWISE: u32 = 1 << 1;
    /// The key is installed for receive only, staged before a rekey.
    pub const RX_ONLY: u32 = 1 << 2;
    /// The key protects management frames.
    pub const MGMT: u32 = 1 << 3;
    /// The key protects beacons.
    pub const BEACON: u32 = 1 << 4;
    /// The software path must build the cipher header itself.
    pub const GENERATE_IV: u32 = 1 << 5;
    /// The software path must compute the integrity code itself.
    pub const GENERATE_MMIC: u32 = 1 << 6;
}

/// What one transmit request asks the lower layer for.
pub mod tx {
    /// The frame must not be fragmented whatever the threshold says.
    pub const DONTFRAG: u32 = 1 << 0;
    /// The frame needs no acknowledgement.
    pub const NO_ACK: u32 = 1 << 1;
    /// The frame must go out even though the destination is asleep.
    pub const CLEAR_PS_FILT: u32 = 1 << 2;
    /// The frame is part of a block-ack session.
    pub const AMPDU: u32 = 1 << 3;
    /// The frame belongs to the authentication exchange and may leave an
    /// interface whose controlled port is not yet authorized.
    pub const CTL_PORT: u32 = 1 << 4;
    /// The frame is already encrypted, or needs no encryption.
    pub const NO_ENCRYPT: u32 = 1 << 5;
    /// The frame is a management frame the caller wants status for.
    pub const REQ_TX_STATUS: u32 = 1 << 6;
    /// The frame goes out on the operating channel even during an off-channel
    /// operation.
    pub const TX_OFFCHAN: u32 = 1 << 7;
    /// The frame is being retransmitted.
    pub const RETRY: u32 = 1 << 8;
}

/// What a driver reports about a frame it received.
pub mod rx {
    /// The radio already decrypted the frame.
    pub const DECRYPTED: u32 = 1 << 0;
    /// The radio removed the cipher header.
    pub const IV_STRIPPED: u32 = 1 << 1;
    /// The radio removed the integrity field.
    pub const MIC_STRIPPED: u32 = 1 << 2;
    /// The radio checked the frame check sequence and it passed.
    pub const FCS_GOOD: u32 = 1 << 3;
    /// The frame failed its frame check sequence and is delivered only to a
    /// monitor interface.
    pub const FAILED_FCS_CRC: u32 = 1 << 4;
    /// The radio already reordered this frame, so the software buffer must
    /// pass it straight through.
    pub const NO_REORDER: u32 = 1 << 5;
    /// The frame carries an aggregated MSDU the radio has not split.
    pub const AMSDU: u32 = 1 << 6;
    /// The frame's integrity check failed in hardware.
    pub const MMIC_ERROR: u32 = 1 << 7;
    /// The radio reports the frame arrived while the receiver was scanning.
    pub const DURING_SCAN: u32 = 1 << 8;
}

/// What one interface's beaconed configuration changed, so a driver applies
/// only what moved rather than reprogramming the radio for every edit.
pub mod bss_changed {
    pub const ASSOC: u32 = 1 << 0;
    pub const ERP_PREAMBLE: u32 = 1 << 1;
    pub const ERP_SLOT: u32 = 1 << 2;
    pub const ERP_CTS_PROT: u32 = 1 << 3;
    pub const BEACON_INT: u32 = 1 << 4;
    pub const BSSID: u32 = 1 << 5;
    pub const BEACON: u32 = 1 << 6;
    pub const BEACON_ENABLED: u32 = 1 << 7;
    pub const PS: u32 = 1 << 8;
    pub const TXPOWER: u32 = 1 << 9;
    pub const QOS: u32 = 1 << 10;
    pub const HT: u32 = 1 << 11;
    pub const BASIC_RATES: u32 = 1 << 12;
    pub const IDLE: u32 = 1 << 13;
    pub const SSID: u32 = 1 << 14;
    pub const KEEP_ALIVE: u32 = 1 << 15;
}

/// What changed in the device-wide configuration.
pub mod conf_changed {
    pub const LISTEN_INTERVAL: u32 = 1 << 0;
    pub const MONITOR: u32 = 1 << 1;
    pub const PS: u32 = 1 << 2;
    pub const POWER: u32 = 1 << 3;
    pub const CHANNEL: u32 = 1 << 4;
    pub const RETRY_LIMITS: u32 = 1 << 5;
    pub const IDLE: u32 = 1 << 6;
    pub const SMPS: u32 = 1 << 7;
}

/// Receive-filter bits an interface's configuration asks the radio for.
pub mod filter {
    /// Deliver frames that failed their frame check sequence.
    pub const FCSFAIL: u32 = 1 << 0;
    /// Deliver frames whose decryption failed.
    pub const PLCPFAIL: u32 = 1 << 1;
    /// Deliver control frames addressed to other stations.
    pub const CONTROL: u32 = 1 << 2;
    /// Deliver every frame heard, addressed to this station or not.
    pub const OTHER_BSS: u32 = 1 << 3;
    /// Deliver probe requests.
    pub const PROBE_REQ: u32 = 1 << 4;
    /// Deliver beacons from networks this interface is not joined to.
    pub const BCN_PRBRESP_PROMISC: u32 = 1 << 5;
}
