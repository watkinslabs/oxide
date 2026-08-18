//! ATA taskfile request and completion values.

/// ATA status BUSY bit. # C: O(1)
pub const STATUS_BUSY: u8 = 0x80;
/// ATA status device-fault bit. # C: O(1)
pub const STATUS_DF: u8 = 0x20;
/// ATA status data-request bit. # C: O(1)
pub const STATUS_DRQ: u8 = 0x08;
/// ATA status error bit. # C: O(1)
pub const STATUS_ERR: u8 = 0x01;

/// ATA command transfer protocol selected by SAT. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Protocol { NonData, PioIn, PioOut, DmaIn, DmaOut, NcqIn, NcqOut }

impl Protocol {
    /// Whether this taskfile transfers data from userspace to the device. # C: O(1)
    pub const fn writes(self) -> bool { matches!(self, Self::PioOut | Self::DmaOut | Self::NcqOut) }

    /// Whether this taskfile has a data phase. # C: O(1)
    pub const fn has_data(self) -> bool { !matches!(self, Self::NonData) }

    /// Whether this taskfile uses native command queueing. # C: O(1)
    pub const fn uses_ncq(self) -> bool { matches!(self, Self::NcqIn | Self::NcqOut) }
}

/// One ATA register taskfile after SAT or legacy-ioctl translation. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Taskfile {
    pub protocol:    Protocol,
    pub extend:      bool,
    pub feature:     u8,
    pub nsect:       u8,
    pub lbal:        u8,
    pub lbam:        u8,
    pub lbah:        u8,
    pub device:      u8,
    pub command:     u8,
    pub auxiliary:   u32,
    pub hob_feature: u8,
    pub hob_nsect:   u8,
    pub hob_lbal:    u8,
    pub hob_lbam:    u8,
    pub hob_lbah:    u8,
}

impl Taskfile {
    /// A zero-register non-data command taskfile. # C: O(1)
    pub const fn non_data(command: u8) -> Self {
        Self { protocol: Protocol::NonData, extend: false, feature: 0, nsect: 0, lbal: 0, lbam: 0, lbah: 0,
            device: 0, command, auxiliary: 0, hob_feature: 0, hob_nsect: 0, hob_lbal: 0, hob_lbam: 0, hob_lbah: 0 }
    }
}

/// ATA register result sampled after a completed taskfile command. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaskfileResult {
    pub extend:    bool,
    pub error:     u8,
    pub nsect:     u8,
    pub lbal:      u8,
    pub lbam:      u8,
    pub lbah:      u8,
    pub device:    u8,
    pub status:    u8,
    pub hob_nsect: u8,
    pub hob_lbal:  u8,
    pub hob_lbam:  u8,
    pub hob_lbah:  u8,
}

impl TaskfileResult {
    /// Whether ATA terminal status reports a command failure. # C: O(1)
    pub const fn failed(self) -> bool { self.status & (STATUS_BUSY | STATUS_DF | STATUS_DRQ | STATUS_ERR) != 0 }
}
