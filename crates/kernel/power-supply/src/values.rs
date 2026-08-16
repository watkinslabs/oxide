// Enumerated property values and the exact text each renders as. A power
// daemon parses these strings, so both the ordinals and the spellings —
// including the capitalisation and the hyphens — are ABI.

/// Supply category. Fixed at registration; the `type` attribute reads it
/// directly rather than asking the driver.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum PsyType {
    Unknown = 0,
    Battery = 1,
    Ups = 2,
    Mains = 3,
    Usb = 4,
    UsbDcp = 5,
    UsbCdp = 6,
    UsbAca = 7,
    UsbTypeC = 8,
    UsbPd = 9,
    UsbPdDrp = 10,
    AppleBrickId = 11,
    Wireless = 12,
}

/// `type` text, indexed by [`PsyType`] ordinal.
pub const TYPE_TEXT: &[&str] = &[
    "Unknown", "Battery", "UPS", "Mains", "USB", "USB_DCP", "USB_CDP", "USB_ACA",
    "USB_C", "USB_PD", "USB_PD_DRP", "BrickID", "Wireless",
];

/// `usb_type` text.
pub const USB_TYPE_TEXT: &[&str] = &[
    "Unknown", "SDP", "DCP", "CDP", "ACA", "C", "PD", "PD_DRP", "PD_PPS",
    "PD_SPR_AVS", "PD_PPS_SPR_AVS", "BrickID",
];

/// `status` text.
pub const STATUS_TEXT: &[&str] = &["Unknown", "Charging", "Discharging", "Not charging", "Full"];

/// `charge_type` / `charge_types` text.
pub const CHARGE_TYPE_TEXT: &[&str] = &[
    "Unknown", "N/A", "Trickle", "Fast", "Standard", "Adaptive", "Custom", "Long Life", "Bypass",
];

/// `health` text.
pub const HEALTH_TEXT: &[&str] = &[
    "Unknown", "Good", "Overheat", "Dead", "Over voltage", "Under voltage",
    "Unspecified failure", "Cold", "Watchdog timer expire", "Safety timer expire",
    "Over current", "Calibration required", "Warm", "Cool", "Hot", "No battery",
    "Blown fuse", "Cell imbalance",
];

/// `technology` text.
pub const TECHNOLOGY_TEXT: &[&str] = &["Unknown", "NiMH", "Li-ion", "Li-poly", "LiFe", "NiCd", "LiMn"];

/// `capacity_level` text.
pub const CAPACITY_LEVEL_TEXT: &[&str] = &["Unknown", "Critical", "Low", "Normal", "High", "Full"];

/// `scope` text.
pub const SCOPE_TEXT: &[&str] = &["Unknown", "System", "Device"];

/// `charge_behaviour` text. Lowercase and hyphenated — a different convention
/// from every other table here, and one userspace matches on literally.
pub const CHARGE_BEHAVIOUR_TEXT: &[&str] =
    &["auto", "inhibit-charge", "inhibit-charge-awake", "force-discharge"];

/// `status` values.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Status { Unknown = 0, Charging = 1, Discharging = 2, NotCharging = 3, Full = 4 }

/// `charge_type` values.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum ChargeType {
    Unknown = 0, None = 1, Trickle = 2, Fast = 3, Standard = 4, Adaptive = 5,
    Custom = 6, LongLife = 7, Bypass = 8,
}

/// `health` values.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Health {
    Unknown = 0, Good = 1, Overheat = 2, Dead = 3, OverVoltage = 4, UnderVoltage = 5,
    UnspecFailure = 6, Cold = 7, WatchdogTimerExpire = 8, SafetyTimerExpire = 9,
    OverCurrent = 10, CalibrationRequired = 11, Warm = 12, Cool = 13, Hot = 14,
    NoBattery = 15, BlownFuse = 16, CellImbalance = 17,
}

/// `technology` values.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Technology { Unknown = 0, NiMh = 1, LiIon = 2, LiPoly = 3, LiFe = 4, NiCd = 5, LiMn = 6 }

/// `capacity_level` values.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum CapacityLevel { Unknown = 0, Critical = 1, Low = 2, Normal = 3, High = 4, Full = 5 }

/// `scope` values.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Scope { Unknown = 0, System = 1, Device = 2 }

/// `usb_type` values.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum UsbType {
    Unknown = 0, Sdp = 1, Dcp = 2, Cdp = 3, Aca = 4, C = 5, Pd = 6, PdDrp = 7,
    PdPps = 8, PdSprAvs = 9, PdPpsSprAvs = 10, AppleBrickId = 11,
}

/// `charge_behaviour` values.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum ChargeBehaviour {
    Auto = 0, InhibitCharge = 1, InhibitChargeAwake = 2, ForceDischarge = 3,
}

/// Class name: the `/sys/class/<name>` directory and the uevent SUBSYSTEM.
pub const CLASS_NAME: &str = "power_supply";

/// Prefix on every uevent variable this class emits.
pub const UEVENT_PREFIX: &str = "POWER_SUPPLY_";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_text_table_covers_its_enum_exactly() {
        assert_eq!(TYPE_TEXT.len(), PsyType::Wireless as usize + 1);
        assert_eq!(USB_TYPE_TEXT.len(), UsbType::AppleBrickId as usize + 1);
        assert_eq!(STATUS_TEXT.len(), Status::Full as usize + 1);
        assert_eq!(CHARGE_TYPE_TEXT.len(), ChargeType::Bypass as usize + 1);
        assert_eq!(HEALTH_TEXT.len(), Health::CellImbalance as usize + 1);
        assert_eq!(TECHNOLOGY_TEXT.len(), Technology::LiMn as usize + 1);
        assert_eq!(CAPACITY_LEVEL_TEXT.len(), CapacityLevel::Full as usize + 1);
        assert_eq!(SCOPE_TEXT.len(), Scope::Device as usize + 1);
        assert_eq!(CHARGE_BEHAVIOUR_TEXT.len(), ChargeBehaviour::ForceDischarge as usize + 1);
    }

    #[test]
    fn the_spellings_userspace_matches_on_are_pinned() {
        assert_eq!(STATUS_TEXT[Status::NotCharging as usize], "Not charging");
        assert_eq!(STATUS_TEXT[Status::Discharging as usize], "Discharging");
        assert_eq!(TECHNOLOGY_TEXT[Technology::LiIon as usize], "Li-ion");
        assert_eq!(TECHNOLOGY_TEXT[Technology::LiPoly as usize], "Li-poly");
        assert_eq!(CHARGE_TYPE_TEXT[ChargeType::None as usize], "N/A");
        assert_eq!(CHARGE_TYPE_TEXT[ChargeType::LongLife as usize], "Long Life");
        assert_eq!(HEALTH_TEXT[Health::OverVoltage as usize], "Over voltage");
        assert_eq!(TYPE_TEXT[PsyType::Mains as usize], "Mains");
        assert_eq!(TYPE_TEXT[PsyType::Battery as usize], "Battery");
        assert_eq!(TYPE_TEXT[PsyType::AppleBrickId as usize], "BrickID");
        assert_eq!(CAPACITY_LEVEL_TEXT[CapacityLevel::Critical as usize], "Critical");
        assert_eq!(CHARGE_BEHAVIOUR_TEXT[ChargeBehaviour::InhibitCharge as usize], "inhibit-charge");
    }

    #[test]
    fn the_supply_type_ordinals_are_the_published_abi() {
        assert_eq!(PsyType::Unknown as u32, 0);
        assert_eq!(PsyType::Battery as u32, 1);
        assert_eq!(PsyType::Mains as u32, 3);
        assert_eq!(PsyType::Usb as u32, 4);
        assert_eq!(PsyType::Wireless as u32, 12);
    }
}
