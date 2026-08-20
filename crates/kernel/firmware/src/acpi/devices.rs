//! Publication of the ACPI device drivers this crate owns.
//!
//! One entry point, called once the AML namespace is available, so a caller
//! does not have to know which classes exist or in what order they must be
//! populated. The AC adapters come first: a battery's charge status depends
//! on whether the machine is on mains, and a battery registered before any
//! adapter would report its first status from an empty supply list.

/// Number of devices each ACPI class provider published.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct AcpiDeviceCounts {
    pub adapters: usize,
    pub batteries: usize,
    pub backlights: usize,
    pub processor_cooling: usize,
    pub thermal_zones: usize,
}

impl AcpiDeviceCounts {
    /// Whether the platform published any of them. # C: O(1)
    pub fn any(&self) -> bool {
        self.adapters + self.batteries + self.backlights + self.processor_cooling + self.thermal_zones != 0
    }
}

/// Scan the firmware namespace and publish every ACPI power and display
/// device it describes. # C: O(namespace + AML)
pub fn init_devices() -> AcpiDeviceCounts {
    let _ = super::device_model::init();
    AcpiDeviceCounts {
        adapters: super::ac::init(),
        batteries: super::battery::init(),
        backlights: super::video::init(),
        // Before zones: a zone binds to cooling devices as it is registered.
        processor_cooling: super::processor_thermal::init(),
        thermal_zones: super::thermal::init(),
    }
}
