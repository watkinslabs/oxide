/// Major boot milestones shown without `initcall_debug`.
///
/// Each record is emitted before its phase begins. The primary route reaches
/// the early UART before a real serial console registers; the direct VT write
/// is a no-op until the framebuffer console exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    EarlyKernel,
    RuntimeSetup,
    GraphicalConsole,
    DeviceProbe,
    SecondaryCpus,
    KernelWorkers,
    RootFilesystem,
    Userspace,
}

impl Phase {
    /// Every production boot phase, in the order it is announced. # C: O(1)
    pub const ALL: [Self; 8] = [
        Self::EarlyKernel,
        Self::RuntimeSetup,
        Self::GraphicalConsole,
        Self::DeviceProbe,
        Self::SecondaryCpus,
        Self::KernelWorkers,
        Self::RootFilesystem,
        Self::Userspace,
    ];

    /// Stable text shown for this boot phase. # C: O(1)
    pub const fn message(self) -> &'static [u8] {
        match self {
            Self::EarlyKernel => b"[BOOT] early kernel initialization\r\n",
            Self::RuntimeSetup => b"[BOOT] initializing runtime services\r\n",
            Self::GraphicalConsole => b"[BOOT] graphical console ready\r\n",
            Self::DeviceProbe => b"[BOOT] probing devices\r\n",
            Self::SecondaryCpus => b"[BOOT] starting secondary CPUs\r\n",
            Self::KernelWorkers => b"[BOOT] starting kernel workers\r\n",
            Self::RootFilesystem => b"[BOOT] mounting root filesystem\r\n",
            Self::Userspace => b"[BOOT] starting userspace\r\n",
        }
    }
}

/// Announce `phase` on the primary UART and the foreground VT.
///
/// The serial path is deliberately primary-only and synchronous, matching the
/// boot console's lock-safe route. The VT bypasses the normal nonblocking
/// klog framebuffer sink so a stage stays visible even before its drain runs.
/// # C: O(phase message bytes + foreground VT blit)
pub fn publish(phase: Phase) {
    let message = phase.message();
    klog::write_primary_raw(message);
    fbcon::kernel::vt_write(1, message);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::sync::Mutex;
    use std::vec::Vec;

    use super::{publish, Phase};

    static SERIAL: Mutex<Vec<u8>> = Mutex::new(Vec::new());

    fn capture(bytes: &[u8]) {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner()).extend_from_slice(bytes);
    }

    fn discard_flush(_pixels: &[u8], _rect: fbcon::kernel::FlushRect) {}

    #[test]
    fn phase_reaches_primary_serial_and_the_foreground_vt() {
        fbcon::kernel::kernel_unregister();
        klog::clear_byte_sink();
        klog::set_byte_sink(capture);
        SERIAL.lock().unwrap_or_else(|e| e.into_inner()).clear();
        fbcon::kernel::kernel_init(640, 480, discard_flush);

        publish(Phase::RootFilesystem);

        assert_eq!(
            SERIAL.lock().unwrap_or_else(|e| e.into_inner()).as_slice(),
            Phase::RootFilesystem.message(),
            "the phase must be observable through the primary serial route",
        );
        assert!(
            fbcon::kernel::screen_dump(false).starts_with(b"[BOOT] mounting root filesystem"),
            "the ready framebuffer must show the same phase",
        );
        fbcon::kernel::kernel_unregister();
        klog::clear_byte_sink();
    }

    #[test]
    fn every_phase_has_a_distinct_complete_line() {
        for phase in Phase::ALL {
            let message = phase.message();
            assert!(message.starts_with(b"[BOOT] "), "{phase:?} is not a boot record");
            assert!(message.ends_with(b"\r\n"), "{phase:?} does not terminate its line");
        }
        assert_ne!(Phase::RootFilesystem.message(), Phase::Userspace.message());
    }
}
