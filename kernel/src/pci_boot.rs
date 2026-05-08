// PCI enumeration boot helper — wraps `pci::enumerate` with per-arch
// `ConfigSpaceReader` selection (x86 LegacyPci CF8/CFC, aarch64
// EcamPci MMIO seeded by `device_map_smoke_arm`). Split out of
// `lib.rs` to keep that file under the 1000-line cap (08§7).

#![cfg(target_os = "oxide-kernel")]

/// Per-arch wrapper that walks the capability list for one BDF and
/// emits `[INFO] pci-cap ... id=...` lines. Pulled out of the main
/// enumeration block so the per-arch `ConfigSpaceReader` selection
/// only happens once per call.
/// # C: O(N_caps) — typical N is 1–6.
fn cap_dump_arch(bdf: pci::Bdf) {
    debug_boot! {
        let caps = {
            #[cfg(target_arch = "x86_64")]
            {
                let r = hal_x86_64::pci::LegacyPci;
                pci::capabilities(&r, bdf)
            }
            #[cfg(target_arch = "aarch64")]
            {
                match hal_aarch64::pci::EcamPci::from_published() {
                    Some(r) => pci::capabilities(&r, bdf),
                    None    => pci::heapless_caps::CapVec::new(),
                }
            }
        };
        for c in caps.iter() {
            klog::write_raw(b"[INFO]  pci-cap ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" id=");
            klog::write_hex_u64(c.id as u64);
            klog::write_raw(b" off=");
            klog::write_hex_u64(c.cfg_off as u64);
            klog::write_raw(b"\n");
        }
    }
}

/// Enumerate the live PCI bus and emit a `[INFO] pci ...` line per
/// device under `debug-boot`. v1 only walks bus 0 (single segment);
/// multi-bus discovery rides alongside the real driver work.
/// # SAFETY: caller is the boot path; per-arch ConfigSpaceReader
/// has been brought up (CF8/CFC available on x86; ECAM device-mapped
/// + `ECAM_BASE_VA` published on aarch64).
/// # C: O(N_bdfs probed)
pub fn enumerate_and_log() {
    debug_boot! {
        let devs = {
            #[cfg(target_arch = "x86_64")]
            {
                let r = hal_x86_64::pci::LegacyPci;
                pci::enumerate(&r)
            }
            #[cfg(target_arch = "aarch64")]
            {
                match hal_aarch64::pci::EcamPci::from_published() {
                    // ECAM mapping is bus 0 only on aarch64 v1 (1 MiB
                    // device-mapped at boot); enumerate cap matches.
                    Some(r) => pci::enumerate_buses(&r, 1),
                    None    => alloc::vec::Vec::new(),
                }
            }
        };
        klog::write_raw(b"[INFO]  pci: devices=");
        klog::write_dec_u64(devs.len() as u64);
        klog::write_raw(b"\n");
        for d in devs.iter().take(16) {
            klog::write_raw(b"[INFO]  pci ");
            klog::write_dec_u64(d.bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(d.bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(d.bdf.function as u64);
            klog::write_raw(b" vendor=");
            klog::write_hex_u64(d.vendor_id as u64);
            klog::write_raw(b" device=");
            klog::write_hex_u64(d.device_id as u64);
            klog::write_raw(b" class=");
            klog::write_hex_u64(d.class_code as u64);
            klog::write_raw(b"\n");
            // Capability list — modern devices always advertise MSI-X
            // + (for virtio) vendor-specific virtio-pci caps. Foundation
            // for upcoming MSI-X routing + virtio modern-transport work.
            cap_dump_arch(d.bdf);
        }
    }
}
