pub(super) fn decode_cap(bdf: pci::Bdf, cfg_off: u8) -> Option<pci::MsixCap> {
    #[cfg(target_arch = "x86_64")]
    {
        hal_x86_64::pci::EcamPci::from_published()
            .and_then(|r| pci::decode_msix_cap(&r, bdf, cfg_off))
    }
    #[cfg(target_arch = "aarch64")]
    {
        hal_aarch64::pci::EcamPci::from_published()
            .and_then(|r| pci::decode_msix_cap(&r, bdf, cfg_off))
    }
}

pub(super) fn set_enabled(bdf: pci::Bdf, cfg_off: u8, enabled: bool) {
    let off = cfg_off & 0xFC;
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(r) = hal_x86_64::pci::EcamPci::from_published() {
            use pci::ConfigSpaceReader as _;
            let cur = r.read32(bdf, off);
            let new = pci::msix_control_value(cur, enabled);
            r.write32(bdf, off, new);
            let _ = r.read32(bdf, off);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
            let cur =
                <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::read32(&r, bdf, off);
            let new = pci::msix_control_value(cur, enabled);
            <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::write32(&r, bdf, off, new);
            let _ =
                <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::read32(&r, bdf, off);
            hal_aarch64::mmio_barrier();
        }
    }
}

pub(super) fn set_enabled_masked(bdf: pci::Bdf, cfg_off: u8) {
    let off = cfg_off & 0xFC;
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(r) = hal_x86_64::pci::EcamPci::from_published() {
            use pci::ConfigSpaceReader as _;
            let cur = r.read32(bdf, off);
            r.write32(bdf, off, pci::msix_control_enable_masked(cur));
            let _ = r.read32(bdf, off);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
            let cur =
                <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::read32(&r, bdf, off);
            <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::write32(
                &r,
                bdf,
                off,
                pci::msix_control_enable_masked(cur),
            );
            let _ =
                <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::read32(&r, bdf, off);
            hal_aarch64::mmio_barrier();
        }
    }
}

pub(super) fn clear_function_mask(bdf: pci::Bdf, cfg_off: u8) {
    set_enabled(bdf, cfg_off, true);
}

pub(super) fn mmio_flush() {
    #[cfg(target_arch = "aarch64")]
    hal_aarch64::mmio_barrier();
    #[cfg(target_arch = "x86_64")]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}
