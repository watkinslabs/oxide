use alloc::sync::Arc;

use crate::{imp, profile::ResetProfile, regs};

pub struct E1000eDriver;

impl drv::Driver for E1000eDriver {
    fn name(&self) -> &'static str { "e1000e" }
    fn matches(&self, dev: &drv::Device) -> bool { imp::supports_e1000e_82571_bm(dev) || imp::supports_e1000e_pch_m(dev) || imp::supports_e1000e_pch2(dev) }
    fn probe(&self, parent: &Arc<drv::Device>) -> drv::KResult<()> {
        let profile = if imp::supports_e1000e_pch2(parent) { ResetProfile::E1000E_PCH2 } else if imp::supports_e1000e_pch_m(parent) { ResetProfile::E1000E_PCH } else { ResetProfile::E1000E_82571_BM };
        imp::probe_common(parent, regs::dma_mask(true), profile)
    }
    fn remove(&self, dev: &drv::Device) { imp::remove_device(dev); }
    fn shutdown(&self, dev: &drv::Device) { imp::remove_device(dev); }
}

pub static E1000E_DRIVER: E1000eDriver = E1000eDriver;
