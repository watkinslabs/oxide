//! Feature-gated controller state at a failed native bring-up boundary.

use super::Nvme;
#[cfg(feature = "debug-boot")]
use super::regs;
use mmio_map::Mapping;

pub(super) fn bring_up_failed(nv: Nvme, stage: &'static [u8]) -> Mapping {
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[WARN]  nvme: bring-up ");
        klog::write_raw(stage);
        klog::write_raw(b" csts=");
        klog::write_hex_u64(u64::from(nv.r32(regs::REG_CSTS)));
        klog::write_raw(b" cc=");
        klog::write_hex_u64(u64::from(nv.r32(regs::REG_CC)));
        klog::write_raw(b"\n");
    }
    #[cfg(not(feature = "debug-boot"))]
    let _ = stage;
    nv.failed_bring_up()
}
