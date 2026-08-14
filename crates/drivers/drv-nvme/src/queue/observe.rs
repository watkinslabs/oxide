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

pub(super) fn cq_timeout(io: bool, cid: u16, d2: u32, d3: u32) {
    #[cfg(feature = "debug-boot")]
    {
        let mut faults = 0u64;
        let _ = iommu::poll_vtd_faults(&mut |_| { faults = faults.saturating_add(1); });
        klog::write_raw(b"[WARN]  nvme: cq timeout q=");
        klog::write_dec_u64(if io { 1 } else { 0 });
        klog::write_raw(b" cid="); klog::write_dec_u64(u64::from(cid));
        klog::write_raw(b" d2="); klog::write_hex_u64(u64::from(d2));
        klog::write_raw(b" d3="); klog::write_hex_u64(u64::from(d3));
        klog::write_raw(b" faults="); klog::write_dec_u64(faults);
        klog::write_raw(b"\n");
    }
    #[cfg(not(feature = "debug-boot"))]
    let _ = (io, cid, d2, d3);
}
