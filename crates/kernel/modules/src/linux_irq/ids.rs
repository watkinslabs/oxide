// Only `linux_irq::arm_irq_is_msi` reads this, and that fn is aarch64-only.
#[cfg(target_arch = "aarch64")]
pub(crate) const ARM_LPI_BASE: u32 = 8192;
