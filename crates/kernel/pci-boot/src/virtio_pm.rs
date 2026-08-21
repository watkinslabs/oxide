//! Sleep callbacks for virtio children whose transport state is reset.

use super::virtio_bus::{parent_key, restore_transport};

fn block_freeze(device: &drv::Device) -> drv::KResult<()> {
    let key = parent_key(device).ok_or(drv::Error::ProbeFailed)?;
    if drv_virtio_blk::modern::freeze_blk(key) {
        Ok(())
    } else {
        Err(drv::Error::ProbeFailed)
    }
}

fn block_restore(device: &drv::Device) -> drv::KResult<()> {
    let key = parent_key(device).ok_or(drv::Error::ProbeFailed)?;
    if !drv_virtio_blk::modern::prepare_restore_blk(key)
        || !restore_transport(key)
        || !drv_virtio_blk::modern::unquiesce_blk(key)
    {
        return Err(drv::Error::ProbeFailed);
    }
    Ok(())
}

static BLOCK_PM: drv::DevPmOps = drv::DevPmOps {
    freeze: Some(block_freeze),
    thaw: Some(block_restore),
    poweroff: Some(block_freeze),
    restore: Some(block_restore),
    ..drv::DevPmOps::none()
};

pub(super) fn block_ops() -> &'static drv::DevPmOps { &BLOCK_PM }
