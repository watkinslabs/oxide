use super::*;

const COMMON_CFG_VA: u64 = 0x1000;
const HHDM_VA: u64 = 0x2000;
const DEVICE_CFG_BYTES: usize = 32;
const CAPACITY_SECTORS: u64 = 16_384;
const LOGICAL_BLOCK_BYTES: u32 = 4_096;

fn write_cfg(bytes: &mut [u8; DEVICE_CFG_BYTES], off: u64, src: &[u8]) {
    let off = off as usize;
    bytes[off..off + src.len()].copy_from_slice(src);
}

fn resources_for_cfg(bytes: &[u8; DEVICE_CFG_BYTES]) -> virtio::VirtioResources {
    virtio::VirtioResources::new(COMMON_CFG_VA, HHDM_VA)
        .with_device_cfg_va(bytes.as_ptr() as u64)
}

#[test]
fn blk_capacity_and_block_size_read_from_child_config_resource() {
    let mut cfg = [0u8; DEVICE_CFG_BYTES];
    write_cfg(&mut cfg, virtio::BLK_CFG_OFF_CAPACITY, &CAPACITY_SECTORS.to_le_bytes());
    write_cfg(&mut cfg, virtio::BLK_CFG_OFF_BLK_SIZE, &LOGICAL_BLOCK_BYTES.to_le_bytes());

    let got = crate::modern::test_read_device_config(
        resources_for_cfg(&cfg),
        virtio::VIRTIO_BLK_F_BLK_SIZE,
    );

    assert_eq!(got, Some((CAPACITY_SECTORS, LOGICAL_BLOCK_BYTES)));
}

#[test]
fn blk_config_uses_default_sector_size_without_negotiated_blk_size() {
    let mut cfg = [0u8; DEVICE_CFG_BYTES];
    write_cfg(&mut cfg, virtio::BLK_CFG_OFF_CAPACITY, &CAPACITY_SECTORS.to_le_bytes());
    write_cfg(&mut cfg, virtio::BLK_CFG_OFF_BLK_SIZE, &LOGICAL_BLOCK_BYTES.to_le_bytes());

    let got = crate::modern::test_read_device_config(resources_for_cfg(&cfg), 0);

    assert_eq!(got, Some((CAPACITY_SECTORS, blk::VIRTIO_BLK_SECTOR_BYTES)));
}

#[test]
fn blk_config_requires_generic_device_cfg_resource() {
    let resources = virtio::VirtioResources::new(COMMON_CFG_VA, HHDM_VA);

    assert_eq!(crate::modern::test_read_device_config(resources, 0), None);
}

#[test]
fn blk_transport_profile_declares_blk_size_feature() {
    let features = crate::modern::wanted_features();
    let profile = crate::modern::transport_profile();

    assert_ne!(features & virtio::VIRTIO_BLK_F_BLK_SIZE, 0);
    assert_eq!(profile.drv_features, features);
    assert!(profile.child_requirements.needs_device_cfg);
    assert!(profile.child_requirements.required_queues[0]);
    assert!(profile.child_requirements.required_queues[1..].iter().all(|required| !required));
}
