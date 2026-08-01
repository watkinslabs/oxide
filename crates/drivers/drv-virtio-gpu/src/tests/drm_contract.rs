use super::super::*;
use super::support::{key, test_device};
use drm::DrmDriver;

const FIRST_MODE_WIDTH: u32 = 800;
const FIRST_MODE_HEIGHT: u32 = 600;
const SECOND_MODE_WIDTH: u32 = 1024;
const SECOND_MODE_HEIGHT: u32 = 768;
const ENABLED_SCANOUT_COUNT: u32 = 2;
const TEST_XRGB8888_FOURCC: u32 = 0x3432_5258;
const TEST_ARGB8888_FOURCC: u32 = 0x3432_5241;
const UNSUPPORTED_FOURCC: u32 = 0xdead_beef;
const FIRST_TEST_BDF: u32 = 0x0010_0000;
const SECOND_TEST_BDF: u32 = 0x0001_0203;
const FIRST_TEST_UNIQUE: &str = "pci:0000:10:00.0";
const SECOND_TEST_UNIQUE: &str = "pci:0000:01:02.3";

#[test]
fn drm_accessors_skip_disabled_scanouts() {
    let mut modes = [VirtioGpuDisplayOne::default(); VIRTIO_GPU_MAX_SCANOUTS];
    modes[1] = VirtioGpuDisplayOne {
        r: VirtioGpuRect {
            x: 0,
            y: 0,
            width: FIRST_MODE_WIDTH,
            height: FIRST_MODE_HEIGHT,
        },
        enabled: 1,
        flags: 0,
    };
    modes[3] = VirtioGpuDisplayOne {
        r: VirtioGpuRect {
            x: 0,
            y: 0,
            width: SECOND_MODE_WIDTH,
            height: SECOND_MODE_HEIGHT,
        },
        enabled: 1,
        flags: 0,
    };
    let driver = VirtioGpuDrm {
        display: DisplayInfo {
            modes,
            count_enabled: ENABLED_SCANOUT_COUNT,
        },
        features_negotiated: 0,
        bdf: 0,
        unique: drm_unique_from_bdf(0),
        edid: None,
    };
    assert_eq!(
        driver.crtc_ids(),
        alloc::vec![drm::crtc_id_for(0), drm::crtc_id_for(1)]
    );
    assert_eq!(
        driver.connector_ids(),
        alloc::vec![drm::connector_id_for(0), drm::connector_id_for(1)]
    );
    assert_eq!(
        driver.encoder_ids(),
        alloc::vec![drm::encoder_id_for(0), drm::encoder_id_for(1)]
    );
    assert_eq!(
        driver.plane_ids(),
        alloc::vec![
            drm::plane_id_for(0),
            drm::plane_id_for(1),
            drm::plane_id_for(2),
            drm::plane_id_for(3),
        ]
    );
    let first_mode = driver.mode_for(0);
    assert_eq!(u32::from(first_mode.hdisplay), FIRST_MODE_WIDTH);
    assert_eq!(u32::from(first_mode.vdisplay), FIRST_MODE_HEIGHT);
    let second_mode = driver.mode_for(1);
    assert_eq!(u32::from(second_mode.hdisplay), SECOND_MODE_WIDTH);
    assert_eq!(u32::from(second_mode.vdisplay), SECOND_MODE_HEIGHT);

    let connector = driver.connector_info(1).unwrap();
    assert_eq!(connector.connection, drm::DRM_MODE_CONNECTED);
    assert_eq!(connector.encoder_id, drm::encoder_id_for(1));
    // The connector publishes a real mode list: its current rect preferred and
    // first, plus the standard alternatives a compositor can switch to.
    let modes = driver.modes_for(1);
    assert_eq!(u32::from(modes[0].hdisplay), SECOND_MODE_WIDTH);
    assert_eq!(u32::from(modes[0].vdisplay), SECOND_MODE_HEIGHT);
    assert_ne!(modes[0].ty & drm::DRM_MODE_TYPE_PREFERRED, 0);
    assert!(modes.len() > 1, "one mode leaves the compositor no choice");
    assert!(modes.iter().any(|m| u32::from(m.hdisplay) == 1920 && u32::from(m.vdisplay) == 1080));
    let crtc = driver.crtc_info(1).unwrap();
    assert_eq!(crtc.mode_valid, 1);
    assert_eq!(crtc.fb_id, 0);
    assert_eq!(
        driver.virtgpu_get_caps(0),
        Some(drm::VirtgpuCaps::NoCapsets)
    );
    assert_eq!(u32::from(crtc.mode.hdisplay), SECOND_MODE_WIDTH);
    let encoder = driver.encoder_info(1).unwrap();
    assert_eq!(encoder.crtc_id, drm::crtc_id_for(1));
    assert_eq!(encoder.possible_crtcs, 1 << 1);
    let plane = driver.plane_info(0).unwrap();
    assert_eq!(plane.crtc_id, drm::crtc_id_for(0));
    assert_eq!(
        driver.plane_info(1).unwrap().crtc_id,
        drm::crtc_id_for(0)
    );
    assert_eq!(
        driver.plane_info(2).unwrap().crtc_id,
        drm::crtc_id_for(1)
    );
    assert!(driver.connector_info(2).is_none());
    assert!(driver.crtc_info(2).is_none());
}

#[test]
fn drm_fourcc_mapping() {
    assert_eq!(
        drm_fourcc_to_virtio(TEST_XRGB8888_FOURCC),
        Some(VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM)
    );
    assert_eq!(
        drm_fourcc_to_virtio(TEST_ARGB8888_FOURCC),
        Some(VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM)
    );
    assert_eq!(
        drm_fourcc_to_virtio(drm::DRM_FORMAT_XRGB8888),
        Some(VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM)
    );
    assert_eq!(
        drm_fourcc_to_virtio(drm::DRM_FORMAT_ARGB8888),
        Some(VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM)
    );
    assert_eq!(drm_fourcc_to_virtio(UNSUPPORTED_FOURCC), None);
}

#[test]
fn drm_unique_uses_pci_bdf_bus_id() {
    assert_eq!(drm_unique_from_bdf(FIRST_TEST_BDF), FIRST_TEST_UNIQUE);
    assert_eq!(drm_unique_from_bdf(SECOND_TEST_BDF), SECOND_TEST_UNIQUE);
}

#[test]
fn resource_id_increments() {
    let device = test_device(key(0), 0);
    let first = device.next_resource_id();
    let second = device.next_resource_id();
    assert_ne!(first, second);
    assert_eq!(second, first + 1);
}
