//! What a connector reports once its display published an EDID.

use super::super::*;
use alloc::vec::Vec;
use drm::DrmDriver;

const SCANOUT_WIDTH: u32 = 1024;
const SCANOUT_HEIGHT: u32 = 768;
const EDID_WIDTH: u32 = 1920;
const EDID_HEIGHT: u32 = 1080;
const UNPACKED_WIDTH: u32 = 1366;
const UNPACKED_HEIGHT: u32 = 768;

/// Detailed timing descriptor bytes for a 1920x1080 60 Hz display.
const DTD_1920X1080: [u8; drm::edid::DTD_LEN] = [
    0x02, 0x3a, 0x80, 0x18, 0x71, 0x38, 0x2d, 0x40, 0x58, 0x2c,
    0x45, 0x00, 0x13, 0x2b, 0x21, 0x00, 0x00, 0x1e,
];

/// Detailed timing descriptor bytes for a 1280x720 60 Hz display: 74.25 MHz,
/// 1650x750 total, 110/40 horizontal and 5/5 vertical sync.
const DTD_1280X720: [u8; drm::edid::DTD_LEN] = [
    0x01, 0x1d, 0x00, 0x72, 0x51, 0xd0, 0x1e, 0x20, 0x6e, 0x28,
    0x55, 0x00, 0x35, 0xae, 0x10, 0x00, 0x00, 0x1e,
];

/// Detailed timing descriptor bytes for a 1366x768 60 Hz display: a width whose
/// packed row is not pitch-aligned, so the scanout cannot honour it.
const DTD_1366X768: [u8; drm::edid::DTD_LEN] = [
    0x66, 0x21, 0x56, 0xaa, 0x51, 0x00, 0x1b, 0x30, 0x46, 0x8f,
    0x33, 0x00, 0x35, 0xae, 0x10, 0x00, 0x00, 0x1e,
];

/// Established-timing bitmap bit 11: 1024x768 at 60 Hz.
const EST_BIT_1024X768: (usize, u8) = (1, 1 << 3);
/// Standard timing entry for 1920x1080 at 60 Hz: 16:9 aspect code.
const STD_1920X1080: (u8, u8) = (((1920 - 248) / 8) as u8, 0xc0);

fn block_with(dtd: &[u8; drm::edid::DTD_LEN]) -> Vec<u8> {
    block_full(&[dtd], false, false)
}

/// A revision-4 base block carrying `dtds`, optionally an established-timing
/// bit and a standard timing entry.
fn block_full(dtds: &[&[u8; drm::edid::DTD_LEN]], est: bool, std: bool) -> Vec<u8> {
    let mut b = alloc::vec![0u8; drm::edid::BLOCK_LEN];
    b[..drm::edid::HEADER.len()].copy_from_slice(&drm::edid::HEADER);
    b[drm::edid::OFF_VERSION] = 1;
    b[drm::edid::OFF_REVISION] = 4;
    for (i, d) in dtds.iter().enumerate().take(drm::edid::DTD_COUNT) {
        let at = drm::edid::OFF_DETAILED + i * drm::edid::DTD_LEN;
        b[at..at + drm::edid::DTD_LEN].copy_from_slice(&d[..]);
    }
    if est { b[drm::edid::OFF_ESTABLISHED + EST_BIT_1024X768.0] = EST_BIT_1024X768.1; }
    if std {
        b[drm::edid::OFF_STANDARD] = STD_1920X1080.0;
        b[drm::edid::OFF_STANDARD + 1] = STD_1920X1080.1;
    }
    b[drm::edid::OFF_CHECKSUM] = drm::edid::computed_checksum(&b);
    b
}

fn driver_with(edid: Option<Vec<u8>>) -> VirtioGpuDrm {
    let mut modes = [VirtioGpuDisplayOne::default(); VIRTIO_GPU_MAX_SCANOUTS];
    modes[0] = VirtioGpuDisplayOne {
        r: VirtioGpuRect { x: 0, y: 0, width: SCANOUT_WIDTH, height: SCANOUT_HEIGHT },
        enabled: 1, flags: 0,
    };
    modes[1] = VirtioGpuDisplayOne {
        r: VirtioGpuRect { x: 0, y: 0, width: SCANOUT_WIDTH, height: SCANOUT_HEIGHT },
        enabled: 1, flags: 0,
    };
    VirtioGpuDrm {
        display: DisplayInfo { modes, count_enabled: 2 },
        features_negotiated: 1u64 << VIRTIO_GPU_F_EDID,
        bdf: 0,
        unique: drm_unique_from_bdf(0),
        edid,
    }
}

#[test]
fn the_test_descriptors_name_the_sizes_they_claim() {
    let fhd = drm::edid::preferred_mode(&block_with(&DTD_1920X1080)).expect("valid timing");
    assert_eq!((fhd.hdisplay as u32, fhd.vdisplay as u32), (EDID_WIDTH, EDID_HEIGHT));
    let wxga = drm::edid::preferred_mode(&block_with(&DTD_1366X768)).expect("valid timing");
    assert_eq!((wxga.hdisplay as u32, wxga.vdisplay as u32), (UNPACKED_WIDTH, UNPACKED_HEIGHT));
    let hd = drm::edid::preferred_mode(&block_with(&DTD_1280X720)).expect("valid timing");
    assert_eq!((hd.hdisplay, hd.vdisplay), (1280, 720));
    assert_eq!(hd.clock, 74_250);
}

#[test]
fn the_connector_serves_the_fetched_edid_as_its_blob() {
    let block = block_with(&DTD_1920X1080);
    let driver = driver_with(Some(block.clone()));
    assert_eq!(driver.edid_blob(0).as_deref(), Some(&block[..]));
    // Only the primary scanout's display was interrogated, so the second
    // connector reports none rather than repeating the first's identity.
    assert!(driver.edid_blob(1).is_none());
}

#[test]
fn a_connector_without_an_edid_serves_no_blob() {
    assert!(driver_with(None).edid_blob(0).is_none());
}

#[test]
fn the_displays_timing_heads_the_primary_connectors_mode_list() {
    let driver = driver_with(Some(block_with(&DTD_1920X1080)));
    let modes = driver.modes_for(0);
    assert_eq!((modes[0].hdisplay as u32, modes[0].vdisplay as u32), (EDID_WIDTH, EDID_HEIGHT));
    assert_ne!(modes[0].ty & drm::DRM_MODE_TYPE_PREFERRED, 0);
    // The display's own timings, not a rectangle synthesised from its size.
    assert_eq!(modes[0].clock, 148_500);
    assert_eq!((modes[0].htotal, modes[0].vtotal), (2200, 1125));
    assert!(modes.len() > 1, "the alternatives are still offered");
    // The connector without an EDID keeps the device's rectangle.
    let other = driver.modes_for(1);
    assert_eq!((other[0].hdisplay as u32, other[0].vdisplay as u32),
        (SCANOUT_WIDTH, SCANOUT_HEIGHT));
}

#[test]
fn the_connector_offers_every_mode_the_display_published() {
    // A second detailed timing, an established mode, and a standard timing
    // entry, none of which is the preferred one.
    let driver = driver_with(Some(block_full(
        &[&DTD_1920X1080, &DTD_1280X720], true, true)));
    let modes = driver.modes_for(0);
    for (w, h) in [(1920u16, 1080u16), (1280, 720), (1024, 768)] {
        assert!(modes.iter().any(|m| m.hdisplay == w && m.vdisplay == h),
            "the display asserted {w}x{h} and the connector must offer it");
    }
    // The standard timing entry names the same size as the preferred timing,
    // so it is collapsed rather than offered twice.
    assert_eq!(modes.iter().filter(|m| m.hdisplay == 1920 && m.vdisplay == 1080).count(), 1);
}

#[test]
fn an_unpacked_edid_width_leaves_the_device_rectangle_preferred() {
    let driver = driver_with(Some(block_with(&DTD_1366X768)));
    let modes = driver.modes_for(0);
    assert_eq!((modes[0].hdisplay as u32, modes[0].vdisplay as u32),
        (SCANOUT_WIDTH, SCANOUT_HEIGHT));
    assert!(!modes.iter().any(|m| m.hdisplay as u32 == UNPACKED_WIDTH));
    // The blob is still published: userspace learns the monitor's identity even
    // when the scanout declines its preferred timing.
    assert!(driver.edid_blob(0).is_some());
}

#[test]
fn a_corrupt_edid_leaves_the_device_rectangle_preferred() {
    let mut block = block_with(&DTD_1920X1080);
    block[drm::edid::OFF_CHECKSUM] ^= 0xff;
    let driver = driver_with(Some(block));
    let modes = driver.modes_for(0);
    assert_eq!((modes[0].hdisplay as u32, modes[0].vdisplay as u32),
        (SCANOUT_WIDTH, SCANOUT_HEIGHT));
}
